//! `POST /v1/proxy-metadata` and the minimal registry-entry store (T-11 S4
//! slice B2).
//!
//! Spec: registry.md R1/R2, ledger-and-query.md L5 (SV-2..SV-5), contracts
//! README N9/M2b. PX-005/010/011, AC-05/06. Not here: the read view and
//! scoped content lookup (R6).
//!
//! # Store
//!
//! A SQLite file of its own (`proxy-metadata.sqlite` next to the state file),
//! opened with the ledger's hardening (`ledger::open_hardened`: owner-only,
//! no symlink, WAL, `synchronous=FULL`, `secure_delete`). Not tables inside
//! the ledger DB: keeping the file apart leaves `ledger.rs` (schema, caps,
//! sweep) untouched and makes the entry content (untrusted `definition`, keyed
//! fingerprint) a separate, separately-permissioned artifact (PX-010). Growth
//! is bounded by two caps (entries per proxy, total bytes) that answer 503
//! `storage_limit`.
//!
//! # Retention (README N9)
//!
//! [`MetadataStore::sweep`] runs after the ledger sweep. It deletes an entry
//! when no retained row names it ([`LiveRefs`]) and its last upload is more
//! than `G = R + M` ago (`R` the proxy's `max_offline_retry_age_seconds`, `M`
//! the ack-loss margin). A byte-identical duplicate upload counts as an upload.
//! Tombstones need no entry: a byte-identical resend matches its tombstone
//! before any registry check. An event batch or inventory report that names a
//! deleted ref gets 424 `metadata_ref_pending`, and the producer uploads the
//! entry again.
//! Event and inventory ingest hold [`MetadataStore::hold_refs`] from the ref
//! lookup until their rows are stored; the sweep holds it exclusively from
//! reading the live set until its delete commits, so a ref validated by ingest
//! is never deleted before the row that names it lands. Like the ledger sweep,
//! the pass ends with `wal_checkpoint(TRUNCATE)` so the WAL keeps no copy of
//! freed pages.
//!
//! # Content deletion (R1)
//!
//! [`MetadataStore::delete_content`] serves a privacy request for one entry.
//! It sets `content_state = 'deleted'`, empties `definition`, recomputes the
//! proxy's usage and truncates the WAL, as the sweep does. The immutable stub
//! stays: ingest still recognises the ref, an equal upload is a duplicate that
//! does not restore the definition (first write wins), and the retention sweep
//! still removes the stub. `observed_at` stays: it is proxy clock metadata, and
//! the column is `NOT NULL`.
//!
//! # Upload rules (R2)
//!
//! Order, first match wins: 404 `proxy_unknown` (body `proxy_id` or any entry
//! `proxy_id` differs from the mTLS identity; read from the raw body before
//! the typed parse), 422 (schema, an entry over 256 KiB, or a
//! `credential_scope_id` the server did not assign to `(proxy, upstream_id)`
//! in the current or previous config revision), 409 `registry_conflict` (same
//! `(proxy_id, metadata_ref)` with a different immutable field), 503, 200.
//! All or nothing; 200 only after commit. `definition` and `observed_at` are
//! volatile: first write wins. Nothing submitted is echoed.

use super::guard::{proxy_unknown, VerifiedProxy};
use super::ingest::{
    acquire_slot, api_response, differs, fixed, index_u32, read_body, semantic_422,
};
use super::ProxyContext;
use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use lodeline_proxy_api::{
    parse_upload, ApiError, ErrorCategory, ErrorCode, ErrorItem, MetadataRef, RegistryEntry,
    UploadResponse,
};
use parking_lot::{Mutex, RwLock, RwLockReadGuard};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

pub const METADATA_PATH: &str = "/v1/proxy-metadata";
/// Request body cap (registry.md R2: 4 MiB).
pub const MAX_UPLOAD_BODY: usize = 4 * 1024 * 1024;
/// Largest `definition` of one entry (registry.md R2: 256 KiB).
pub const MAX_DEFINITION_BYTES: usize = 256 * 1024;

const SCHEMA_VERSION: i64 = 3;
const SCHEMA: &str = "
CREATE TABLE entries (
    proxy_id            TEXT NOT NULL,
    metadata_ref        TEXT NOT NULL,
    upstream_id         TEXT NOT NULL,
    credential_scope_id TEXT NOT NULL,
    protocol_version    TEXT NOT NULL,
    observation_source  TEXT NOT NULL,
    canon               TEXT NOT NULL,
    key_id              TEXT NOT NULL,
    fingerprint         TEXT NOT NULL,
    observed_at         TEXT NOT NULL,
    definition          BLOB NOT NULL,
    size                INTEGER NOT NULL,
    registered_at       INTEGER NOT NULL,
    PRIMARY KEY (proxy_id, metadata_ref)
) WITHOUT ROWID;
CREATE INDEX entries_ref ON entries (metadata_ref);
CREATE TABLE usage (
    proxy_id TEXT PRIMARY KEY,
    entries  INTEGER NOT NULL,
    bytes    INTEGER NOT NULL
) WITHOUT ROWID;
";
/// v2: the retention clock. Applied on a fresh file and by the v1 -> v2
/// migration, so the two cannot drift; a v1 entry's last upload is its
/// registration.
const V2_DDL: &str = "
ALTER TABLE entries ADD COLUMN last_upload_at INTEGER NOT NULL DEFAULT 0;
UPDATE entries SET last_upload_at = registered_at;
";
/// v3: content deletion (R1). Shared by a fresh file and the migrations like
/// [`V2_DDL`]; every older entry still has its content.
const V3_DDL: &str = "
ALTER TABLE entries ADD COLUMN content_state TEXT NOT NULL DEFAULT 'present'
    CHECK (content_state IN ('present', 'deleted'));
";

/// `(proxy_id, metadata_ref)` pairs named by retained rows (ledger events and
/// inventory, proxy-reported `registry_conflict` gaps). The sweep keeps these.
pub type LiveRefs = HashSet<(String, String)>;

/// Serde text of a closed-enum value (`\"2025-11-25\"`, `\"proxy_live\"`, ...).
pub(super) fn enum_text<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The immutable fields of a stored entry that ingest checks need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefInfo {
    pub upstream_id: String,
    pub credential_scope_id: String,
    pub protocol_version: String,
    pub observation_source: String,
}

/// Registration state of a ref from one proxy's point of view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefLookup {
    /// Registered for this proxy.
    Own(RefInfo),
    /// Not for this proxy, but registered under another one (SV-3).
    OtherProxy,
    /// Registered nowhere (SV-2).
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UploadError {
    /// 409: indexes of entries whose immutable fields differ from the stored
    /// ones. Nothing was stored.
    Conflicts(Vec<usize>),
    /// 503 `storage_limit`. Nothing was stored.
    StorageLimit,
    /// 503 `storage_unavailable`. Nothing was stored.
    StorageUnavailable,
}

impl From<rusqlite::Error> for UploadError {
    fn from(e: rusqlite::Error) -> Self {
        let code = match &e {
            rusqlite::Error::SqliteFailure(f, _) => format!("{:?}", f.code),
            _ => "other".to_string(),
        };
        tracing::error!(sqlite_code = %code, "proxy metadata storage failure");
        UploadError::StorageUnavailable
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct UploadOutcome {
    pub registered: Vec<MetadataRef>,
    pub duplicate: Vec<MetadataRef>,
}

#[derive(Clone, Copy, Debug)]
pub struct MetadataCaps {
    pub entries_per_proxy: u64,
    pub bytes_per_proxy: u64,
    pub bytes_total: u64,
}

/// Stored size of one entry: the definition plus every other stored column
/// (text lengths and a fixed allowance for row/index overhead).
fn row_size(e: &RegistryEntry, def_len: usize) -> i64 {
    let fixed = e.proxy_id.as_str().len()
        + e.metadata_ref.as_str().len() * 2
        + e.upstream_id.as_str().len()
        + e.credential_scope_id.as_str().len()
        + e.key_id.as_str().len()
        + e.fingerprint.as_str().len()
        + e.observed_at.as_str().len()
        + 64
        + 256;
    i64::try_from(def_len + fixed).unwrap_or(i64::MAX)
}

pub struct MetadataStore {
    conn: Mutex<Connection>,
    caps: MetadataCaps,
    /// Shared: a lookup result in use by ingest. Exclusive: the sweep.
    refs: RwLock<()>,
}

type Immutable = (String, String, String, String, String, String, String);

fn immutable_of(e: &RegistryEntry) -> Immutable {
    (
        e.upstream_id.as_str().to_string(),
        e.credential_scope_id.as_str().to_string(),
        enum_text(&e.protocol_version),
        enum_text(&e.observation_source),
        enum_text(&e.canon),
        e.key_id.as_str().to_string(),
        e.fingerprint.as_str().to_string(),
    )
}

impl MetadataStore {
    /// Open or create the store (same file rules as the ledger).
    pub fn open(path: &Path, caps: MetadataCaps) -> Result<Self> {
        let conn = super::ledger::open_hardened(path)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let tables: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0))?;
        match (version, tables) {
            (0, 0) => conn
                .execute_batch(&format!(
                    "BEGIN IMMEDIATE;{SCHEMA}{V2_DDL}{V3_DDL}PRAGMA user_version = {SCHEMA_VERSION};COMMIT;"
                ))
                .context("create metadata schema")?,
            (1, _) => conn
                .execute_batch(&format!(
                    "BEGIN IMMEDIATE;{V2_DDL}{V3_DDL}PRAGMA user_version = {SCHEMA_VERSION};COMMIT;"
                ))
                .context("migrate metadata schema to v3")?,
            (2, _) => conn
                .execute_batch(&format!(
                    "BEGIN IMMEDIATE;{V3_DDL}PRAGMA user_version = {SCHEMA_VERSION};COMMIT;"
                ))
                .context("migrate metadata schema to v3")?,
            (SCHEMA_VERSION, _) => {}
            _ => bail!("metadata database has an unknown format version"),
        }
        Ok(Self {
            conn: Mutex::new(conn),
            caps,
            refs: RwLock::new(()),
        })
    }

    /// Hold from [`Self::lookup`] until the rows naming the looked-up refs are
    /// stored, so the sweep cannot delete a ref in between.
    pub fn hold_refs(&self) -> RwLockReadGuard<'_, ()> {
        self.refs.read()
    }

    /// Retention pass (module doc). `live` runs while the refs are held
    /// exclusively. An entry of proxy `p` goes when `live` does not name it and
    /// `now - last_upload_at > grace(p)`. Returns how many entries were deleted.
    pub fn sweep(
        &self,
        now: i64,
        grace: &dyn Fn(&str) -> i64,
        live: impl FnOnce() -> Result<LiveRefs, super::ledger::LedgerError>,
    ) -> Result<usize, UploadError> {
        let _refs = self.refs.write();
        // `live` scans every stored start event while ingest waits, so skip it
        // when nothing has expired.
        if !self.any_expired(now, grace)? {
            return Ok(0);
        }
        let live = live().map_err(|_| UploadError::StorageUnavailable)?;
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Vec<(String, String, i64)> = {
            let mut st =
                tx.prepare("SELECT proxy_id, metadata_ref, last_upload_at FROM entries")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut deleted = 0;
        for (proxy_id, mref, last_upload) in old {
            let expired = now.saturating_sub(last_upload) > grace(&proxy_id);
            let key = (proxy_id, mref);
            if expired && !live.contains(&key) {
                deleted += tx.execute(
                    "DELETE FROM entries WHERE proxy_id = ?1 AND metadata_ref = ?2",
                    params![key.0, key.1],
                )?;
            }
        }
        if deleted == 0 {
            return Ok(0);
        }
        tx.execute_batch(
            "DELETE FROM usage;
             INSERT INTO usage (proxy_id, entries, bytes)
                 SELECT proxy_id, COUNT(*), SUM(size) FROM entries GROUP BY proxy_id;",
        )?;
        tx.commit()?;
        // secure_delete zeroes freed pages in the database, but the WAL can
        // still hold older copies until it is checkpointed and truncated.
        // A busy checkpoint is a row with busy=1, not an error.
        let busy = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            r.get::<_, i64>(0)
        });
        if !matches!(busy, Ok(0)) {
            tracing::error!(
                "proxy metadata WAL truncate after sweep did not complete; \
                 the WAL can hold swept entries until the next checkpoint"
            );
        }
        Ok(deleted)
    }

    /// Delete the content of one entry and keep its stub (module doc).
    /// Idempotent. `Ok(false)`: no such entry for this proxy.
    pub fn delete_content(&self, proxy_id: &str, metadata_ref: &str) -> Result<bool, UploadError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // SET expressions read the old row, so `size` drops by the old length.
        let found = tx.execute(
            "UPDATE entries SET content_state = 'deleted', definition = x'',
                 size = size - length(definition)
             WHERE proxy_id = ?1 AND metadata_ref = ?2",
            params![proxy_id, metadata_ref],
        )?;
        if found == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE usage SET bytes =
                 (SELECT COALESCE(SUM(size), 0) FROM entries WHERE proxy_id = ?1)
             WHERE proxy_id = ?1",
            params![proxy_id],
        )?;
        tx.commit()?;
        // A busy checkpoint is a row with busy=1, not an error. The deletion is
        // committed either way, and a repeat call on the deleted entry retries it.
        let busy = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            r.get::<_, i64>(0)
        });
        if !matches!(busy, Ok(0)) {
            tracing::error!(
                "proxy metadata WAL truncate after content deletion did not complete; \
                 the WAL can hold the old content until a repeat call or the next checkpoint"
            );
        }
        Ok(true)
    }

    fn any_expired(&self, now: i64, grace: &dyn Fn(&str) -> i64) -> Result<bool, UploadError> {
        let conn = self.conn.lock();
        let mut st = conn.prepare("SELECT proxy_id, last_upload_at FROM entries")?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            let proxy_id: String = r.get(0)?;
            if now.saturating_sub(r.get::<_, i64>(1)?) > grace(&proxy_id) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Blocking. One result per input ref, in order.
    pub fn lookup(&self, proxy_id: &str, refs: &[&str]) -> Result<Vec<RefLookup>, UploadError> {
        let conn = self.conn.lock();
        let mut own = conn.prepare(
            "SELECT upstream_id, credential_scope_id, protocol_version, observation_source
             FROM entries WHERE proxy_id = ?1 AND metadata_ref = ?2",
        )?;
        let mut other = conn.prepare(
            "SELECT EXISTS(SELECT 1 FROM entries WHERE metadata_ref = ?1 AND proxy_id <> ?2)",
        )?;
        let mut out = Vec::with_capacity(refs.len());
        for r in refs {
            let hit = own
                .query_row(params![proxy_id, r], |row| {
                    Ok(RefInfo {
                        upstream_id: row.get(0)?,
                        credential_scope_id: row.get(1)?,
                        protocol_version: row.get(2)?,
                        observation_source: row.get(3)?,
                    })
                })
                .optional()?;
            out.push(match hit {
                Some(i) => RefLookup::Own(i),
                None if other.query_row(params![r, proxy_id], |row| row.get::<_, bool>(0))? => {
                    RefLookup::OtherProxy
                }
                None => RefLookup::Unknown,
            });
        }
        Ok(out)
    }

    /// Register a validated upload atomically (blocking). `now` is unix seconds.
    pub fn register(
        &self,
        proxy_id: &str,
        entries: &[RegistryEntry],
        now: i64,
    ) -> Result<UploadOutcome, UploadError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut out = UploadOutcome::default();
        let mut conflicts = Vec::new();
        let (mut new_entries, mut new_bytes) = (0i64, 0i64);
        for (index, e) in entries.iter().enumerate() {
            let mine = immutable_of(e);
            let stored: Option<Immutable> = tx
                .query_row(
                    "SELECT upstream_id, credential_scope_id, protocol_version,
                            observation_source, canon, key_id, fingerprint
                     FROM entries WHERE proxy_id = ?1 AND metadata_ref = ?2",
                    params![proxy_id, e.metadata_ref.as_str()],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                        ))
                    },
                )
                .optional()?;
            match stored {
                Some(s) if s == mine => {
                    // First write wins: later `definition`/`observed_at` ignored,
                    // so deleted content stays deleted. The upload still counts
                    // for retention.
                    tx.execute(
                        "UPDATE entries SET last_upload_at = MAX(last_upload_at, ?3)
                         WHERE proxy_id = ?1 AND metadata_ref = ?2",
                        params![proxy_id, e.metadata_ref.as_str(), now],
                    )?;
                    if !out.registered.contains(&e.metadata_ref)
                        && !out.duplicate.contains(&e.metadata_ref)
                    {
                        out.duplicate.push(e.metadata_ref.clone());
                    }
                }
                Some(_) => conflicts.push(index),
                None => {
                    let def = serde_json::to_vec(&e.definition).unwrap_or_default();
                    tx.execute(
                        "INSERT INTO entries (proxy_id, metadata_ref, upstream_id,
                             credential_scope_id, protocol_version, observation_source, canon,
                             key_id, fingerprint, observed_at, definition, size, registered_at,
                             last_upload_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)",
                        params![
                            proxy_id,
                            e.metadata_ref.as_str(),
                            mine.0,
                            mine.1,
                            mine.2,
                            mine.3,
                            mine.4,
                            mine.5,
                            mine.6,
                            e.observed_at.as_str(),
                            def,
                            row_size(e, def.len()),
                            now,
                        ],
                    )?;
                    new_entries += 1;
                    new_bytes += row_size(e, def.len());
                    out.registered.push(e.metadata_ref.clone());
                }
            }
        }
        if !conflicts.is_empty() {
            return Err(UploadError::Conflicts(conflicts));
        }
        if new_entries > 0 {
            tx.execute(
                "INSERT INTO usage (proxy_id, entries, bytes) VALUES (?1, ?2, ?3)
                 ON CONFLICT (proxy_id) DO UPDATE SET
                     entries = entries + excluded.entries, bytes = bytes + excluded.bytes",
                params![proxy_id, new_entries, new_bytes],
            )?;
            let (mine, mine_bytes): (i64, i64) = tx.query_row(
                "SELECT entries, bytes FROM usage WHERE proxy_id = ?1",
                params![proxy_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let total: i64 =
                tx.query_row("SELECT COALESCE(SUM(bytes), 0) FROM usage", [], |r| {
                    r.get(0)
                })?;
            let over = |v: i64, cap: u64| u64::try_from(v).is_ok_and(|v| v > cap);
            if over(mine, self.caps.entries_per_proxy)
                || over(mine_bytes, self.caps.bytes_per_proxy)
                || over(total, self.caps.bytes_total)
            {
                return Err(UploadError::StorageLimit);
            }
        }
        tx.commit()?;
        Ok(out)
    }

    /// Per entry: is an entry with equal immutable fields already stored?
    pub fn existing_equal(
        &self,
        proxy_id: &str,
        entries: &[RegistryEntry],
    ) -> Result<Vec<bool>, UploadError> {
        let conn = self.conn.lock();
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let m = immutable_of(e);
            let hit: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM entries WHERE proxy_id = ?1 AND metadata_ref = ?2
                     AND upstream_id = ?3 AND credential_scope_id = ?4 AND protocol_version = ?5
                     AND observation_source = ?6 AND canon = ?7 AND key_id = ?8 AND fingerprint = ?9)",
                params![proxy_id, e.metadata_ref.as_str(), m.0, m.1, m.2, m.3, m.4, m.5, m.6],
                |r| r.get(0),
            )?;
            out.push(hit);
        }
        Ok(out)
    }

    /// Number of stored entries of a proxy (tests and diagnostics).
    pub fn count(&self, proxy_id: &str) -> Result<i64, UploadError> {
        let conn = self.conn.lock();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE proxy_id = ?1",
            params![proxy_id],
            |r| r.get(0),
        )?)
    }
}

/// Same rule as the event ingest: a string `proxy_id` in the body or in any
/// entry that is not the caller's, read before the typed parse.
fn foreign_proxy_id_in_body(body: &[u8], peer_id: &str) -> bool {
    let Ok(serde_json::Value::Object(doc)) = serde_json::from_slice::<serde_json::Value>(body)
    else {
        return false;
    };
    differs(doc.get("proxy_id"), peer_id)
        || doc
            .get("entries")
            .and_then(|e| e.as_array())
            .is_some_and(|es| es.iter().any(|e| differs(e.get("proxy_id"), peer_id)))
}

/// Blocking body of the upload handler.
pub fn handle(ctx: &ProxyContext, peer_id: &str, body: &[u8]) -> Response {
    if foreign_proxy_id_in_body(body, peer_id) {
        ctx.ingest_log.note("metadata", "identity_mismatch");
        return proxy_unknown();
    }
    let req = match parse_upload(body) {
        Ok(r) => r,
        Err(e) => {
            if e.category() == ErrorCategory::Limit {
                ctx.ingest_log.note("metadata", "payload_too_large");
                return fixed(ErrorCode::PayloadTooLarge);
            }
            ctx.ingest_log.note("metadata", "invalid");
            let err = ApiError::from_code(ErrorCode::SemanticInvalid);
            return api_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                match e.index() {
                    Some(i) => err.with_items(vec![ErrorItem {
                        index: index_u32(i),
                        event_id: None,
                        gap_id: None,
                        metadata_ref: None,
                        code: ErrorCode::SemanticInvalid,
                    }]),
                    None => err,
                },
            );
        }
    };
    if req.proxy_id.as_str() != peer_id
        || req.entries.iter().any(|e| e.proxy_id.as_str() != peer_id)
    {
        ctx.ingest_log.note("metadata", "identity_mismatch");
        return proxy_unknown();
    }

    // 422: oversized definition, or a scope the server did not assign. An
    // entry equal to a stored one is a duplicate and skips the scope check
    // (a retry after the scope window moved on must not turn into a 422).
    let stored_equal = match ctx.metadata.existing_equal(peer_id, &req.entries) {
        Ok(v) => v,
        Err(_) => return fixed(ErrorCode::StorageUnavailable),
    };
    let invalid: Vec<usize> = req
        .entries
        .iter()
        .enumerate()
        .filter(|(i, e)| {
            serde_json::to_vec(&e.definition).map_or(usize::MAX, |d| d.len()) > MAX_DEFINITION_BYTES
                || (!stored_equal[*i]
                    && !ctx.store.scope_assigned(
                        peer_id,
                        e.upstream_id.as_str(),
                        e.credential_scope_id.as_str(),
                    ))
        })
        .map(|(i, _)| i)
        .collect();
    if !invalid.is_empty() {
        ctx.ingest_log.note("metadata", "semantic_invalid");
        return semantic_422(invalid);
    }

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    match ctx.metadata.register(peer_id, &req.entries, now) {
        Ok(out) => Json(
            serde_json::to_value(UploadResponse {
                registered_metadata_refs: out.registered,
                duplicate_metadata_refs: out.duplicate,
            })
            .unwrap_or(serde_json::Value::Null),
        )
        .into_response(),
        Err(UploadError::Conflicts(idx)) => {
            ctx.ingest_log.note("metadata", "registry_conflict");
            // The contract's item carries `{index, metadata_ref, code}` (R2): the
            // ref is the (already validated) conflicting entry's own, never a
            // stored or submitted value beyond that.
            let items = idx
                .into_iter()
                .map(|i| ErrorItem {
                    index: index_u32(i),
                    event_id: None,
                    gap_id: None,
                    metadata_ref: req.entries.get(i).map(|e| e.metadata_ref.clone()),
                    code: ErrorCode::RegistryConflict,
                })
                .collect();
            api_response(
                StatusCode::CONFLICT,
                ApiError::from_code(ErrorCode::RegistryConflict).with_items(items),
            )
        }
        Err(UploadError::StorageLimit) => {
            ctx.ingest_log.note("metadata", "storage");
            fixed(ErrorCode::StorageLimit)
        }
        Err(UploadError::StorageUnavailable) => {
            ctx.ingest_log.note("metadata", "storage");
            fixed(ErrorCode::StorageUnavailable)
        }
    }
}

pub async fn post_metadata(
    State(ctx): State<Arc<ProxyContext>>,
    Extension(id): Extension<VerifiedProxy>,
    req: Request<Body>,
) -> Response {
    let slot = match acquire_slot(&ctx, &id.proxy_id, "metadata") {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let body = match read_body(&ctx, req.into_body(), MAX_UPLOAD_BODY, "metadata").await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let r = tokio::task::spawn_blocking(move || {
        let r = handle(&ctx, &id.proxy_id, &body);
        drop(slot);
        r
    })
    .await;
    r.unwrap_or_else(|_| fixed(ErrorCode::StorageUnavailable))
}
