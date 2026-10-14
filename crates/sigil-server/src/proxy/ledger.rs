//! T-11 S4 slice B1 — the proxy event ledger (storage layer only).
//!
//! Spec: ledger-and-query.md L1 (retention, tombstones), L4 (server-derived
//! gaps), L5 SV-1 (invocation owner); contracts README N2/M1/M2a. PX-010/011,
//! AC-05/06. There is no HTTP route and no metadata upload here (slice B2).
//!
//! Storage: one SQLite file next to the proxy state file, owner-only (0600).
//!
//! * **Durability.** `journal_mode=WAL` with `synchronous=FULL` (and `fullfsync`
//!   where the OS has it). In WAL mode `NORMAL` does not sync the log at commit,
//!   so a power loss could drop an acknowledged batch; the handler ACKs only
//!   after [`Ledger::insert_batch`] returns, so commits must be durable.
//!   `secure_delete=ON` zeroes freed content in the database file; because the
//!   WAL can still hold older page copies, every sweep ends with
//!   `wal_checkpoint(TRUNCATE)`. The file itself does not shrink (freed pages
//!   are reused).
//! * **Concurrency.** The connection sits behind a `Mutex`. `rusqlite::Connection`
//!   is `Send` but not `Sync`; the mutex makes [`Ledger`] `Send + Sync` and also
//!   serialises batches in-process (SQLite allows one writer anyway). Calls block
//!   on disk I/O: the HTTP handler must use `spawn_blocking`. Each batch is one
//!   `BEGIN IMMEDIATE` transaction; a read-only S5 connection can be added later
//!   without changing this (WAL readers do not block the writer).
//! * **All or nothing.** Any conflict, cap hit or storage error rolls the whole
//!   batch back; `accepted`/`duplicate` are returned only after `COMMIT`.
//! * **Errors echo nothing.** [`LedgerError`] carries only indexes, event ids the
//!   caller already validated, and fixed codes. SQLite error text is never kept.
//!
//! Dedup equality is the proxy-api canonical form (`canonical_event_bytes`).
//! Equal bytes <=> equal SHA-256, so the stored digest decides duplicate versus
//! conflict even after the body has been removed by retention.

use crate::config::ProxyConfig;
use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use sigil_proxy_api::{canonical_event_bytes, ErrorCode, EventPayload, ProxyEvent, Uuid};
use std::collections::HashMap;
use std::path::Path;

/// Format version stored in `PRAGMA user_version`.
pub const SCHEMA_VERSION: i64 = 1;
/// Open server-derived gaps per proxy. A batch that would exceed it is refused
/// (`storage_limit`) rather than dropping a stored gap. Closed gaps do not
/// count: they are only retained until E.
pub const MAX_GAPS_PER_PROXY: i64 = 10_000;

/// Storage caps. Defaults are conservative, **unmeasured** test values (D-04).
///
/// * `rows_*` count event rows; `bytes_*` count **canonical event bytes only**
///   (no index, tombstone or page overhead).
/// * Tombstones have their own bound, derived as `TOMBSTONE_FACTOR` x the rows
///   cap (tombstones can outlive event bodies when T > E, but must not eat the
///   event rows budget).
/// * `file_bytes` is a hard backstop on the live database size
///   (`(page_count - freelist_count) * page_size`), derived as
///   `FILE_FACTOR` x `bytes_total` to cover indexes and tombstones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerCaps {
    pub rows_per_proxy: u64,
    pub bytes_per_proxy: u64,
    pub rows_total: u64,
    pub bytes_total: u64,
    pub tombstones_per_proxy: u64,
    pub tombstones_total: u64,
    pub file_bytes: u64,
}

pub const TOMBSTONE_FACTOR: u64 = 4;
pub const FILE_FACTOR: u64 = 3;

impl LedgerCaps {
    pub fn new(
        rows_per_proxy: u64,
        bytes_per_proxy: u64,
        rows_total: u64,
        bytes_total: u64,
    ) -> Self {
        Self {
            rows_per_proxy,
            bytes_per_proxy,
            rows_total,
            bytes_total,
            tombstones_per_proxy: rows_per_proxy.saturating_mul(TOMBSTONE_FACTOR),
            tombstones_total: rows_total.saturating_mul(TOMBSTONE_FACTOR),
            file_bytes: bytes_total.saturating_mul(FILE_FACTOR),
        }
    }
}

impl Default for LedgerCaps {
    fn default() -> Self {
        Self::new(
            ProxyConfig::DEFAULT_LEDGER_ROWS_PER_PROXY,
            ProxyConfig::DEFAULT_LEDGER_BYTES_PER_PROXY,
            ProxyConfig::DEFAULT_LEDGER_ROWS_TOTAL,
            ProxyConfig::DEFAULT_LEDGER_BYTES_TOTAL,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerOptions {
    /// T: seconds a tombstone is kept after acceptance.
    pub tombstone_retention_secs: i64,
    pub caps: LedgerCaps,
}

impl LedgerOptions {
    pub fn from_config(pc: &ProxyConfig) -> Self {
        Self {
            tombstone_retention_secs: i64::from(pc.dedup_tombstone_retention()),
            caps: LedgerCaps::new(
                pc.ledger_max_rows_per_proxy(),
                pc.ledger_max_bytes_per_proxy(),
                pc.ledger_max_rows_total(),
                pc.ledger_max_bytes_total(),
            ),
        }
    }
}

impl Default for LedgerOptions {
    fn default() -> Self {
        Self {
            tombstone_retention_secs: i64::from(ProxyConfig::DEFAULT_TOMBSTONE_RETENTION_SECONDS),
            caps: LedgerCaps::default(),
        }
    }
}

/// Startup invariant (L1): `T >= R + M` for every stored proxy config.
///
/// `proxy_retry_ages` yields `(proxy_id, R seconds)`. The error text names the
/// proxy id (operator-controlled) and numbers only.
///
/// Relation to `stale_retention` (mod.rs): that check is `E >= R + M` and stays
/// a warning, because a stale E only shortens how long event *bodies* live; the
/// dedup window that protects against double-ingest is `max(E, T)`. A broken T
/// silently re-accepts retransmitted events as new, so it is a boot error.
///
/// A retransmission later than T after acceptance is outside this invariant
/// (T >= R + M means a legitimate producer never retransmits that late). If one
/// arrives anyway it is treated as new: it may also look like a new epoch
/// (spurious `producer_epoch_change`) once its epoch row was swept. That is
/// accepted behaviour, not a defect.
pub fn check_tombstone_invariant<'a>(
    tombstone_secs: i64,
    margin_secs: u32,
    proxy_retry_ages: impl IntoIterator<Item = (&'a str, i64)>,
) -> Result<()> {
    for (id, r) in proxy_retry_ages {
        if tombstone_secs < r.saturating_add(i64::from(margin_secs)) {
            bail!(
                "proxy.dedup_tombstone_retention_seconds ({tombstone_secs}) is below \
                 max_offline_retry_age_seconds ({r}) of proxy {id} plus \
                 proxy.ack_loss_margin_seconds ({margin_secs}); a retransmitted event could be \
                 accepted twice (ledger L1 requires T >= R + M). Raise the tombstone retention \
                 or lower the margin or the proxy's retry age"
            );
        }
    }
    Ok(())
}

/// The config-PUT form of the L1 rules: `E >= R + M` and `T >= R + M`. A PUT
/// that breaks either is refused (422) so it cannot make the next boot fail.
pub fn config_retention_ok(
    event_retention: i64,
    max_offline_retry_age: i64,
    margin_secs: u32,
    tombstone_retention: i64,
) -> bool {
    let need = max_offline_retry_age.saturating_add(i64::from(margin_secs));
    event_retention >= need && tombstone_retention >= need
}

/// Result of a committed batch, in batch order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IngestOutcome {
    pub accepted: Vec<Uuid>,
    pub duplicate: Vec<Uuid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictKind {
    /// Same `(proxy_id, event_id)`, different canonical event.
    Conflict,
    /// Same `(proxy_id, epoch_id, sequence)`, different `event_id`.
    SequenceConflict,
    /// SV-1: `invocation_id` already bound to another proxy.
    InvocationOwnerConflict,
}

impl ConflictKind {
    pub fn error_code(self) -> ErrorCode {
        match self {
            ConflictKind::Conflict => ErrorCode::Conflict,
            ConflictKind::SequenceConflict => ErrorCode::SequenceConflict,
            ConflictKind::InvocationOwnerConflict => ErrorCode::InvocationOwnerConflict,
        }
    }
}

/// One 409 item: index in the submitted batch, the (validated) event id, code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictItem {
    pub index: usize,
    pub event_id: Uuid,
    pub kind: ConflictKind,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// 409: nothing was stored. Lists every conflicting item.
    Conflicts(Vec<ConflictItem>),
    /// 503 `storage_limit`: a cap would be exceeded. Nothing was stored.
    StorageLimit,
    /// 503 `storage_unavailable`: the store failed. Nothing was stored.
    StorageUnavailable,
    /// Caller bug: an event's `proxy_id` differs from the authenticated one.
    /// The handler checks this before calling; nothing was stored.
    ProxyMismatch,
}

impl LedgerError {
    /// The envelope-level code for non-item errors.
    pub fn error_code(&self) -> Option<ErrorCode> {
        match self {
            LedgerError::StorageLimit => Some(ErrorCode::StorageLimit),
            LedgerError::StorageUnavailable => Some(ErrorCode::StorageUnavailable),
            _ => None,
        }
    }
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LedgerError::Conflicts(_) => "ledger conflict",
            LedgerError::StorageLimit => "ledger storage limit reached",
            LedgerError::StorageUnavailable => "ledger storage unavailable",
            LedgerError::ProxyMismatch => "event proxy_id does not match the caller",
        })
    }
}

impl std::error::Error for LedgerError {}

impl From<rusqlite::Error> for LedgerError {
    fn from(e: rusqlite::Error) -> Self {
        // Log the SQLite result code only, never the message.
        let code = match &e {
            rusqlite::Error::SqliteFailure(f, _) => format!("{:?}", f.code),
            _ => "other".to_string(),
        };
        tracing::error!(sqlite_code = %code, "proxy ledger storage failure");
        LedgerError::StorageUnavailable
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GapKind {
    ProducerEpochChange,
    SequenceGap,
}

impl GapKind {
    fn as_str(self) -> &'static str {
        match self {
            GapKind::ProducerEpochChange => "producer_epoch_change",
            GapKind::SequenceGap => "sequence_gap",
        }
    }
}

/// A server-derived audit gap (L4). Only `sequence_gap` can close; a closed gap
/// stays listed until its retention expires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GapRecord {
    pub gap_id: String,
    pub kind: GapKind,
    pub detected_at: i64,
    pub epoch_id: String,
    pub previous_epoch_id: Option<String>,
    pub from_sequence: Option<i64>,
    pub to_sequence: Option<i64>,
    pub open: bool,
    pub closed_at: Option<i64>,
}

/// What S5 needs from a stored event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEvent {
    pub created_seq: i64,
    pub received_at: i64,
    pub epoch_id: String,
    pub sequence: i64,
    pub canonical: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub event_rows: i64,
    pub event_bytes: i64,
    pub tombstone_rows: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepStats {
    pub events: usize,
    pub tombstones: usize,
    pub gaps: usize,
    pub epochs: usize,
    pub invocations: usize,
}

pub struct Ledger {
    conn: Mutex<Connection>,
    opts: LedgerOptions,
}

const SCHEMA: &str = "
CREATE TABLE events (
    created_seq   INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_id      TEXT NOT NULL,
    event_id      TEXT NOT NULL,
    epoch_id      TEXT NOT NULL,
    sequence      INTEGER NOT NULL,
    invocation_id TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    occurred_at   TEXT NOT NULL,
    received_at   INTEGER NOT NULL,
    canonical     BLOB NOT NULL,
    sha256        BLOB NOT NULL,
    size          INTEGER NOT NULL,
    UNIQUE (proxy_id, event_id),
    UNIQUE (proxy_id, epoch_id, sequence)
);
CREATE INDEX events_received ON events (proxy_id, received_at);
CREATE INDEX events_invocation ON events (invocation_id);
CREATE TABLE tombstones (
    proxy_id    TEXT NOT NULL,
    event_id    TEXT NOT NULL,
    epoch_id    TEXT NOT NULL,
    sequence    INTEGER NOT NULL,
    sha256      BLOB NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (proxy_id, event_id),
    UNIQUE (proxy_id, epoch_id, sequence)
) WITHOUT ROWID;
CREATE INDEX tombstones_received ON tombstones (received_at);
CREATE TABLE epochs (
    ord              INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_id         TEXT NOT NULL,
    epoch_id         TEXT NOT NULL,
    highest_sequence INTEGER NOT NULL,
    last_received_at INTEGER NOT NULL,
    UNIQUE (proxy_id, epoch_id)
);
CREATE TABLE gaps (
    rowid_seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    gap_id            TEXT NOT NULL UNIQUE,
    proxy_id          TEXT NOT NULL,
    kind              TEXT NOT NULL,
    detected_at       INTEGER NOT NULL,
    epoch_id          TEXT NOT NULL,
    previous_epoch_id TEXT,
    from_sequence     INTEGER,
    to_sequence       INTEGER,
    open              INTEGER NOT NULL,
    closed_at         INTEGER,
    present           INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX gaps_open ON gaps (proxy_id, epoch_id, open, from_sequence);
CREATE TABLE invocations (
    invocation_id    TEXT PRIMARY KEY,
    proxy_id         TEXT NOT NULL,
    last_received_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE usage (
    proxy_id       TEXT PRIMARY KEY,
    event_rows     INTEGER NOT NULL,
    event_bytes    INTEGER NOT NULL,
    tombstone_rows INTEGER NOT NULL
) WITHOUT ROWID;
";

impl Ledger {
    /// Open (creating if needed) the ledger. Refuses a symlink (checked, and
    /// SQLite is opened with `NOFOLLOW`), a non-regular file, a file owned by
    /// another user, a group/world accessible file, a newer or foreign schema,
    /// or a filesystem that cannot do WAL.
    pub fn open(path: &Path, opts: LedgerOptions) -> Result<Self> {
        prepare_file(path)?;
        // SQLite's NOFOLLOW rejects a symlink in ANY path component (for example
        // /var -> /private/var), so resolve the directory first; the final
        // component was already checked by prepare_file and NOFOLLOW covers it.
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .canonicalize()
            .context("resolve ledger directory")?;
        let real = dir.join(path.file_name().context("ledger path has no file name")?);
        let conn = Connection::open_with_flags(
            &real,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .context("open ledger database")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "fullfsync", true)?;
        conn.pragma_update(None, "secure_delete", true)?;
        let jm: String = conn.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        let sync: i64 = conn.pragma_query_value(None, "synchronous", |r| r.get(0))?;
        if !jm.eq_ignore_ascii_case("wal") || sync != 2 {
            bail!("ledger database could not be set to WAL with synchronous=FULL");
        }
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            opts,
        })
    }

    pub fn options(&self) -> &LedgerOptions {
        &self.opts
    }

    /// Insert a validated batch atomically. `received_at` is the server clock
    /// (unix seconds); retention uses it and never `occurred_at` (L1).
    pub fn insert_batch(
        &self,
        proxy_id: &str,
        events: &[ProxyEvent],
        received_at: i64,
    ) -> Result<IngestOutcome, LedgerError> {
        if events.iter().any(|e| e.proxy_id.as_str() != proxy_id) {
            return Err(LedgerError::ProxyMismatch);
        }
        let prepared: Vec<Prepared> = events.iter().map(Prepared::new).collect();
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let mut out = IngestOutcome::default();
        let mut conflicts = Vec::new();
        let mut fresh: Vec<(usize, &Prepared)> = Vec::new();
        for (index, (ev, p)) in events.iter().zip(&prepared).enumerate() {
            let existing_digest: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT sha256 FROM events WHERE proxy_id = ?1 AND event_id = ?2",
                    params![proxy_id, ev.event_id.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            let existing_digest = match existing_digest {
                Some(d) => Some(d),
                None => tx
                    .query_row(
                        "SELECT sha256 FROM tombstones WHERE proxy_id = ?1 AND event_id = ?2",
                        params![proxy_id, ev.event_id.as_str()],
                        |r| r.get(0),
                    )
                    .optional()?,
            };
            if let Some(d) = existing_digest {
                if d == p.digest {
                    out.duplicate.push(ev.event_id.clone());
                } else {
                    conflicts.push(conflict(index, ev, ConflictKind::Conflict));
                }
                continue;
            }
            let seq_taken: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM tombstones WHERE proxy_id = ?1 AND epoch_id = ?2 AND sequence = ?3)
                     OR EXISTS(SELECT 1 FROM events WHERE proxy_id = ?1 AND epoch_id = ?2 AND sequence = ?3)",
                params![proxy_id, ev.epoch_id.as_str(), p.sequence],
                |r| r.get(0),
            )?;
            if seq_taken {
                // Only the later colliding event is reported (the stored one
                // is already accepted and not part of this batch's items).
                conflicts.push(conflict(index, ev, ConflictKind::SequenceConflict));
                continue;
            }
            let owner: Option<String> = tx
                .query_row(
                    "SELECT proxy_id FROM invocations WHERE invocation_id = ?1",
                    params![p.invocation_id],
                    |r| r.get(0),
                )
                .optional()?;
            if owner.as_deref().is_some_and(|o| o != proxy_id) {
                conflicts.push(conflict(index, ev, ConflictKind::InvocationOwnerConflict));
                continue;
            }
            tx.execute(
                "INSERT INTO events (proxy_id, event_id, epoch_id, sequence, invocation_id,
                     event_type, occurred_at, received_at, canonical, sha256, size)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    proxy_id,
                    ev.event_id.as_str(),
                    ev.epoch_id.as_str(),
                    p.sequence,
                    p.invocation_id,
                    p.event_type,
                    ev.occurred_at.as_str(),
                    received_at,
                    p.canonical,
                    p.digest,
                    p.canonical.len() as i64,
                ],
            )?;
            tx.execute(
                "INSERT INTO tombstones (proxy_id, event_id, epoch_id, sequence, sha256, received_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    proxy_id,
                    ev.event_id.as_str(),
                    ev.epoch_id.as_str(),
                    p.sequence,
                    p.digest,
                    received_at
                ],
            )?;
            tx.execute(
                "INSERT INTO invocations (invocation_id, proxy_id, last_received_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (invocation_id) DO UPDATE SET last_received_at = excluded.last_received_at",
                params![p.invocation_id, proxy_id, received_at],
            )?;
            out.accepted.push(ev.event_id.clone());
            fresh.push((index, p));
        }
        if !conflicts.is_empty() {
            // Dropping `tx` rolls back every insert of this batch.
            return Err(LedgerError::Conflicts(conflicts));
        }
        if fresh.is_empty() {
            return Ok(out);
        }

        // Gap derivation runs over the batch sorted by (epoch order of first
        // appearance, sequence), so the result does not depend on the order
        // inside the batch.
        let mut epoch_order: HashMap<&str, usize> = HashMap::new();
        for (index, _) in &fresh {
            let next = epoch_order.len();
            epoch_order
                .entry(events[*index].epoch_id.as_str())
                .or_insert(next);
        }
        let mut seqs: Vec<(usize, &str, i64)> = fresh
            .iter()
            .map(|(i, p)| {
                let e = events[*i].epoch_id.as_str();
                (epoch_order[e], e, p.sequence)
            })
            .collect();
        seqs.sort_unstable();
        let mut gaps_added = false;
        for (_, epoch, seq) in seqs {
            gaps_added |= derive_gaps(
                &tx,
                proxy_id,
                epoch,
                seq,
                received_at,
                self.opts.tombstone_retention_secs,
            )?;
        }

        let rows = fresh.len() as i64;
        let bytes: i64 = fresh.iter().map(|(_, p)| p.canonical.len() as i64).sum();
        tx.execute(
            "INSERT INTO usage (proxy_id, event_rows, event_bytes, tombstone_rows)
             VALUES (?1, ?2, ?3, ?2)
             ON CONFLICT (proxy_id) DO UPDATE SET
                 event_rows = event_rows + excluded.event_rows,
                 event_bytes = event_bytes + excluded.event_bytes,
                 tombstone_rows = tombstone_rows + excluded.tombstone_rows",
            params![proxy_id, rows, bytes],
        )?;
        if self.over_caps(&tx, proxy_id)? {
            return Err(LedgerError::StorageLimit);
        }
        if gaps_added {
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM gaps WHERE proxy_id = ?1 AND open = 1 AND kind = 'sequence_gap'",
                params![proxy_id],
                |r| r.get(0),
            )?;
            if n > MAX_GAPS_PER_PROXY {
                return Err(LedgerError::StorageLimit);
            }
        }
        tx.commit()?;
        Ok(out)
    }

    fn over_caps(
        &self,
        tx: &rusqlite::Transaction<'_>,
        proxy_id: &str,
    ) -> Result<bool, LedgerError> {
        let c = &self.opts.caps;
        let (pr, pb, pt): (i64, i64, i64) = tx.query_row(
            "SELECT event_rows, event_bytes, tombstone_rows FROM usage WHERE proxy_id = ?1",
            params![proxy_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let (tr, tb, tt): (i64, i64, i64) = tx.query_row(
            "SELECT COALESCE(SUM(event_rows),0), COALESCE(SUM(event_bytes),0),
                    COALESCE(SUM(tombstone_rows),0) FROM usage",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let pages: i64 = tx.pragma_query_value(None, "page_count", |r| r.get(0))?;
        let free: i64 = tx.pragma_query_value(None, "freelist_count", |r| r.get(0))?;
        let page_size: i64 = tx.pragma_query_value(None, "page_size", |r| r.get(0))?;
        let live_bytes = (pages - free).saturating_mul(page_size);
        let over = |v: i64, cap: u64| u64::try_from(v).is_ok_and(|v| v > cap);
        Ok(over(pr, c.rows_per_proxy)
            || over(pt, c.tombstones_per_proxy)
            || over(pb, c.bytes_per_proxy)
            || over(tr, c.rows_total)
            || over(tt, c.tombstones_total)
            || over(tb, c.bytes_total)
            || over(live_bytes, c.file_bytes))
    }

    /// Retention sweep by server `received_at` only (L1). Event rows go after
    /// `event_retention(proxy_id)` seconds, tombstones after T, gap records after
    /// E, invocation owner bindings after `max(E, T)`, and non-latest epoch
    /// rows after T. A row is kept while `now - received_at <= retention`.
    /// Callable at any time; one transaction.
    pub fn sweep(
        &self,
        now: i64,
        event_retention: &dyn Fn(&str) -> i64,
    ) -> Result<SweepStats, LedgerError> {
        let t = self.opts.tombstone_retention_secs;
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let proxies: Vec<String> = {
            let mut st = tx.prepare(
                "SELECT proxy_id FROM events UNION SELECT proxy_id FROM gaps
                 UNION SELECT proxy_id FROM invocations",
            )?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut s = SweepStats::default();
        for p in &proxies {
            let e = event_retention(p);
            s.events += tx.execute(
                "DELETE FROM events WHERE proxy_id = ?1 AND received_at < ?2",
                params![p, now.saturating_sub(e)],
            )?;
            s.gaps += tx.execute(
                "DELETE FROM gaps WHERE proxy_id = ?1 AND detected_at < ?2",
                params![p, now.saturating_sub(e)],
            )?;
            s.invocations += tx.execute(
                "DELETE FROM invocations WHERE proxy_id = ?1 AND last_received_at < ?2",
                params![p, now.saturating_sub(e.max(t))],
            )?;
        }
        s.tombstones += tx.execute(
            "DELETE FROM tombstones WHERE received_at < ?1",
            params![now.saturating_sub(t)],
        )?;
        s.epochs += tx.execute(
            "DELETE FROM epochs WHERE last_received_at < ?1
               AND ord NOT IN (SELECT MAX(ord) FROM epochs GROUP BY proxy_id)",
            params![now.saturating_sub(t)],
        )?;
        tx.execute_batch(
            "DELETE FROM usage;
             INSERT INTO usage (proxy_id, event_rows, event_bytes, tombstone_rows)
                 SELECT proxy_id, COUNT(*), COALESCE(SUM(size),0), 0 FROM events GROUP BY proxy_id;
             INSERT INTO usage (proxy_id, event_rows, event_bytes, tombstone_rows)
                 SELECT proxy_id, 0, 0, COUNT(*) FROM tombstones GROUP BY proxy_id
                 ON CONFLICT (proxy_id) DO UPDATE SET tombstone_rows = excluded.tombstone_rows;",
        )?;
        tx.commit()?;
        // secure_delete zeroes freed pages in the database, but the WAL can
        // still hold older copies until it is checkpointed and truncated.
        if let Err(e) = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())) {
            tracing::warn!(error = %LedgerError::from(e), "proxy ledger WAL checkpoint after sweep failed");
        }
        Ok(s)
    }

    /// Server-derived gaps of a proxy in detection order.
    pub fn gaps(&self, proxy_id: &str) -> Result<Vec<GapRecord>, LedgerError> {
        let conn = self.conn.lock();
        let mut st = conn.prepare(
            "SELECT gap_id, kind, detected_at, epoch_id, previous_epoch_id, from_sequence,
                    to_sequence, open, closed_at FROM gaps WHERE proxy_id = ?1 ORDER BY rowid_seq",
        )?;
        let rows = st.query_map(params![proxy_id], |r| {
            let kind: String = r.get(1)?;
            Ok(GapRecord {
                gap_id: r.get(0)?,
                kind: if kind == "sequence_gap" {
                    GapKind::SequenceGap
                } else {
                    GapKind::ProducerEpochChange
                },
                detected_at: r.get(2)?,
                epoch_id: r.get(3)?,
                previous_epoch_id: r.get(4)?,
                from_sequence: r.get(5)?,
                to_sequence: r.get(6)?,
                open: r.get::<_, i64>(7)? != 0,
                closed_at: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The stored event row (absent after retention removed the body).
    pub fn stored_event(
        &self,
        proxy_id: &str,
        event_id: &str,
    ) -> Result<Option<StoredEvent>, LedgerError> {
        let conn = self.conn.lock();
        Ok(conn
            .query_row(
                "SELECT created_seq, received_at, epoch_id, sequence, canonical FROM events
                 WHERE proxy_id = ?1 AND event_id = ?2",
                params![proxy_id, event_id],
                |r| {
                    Ok(StoredEvent {
                        created_seq: r.get(0)?,
                        received_at: r.get(1)?,
                        epoch_id: r.get(2)?,
                        sequence: r.get(3)?,
                        canonical: r.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    /// Usage counters of one proxy (zeros when none).
    pub fn usage(&self, proxy_id: &str) -> Result<Usage, LedgerError> {
        let conn = self.conn.lock();
        Ok(conn
            .query_row(
                "SELECT event_rows, event_bytes, tombstone_rows FROM usage WHERE proxy_id = ?1",
                params![proxy_id],
                |r| {
                    Ok(Usage {
                        event_rows: r.get(0)?,
                        event_bytes: r.get(1)?,
                        tombstone_rows: r.get(2)?,
                    })
                },
            )
            .optional()?
            .unwrap_or_default())
    }
}

struct Prepared {
    canonical: Vec<u8>,
    digest: Vec<u8>,
    sequence: i64,
    invocation_id: String,
    event_type: &'static str,
}

impl Prepared {
    fn new(ev: &ProxyEvent) -> Self {
        let canonical = canonical_event_bytes(ev);
        let digest = Sha256::digest(&canonical).to_vec();
        Prepared {
            canonical,
            digest,
            sequence: ev.sequence.get(),
            invocation_id: ev.payload.invocation_id().as_str().to_string(),
            event_type: match &ev.payload {
                EventPayload::Started(_) => "invocation.started",
                EventPayload::Completed(_) => "invocation.completed",
                EventPayload::CancelRequested(_) => "invocation.cancel_requested",
            },
        }
    }
}

fn conflict(index: usize, ev: &ProxyEvent, kind: ConflictKind) -> ConflictItem {
    ConflictItem {
        index,
        event_id: ev.event_id.clone(),
        kind,
    }
}

/// Apply one newly accepted `(epoch, sequence)` to the gap model. Returns true
/// when a gap row was inserted.
fn derive_gaps(
    tx: &rusqlite::Transaction<'_>,
    proxy_id: &str,
    epoch: &str,
    seq: i64,
    now: i64,
    tombstone_secs: i64,
) -> Result<bool, LedgerError> {
    let mut added = false;
    let highest: Option<i64> = tx
        .query_row(
            "SELECT highest_sequence FROM epochs WHERE proxy_id = ?1 AND epoch_id = ?2",
            params![proxy_id, epoch],
            |r| r.get(0),
        )
        .optional()?;
    let highest = match highest {
        Some(h) => h,
        None => {
            let previous: Option<String> = tx
                .query_row(
                    "SELECT epoch_id FROM epochs WHERE proxy_id = ?1 ORDER BY ord DESC LIMIT 1",
                    params![proxy_id],
                    |r| r.get(0),
                )
                .optional()?;
            tx.execute(
                "INSERT INTO epochs (proxy_id, epoch_id, highest_sequence, last_received_at)
                 VALUES (?1, ?2, 0, ?3)",
                params![proxy_id, epoch, now],
            )?;
            if let Some(prev) = previous {
                insert_gap(
                    tx,
                    proxy_id,
                    GapKind::ProducerEpochChange,
                    now,
                    epoch,
                    Some(&prev),
                    None,
                )?;
                added = true;
            }
            0
        }
    };
    if seq > highest {
        if seq > highest + 1 {
            insert_gap(
                tx,
                proxy_id,
                GapKind::SequenceGap,
                now,
                epoch,
                None,
                Some((highest + 1, seq - 1)),
            )?;
            added = true;
        }
        tx.execute(
            "UPDATE epochs SET highest_sequence = ?3, last_received_at = ?4
             WHERE proxy_id = ?1 AND epoch_id = ?2",
            params![proxy_id, epoch, seq, now],
        )?;
    } else {
        tx.execute(
            "UPDATE epochs SET last_received_at = ?3 WHERE proxy_id = ?1 AND epoch_id = ?2",
            params![proxy_id, epoch, now],
        )?;
        // Each open gap has a `present` counter: an accepted sequence inside
        // its range adds one, and the gap closes when present == range length.
        // O(log n) per arrival, no range scan. A sequence is accepted once per
        // (epoch, sequence) while its tombstone lives, so counts cannot double.
        // Gaps older than T stop counting: a replay of an already-filled
        // sequence (tombstone expired) must not close a gap wrongly, so such a
        // gap can only stay open (safe direction).
        // Gaps within an epoch are disjoint (a gap always starts above the
        // highest accepted sequence), so at most one open gap contains `seq`:
        // the one with the greatest start <= seq. Index range lookup, O(log n).
        let cand: Option<(String, i64, i64, i64, i64)> = tx
            .query_row(
                "SELECT gap_id, from_sequence, to_sequence, present, detected_at FROM gaps
                 WHERE proxy_id = ?1 AND epoch_id = ?2 AND open = 1 AND from_sequence <= ?3
                 ORDER BY from_sequence DESC LIMIT 1",
                params![proxy_id, epoch, seq],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        if let Some((gap_id, from, to, present, detected_at)) = cand {
            if to >= seq && detected_at >= now.saturating_sub(tombstone_secs) {
                let present = present + 1;
                if present > to - from {
                    tx.execute(
                        "UPDATE gaps SET present = ?2, open = 0, closed_at = ?3 WHERE gap_id = ?1",
                        params![gap_id, present, now],
                    )?;
                } else {
                    tx.execute(
                        "UPDATE gaps SET present = ?2 WHERE gap_id = ?1",
                        params![gap_id, present],
                    )?;
                }
            }
        }
    }
    Ok(added)
}

fn insert_gap(
    tx: &rusqlite::Transaction<'_>,
    proxy_id: &str,
    kind: GapKind,
    now: i64,
    epoch: &str,
    previous_epoch: Option<&str>,
    range: Option<(i64, i64)>,
) -> Result<(), LedgerError> {
    tx.execute(
        "INSERT INTO gaps (gap_id, proxy_id, kind, detected_at, epoch_id, previous_epoch_id,
             from_sequence, to_sequence, open)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
        params![
            uuid::Uuid::new_v4().to_string(),
            proxy_id,
            kind.as_str(),
            now,
            epoch,
            previous_epoch,
            range.map(|r| r.0),
            range.map(|r| r.1),
        ],
    )?;
    Ok(())
}

/// Create the file owner-only when missing; refuse unsafe existing files.
fn prepare_file(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options
                .open(path)
                .context("create ledger database")?
                .sync_all()?;
            #[cfg(unix)]
            std::fs::File::open(
                path.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?
            .sync_all()?;
            Ok(())
        }
        Err(e) => Err(e).context("stat ledger database"),
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                bail!("ledger database must not be a symlink");
            }
            if !meta.is_file() {
                bail!("ledger database is not a regular file");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o077 != 0 {
                    bail!("ledger database must be owner-only (it holds event data)");
                }
                use std::os::unix::fs::MetadataExt;
                // SAFETY: geteuid has no preconditions and cannot fail.
                if meta.uid() != unsafe { libc::geteuid() } {
                    bail!("ledger database must be owned by the server user");
                }
            }
            Ok(())
        }
    }
}

fn init_schema(conn: &Connection) -> Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let tables: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0))?;
    match (version, tables) {
        (0, 0) => {
            conn.execute_batch(&format!(
                "BEGIN IMMEDIATE;{SCHEMA}PRAGMA user_version = {SCHEMA_VERSION};COMMIT;"
            ))
            .context("create ledger schema")?;
            Ok(())
        }
        (SCHEMA_VERSION, _) => Ok(()),
        _ => bail!("ledger database has an unknown format version"),
    }
}
