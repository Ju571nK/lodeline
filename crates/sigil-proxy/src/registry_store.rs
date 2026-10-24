//! Durable local metadata registry (README "D-05 metadata registry (N9)",
//! `contracts/registry.md` R1/R3/R7).
//!
//! One SQLite file (WAL, `synchronous=FULL`, mode 0600) next to the key file in
//! the state directory. What it holds, and nothing else:
//!
//! * `entries`: the registry entries (the nine immutable fields, `observed_at`,
//!   the tool name and the tool definition as JCS text). The name and definition
//!   are UNTRUSTED CONTENT; they are stored because the upload needs the
//!   definition and the local tool identity (the name) pairs tools across a key
//!   rotation. They are never logged and never part of a `Debug` or error text.
//! * `snapshots` / `snapshot_members`: the latest complete inventory per scope
//!   key (refs only).
//! * `reports`: inventory reports not yet acknowledged (the exact bytes sent, so
//!   a retry is byte-identical).
//! * `rotations`: declared key rotations (`key_id` of the new key).
//!
//! Durability rule (README "Sync ordering"): [`RegistryStore::commit_complete`]
//! returns only after the entries and the snapshot are committed, so a start
//! event may reference a `metadata_ref` as soon as a call returns it.
//!
//! The API is synchronous and blocking (SQLite, fsync). Async callers use
//! `spawn_blocking`. [`RegistryStore`] is a cheap clonable handle.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::json;

use crate::jcs::{self, JcsError};
use crate::registry_key::{sha256_hex, Key, ScopeKey, CANON_V1};

/// SQLite file inside the state directory.
pub const REGISTRY_DB_FILE: &str = "registry.sqlite3";
const SCHEMA_VERSION: &str = "1";
/// Per-definition bound, measured on the JCS text. registry.md R2 allows 256 KiB
/// per uploaded entry; the other fields take at most about 1 KiB (three 128-byte
/// ids plus fixed fields and member names), and re-serialising can differ from
/// the JCS text by a few bytes per number, so 6 KiB of margin is left. The
/// client re-checks the serialized entry before sending.
pub const MAX_DEFINITION_BYTES: usize = 250 * 1024;
/// Unsent incomplete reports kept; the oldest ones are dropped beyond this.
/// A complete report is never dropped for space.
pub const MAX_PENDING_INCOMPLETE_REPORTS: usize = 64;

/// A registry failure. Never carries content (names, definitions, key bytes,
/// paths).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// Filesystem error (kind only).
    Io(std::io::ErrorKind),
    /// SQLite refused or failed.
    Storage,
    /// The database is not the expected schema or belongs to another proxy.
    Corrupt,
    /// The key file is unreadable as a key.
    KeyCorrupt,
    /// No randomness available.
    Random,
    /// A stored entry disagrees with the one being written (same ref, other
    /// immutable fields). The write is refused.
    Integrity,
    /// An input is outside a bound (definition size, ...).
    Invalid(&'static str),
    /// A definition cannot be canonicalised.
    Jcs(JcsError),
    /// Not a unix host.
    Unsupported,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::Io(k) => write!(f, "registry i/o error ({k:?})"),
            RegistryError::Storage => f.write_str("registry storage error"),
            RegistryError::Corrupt => f.write_str("registry database is not usable"),
            RegistryError::KeyCorrupt => f.write_str("registry key file is not usable"),
            RegistryError::Random => f.write_str("no random source"),
            RegistryError::Integrity => f.write_str("registry entry integrity mismatch"),
            RegistryError::Invalid(w) => write!(f, "registry input out of bounds ({w})"),
            RegistryError::Jcs(e) => write!(f, "cannot canonicalise: {e}"),
            RegistryError::Unsupported => f.write_str("unsupported platform"),
        }
    }
}

impl std::error::Error for RegistryError {}

impl From<rusqlite::Error> for RegistryError {
    fn from(_: rusqlite::Error) -> Self {
        // The sqlite message is dropped on purpose (it can echo statements).
        RegistryError::Storage
    }
}

impl From<JcsError> for RegistryError {
    fn from(e: JcsError) -> Self {
        RegistryError::Jcs(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// Not yet acknowledged by the server.
    Pending,
    /// The server answered registered or duplicate; the immutable-field hash is
    /// recorded.
    Acked,
    /// The server answered 409 (or the local hash check failed). Kept unchanged,
    /// never uploaded again.
    Quarantined,
    /// Refused by the server for good (repeated 422, or too large alone). Never
    /// uploaded again; counted. Not a conflict, so no gap.
    Poisoned,
}

impl EntryState {
    fn parse(s: &str) -> Option<EntryState> {
        Some(match s {
            "pending" => EntryState::Pending,
            "acked" => EntryState::Acked,
            "quarantined" => EntryState::Quarantined,
            "poisoned" => EntryState::Poisoned,
            _ => return None,
        })
    }
}

/// One registry entry as stored locally. `tool_name` and `definition` are
/// untrusted content and are not shown by `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct EntryRecord {
    pub metadata_ref: String,
    pub scope: ScopeKey,
    pub canon: String,
    pub key_id: String,
    pub fingerprint: String,
    pub observed_at: String,
    pub tool_name: String,
    /// JCS text of the tool object.
    pub definition: String,
    pub state: EntryState,
}

impl fmt::Debug for EntryRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryRecord")
            .field("metadata_ref", &self.metadata_ref)
            .field("key_id", &self.key_id)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl EntryRecord {
    /// SHA-256 over the JCS of the nine immutable fields (README N11 iii).
    pub fn immutable_hash(&self) -> String {
        let v = json!({
            "proxy_id": self.scope.proxy_id,
            "metadata_ref": self.metadata_ref,
            "upstream_id": self.scope.upstream_id,
            "credential_scope_id": self.scope.credential_scope_id,
            "protocol_version": self.scope.protocol_version,
            "observation_source": self.scope.observation_source,
            "canon": self.canon,
            "key_id": self.key_id,
            "fingerprint": self.fingerprint,
        });
        // All members are strings: JCS cannot fail.
        sha256_hex(&jcs::canonicalize(&v).unwrap_or_default())
    }
}

/// The latest complete inventory of one scope key. Names are untrusted content.
#[derive(Clone, PartialEq, Eq)]
pub struct SnapshotRecord {
    pub inventory_id: String,
    pub scope: ScopeKey,
    pub canon: String,
    pub key_id: String,
    pub observed_at: String,
    /// `(metadata_ref, tool_name)`.
    pub members: Vec<(String, String)>,
}

impl fmt::Debug for SnapshotRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotRecord")
            .field("inventory_id", &self.inventory_id)
            .field("key_id", &self.key_id)
            .field("members", &self.members.len())
            .finish_non_exhaustive()
    }
}

/// An inventory report waiting to be acknowledged.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredReport {
    pub report_id: String,
    pub complete: bool,
    /// The exact bytes to send.
    pub body: Vec<u8>,
}

impl fmt::Debug for StoredReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StoredReport({}, {} bytes)",
            self.report_id,
            self.body.len()
        )
    }
}

/// Everything one complete listing commits.
pub struct CompleteCommit {
    pub entries: Vec<EntryRecord>,
    pub snapshot: SnapshotRecord,
    pub report: StoredReport,
}

/// Result of [`RegistryStore::verify_entry`] (README N11 iii).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryCheck {
    /// Acknowledged and the recomputed immutable-field hash equals the one
    /// recorded at the ACK.
    Verified,
    /// Not acknowledged yet (nothing to compare against).
    NotAcked,
    /// The stored fields no longer hash to the value recorded at the ACK.
    Mismatch,
    /// Already quarantined (a registry conflict). Only this state permits the
    /// registry-conflict rewrite of dependent events.
    Quarantined,
    /// Poisoned: a pause, not a conflict. The entry is offered again later
    /// (`registry_client::POISON_RETRY`), so its dependents keep waiting.
    Poisoned,
    /// No such entry.
    Missing,
}

/// How [`RegistryStore::open`] found the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenKind {
    /// No earlier registry state: a new K was generated.
    Fresh,
    /// The existing key and database were loaded.
    Existing,
    /// The database holds entries but the key file is gone: a NEW K was
    /// generated and the comparison state was cleared, so the next complete
    /// inventory is an `initial_baseline`. Entries are kept (events may still
    /// reference them). The caller treats this as state loss (README M1: a new
    /// producer epoch).
    KeyLost,
}

/// Result of [`RegistryStore::rotate_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    pub old_key_id: String,
    pub new_key_id: String,
}

pub(crate) struct Inner {
    conn: Connection,
    dir: PathBuf,
    key: Key,
    proxy_id: String,
}

/// Handle to the local registry. Clones share one connection.
#[derive(Clone)]
pub struct RegistryStore(Arc<Mutex<Inner>>);

impl fmt::Debug for RegistryStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegistryStore")
    }
}

const SCHEMA: &str = "
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE entries(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  metadata_ref TEXT NOT NULL UNIQUE,
  proxy_id TEXT NOT NULL,
  upstream_id TEXT NOT NULL,
  credential_scope_id TEXT NOT NULL,
  protocol_version TEXT NOT NULL,
  observation_source TEXT NOT NULL,
  canon TEXT NOT NULL,
  key_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  definition TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','acked','quarantined','poisoned')),
  ack_hash TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  gap_pending INTEGER NOT NULL DEFAULT 0,
  gap_detector TEXT
);
CREATE TABLE snapshots(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  inventory_id TEXT NOT NULL UNIQUE,
  upstream_id TEXT NOT NULL,
  credential_scope_id TEXT NOT NULL,
  protocol_version TEXT NOT NULL,
  observation_source TEXT NOT NULL,
  canon TEXT NOT NULL,
  key_id TEXT NOT NULL,
  observed_at TEXT NOT NULL
);
CREATE TABLE snapshot_members(
  inventory_id TEXT NOT NULL,
  metadata_ref TEXT NOT NULL,
  PRIMARY KEY(inventory_id, metadata_ref)
) WITHOUT ROWID;
CREATE TABLE reports(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id TEXT NOT NULL UNIQUE,
  complete INTEGER NOT NULL,
  body BLOB NOT NULL
);
CREATE TABLE rotations(key_id TEXT PRIMARY KEY, reason TEXT NOT NULL) WITHOUT ROWID;
";

const ENTRY_COLS: &str = "metadata_ref, proxy_id, upstream_id, credential_scope_id, \
protocol_version, observation_source, canon, key_id, fingerprint, observed_at, tool_name, \
definition, state";

fn row_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<EntryRecord> {
    let state: String = r.get(12)?;
    Ok(EntryRecord {
        metadata_ref: r.get(0)?,
        scope: ScopeKey {
            proxy_id: r.get(1)?,
            upstream_id: r.get(2)?,
            credential_scope_id: r.get(3)?,
            protocol_version: r.get(4)?,
            observation_source: r.get(5)?,
        },
        canon: r.get(6)?,
        key_id: r.get(7)?,
        fingerprint: r.get(8)?,
        observed_at: r.get(9)?,
        tool_name: r.get(10)?,
        definition: r.get(11)?,
        state: EntryState::parse(&state).ok_or(rusqlite::Error::InvalidQuery)?,
    })
}

#[cfg(unix)]
fn create_private(path: &Path) -> Result<(), RegistryError> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map(|_| ())
        .map_err(|e| RegistryError::Io(e.kind()))
}

#[cfg(not(unix))]
fn create_private(_: &Path) -> Result<(), RegistryError> {
    Err(RegistryError::Unsupported)
}

impl RegistryStore {
    /// Open (or create) the registry in `dir` (the proxy state directory, which
    /// the caller already created 0700 and locked). Loads K, or generates one.
    pub fn open(dir: &Path, proxy_id: &str) -> Result<(RegistryStore, OpenKind), RegistryError> {
        let path = dir.join(REGISTRY_DB_FILE);
        let db_existed = match std::fs::symlink_metadata(&path) {
            Ok(md) if md.is_file() => md.len() > 0,
            Ok(_) => return Err(RegistryError::Corrupt),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(RegistryError::Io(e.kind())),
        };
        if !db_existed {
            create_private(&path)?;
        }
        let conn = Connection::open(&path)?;
        let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(RegistryError::Storage);
        }
        conn.execute_batch("PRAGMA synchronous=FULL;")?;
        let level: i64 = conn.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
        if level != 2 {
            return Err(RegistryError::Storage);
        }
        let quick: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if quick != "ok" {
            return Err(RegistryError::Corrupt);
        }
        let tables: i64 = conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))?;
        if tables == 0 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(SCHEMA)?;
            tx.execute(
                "INSERT INTO meta(key, value) VALUES ('schema_version', ?1), ('proxy_id', ?2)",
                params![SCHEMA_VERSION, proxy_id],
            )?;
            tx.commit()?;
        } else {
            let get = |k: &str| -> Result<Option<String>, RegistryError> {
                Ok(conn
                    .query_row("SELECT value FROM meta WHERE key = ?1", [k], |r| r.get(0))
                    .optional()?)
            };
            if get("schema_version")?.as_deref() != Some(SCHEMA_VERSION)
                || get("proxy_id")?.as_deref() != Some(proxy_id)
            {
                return Err(RegistryError::Corrupt);
            }
        }
        let entry_count: i64 = conn.query_row("SELECT count(*) FROM entries", [], |r| r.get(0))?;

        let (key, kind) = match Key::load(dir)? {
            Some(k) => (
                k,
                if tables == 0 {
                    OpenKind::Fresh
                } else {
                    OpenKind::Existing
                },
            ),
            None => {
                // State loss. Forget the comparison state FIRST (committed), then
                // write the new key: a crash in between finds no key again and
                // repeats this branch, never a new key with old snapshots.
                if entry_count > 0 {
                    let tx = conn.unchecked_transaction()?;
                    tx.execute("DELETE FROM snapshot_members", [])?;
                    tx.execute("DELETE FROM snapshots", [])?;
                    tx.commit()?;
                }
                let k = Key::generate()?;
                k.store(dir)?;
                (
                    k,
                    if entry_count > 0 {
                        OpenKind::KeyLost
                    } else {
                        OpenKind::Fresh
                    },
                )
            }
        };
        let inner = Inner {
            conn,
            dir: dir.to_path_buf(),
            key,
            proxy_id: proxy_id.to_string(),
        };
        Ok((RegistryStore(Arc::new(Mutex::new(inner))), kind))
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn proxy_id(&self) -> String {
        self.lock().proxy_id.clone()
    }

    /// The current `key_id` (not secret).
    pub fn key_id(&self) -> String {
        self.lock().key.key_id()
    }

    /// Planned key rotation (registry.md R3, decisions O-2): a new K and `key_id`
    /// are made durable and the OLD K is destroyed at once. The next complete
    /// inventory per scope is reported as `rebaseline` / `key_rotation` with
    /// links. The epoch and sequence are untouched (the caller does nothing).
    ///
    /// Order: the declaration is committed first, then the key file is replaced
    /// atomically. A crash in between leaves a harmless declaration for a key
    /// that never existed.
    pub fn rotate_key(&self) -> Result<Rotation, RegistryError> {
        let mut g = self.lock();
        let new = Key::generate()?;
        let new_key_id = new.key_id();
        g.conn.execute(
            "INSERT INTO rotations(key_id, reason) VALUES (?1, 'key_rotation')",
            [&new_key_id],
        )?;
        if let Err(e) = new.store(&g.dir) {
            // The rename may or may not have happened: trust the disk. If it
            // holds the new key, use it; otherwise keep the old one.
            if let Ok(Some(k)) = Key::load(&g.dir) {
                g.key = k;
            }
            return Err(e);
        }
        let old = std::mem::replace(&mut g.key, new);
        let old_key_id = old.key_id();
        drop(old); // zeroises
        Ok(Rotation {
            old_key_id,
            new_key_id,
        })
    }

    /// Run `f` with the key and queries while holding the store lock, so a
    /// rotation cannot change K between minting and committing.
    pub(crate) fn with<R>(
        &self,
        f: impl FnOnce(&mut Inner) -> Result<R, RegistryError>,
    ) -> Result<R, RegistryError> {
        f(&mut self.lock())
    }

    // -------------------------------------------------------------- queries

    pub fn entry(&self, metadata_ref: &str) -> Result<Option<EntryRecord>, RegistryError> {
        self.lock().entry(metadata_ref)
    }

    /// The latest complete snapshot of a scope key.
    pub fn latest_snapshot(
        &self,
        scope: &ScopeKey,
    ) -> Result<Option<SnapshotRecord>, RegistryError> {
        self.lock().latest_snapshot(scope)
    }

    /// Offline resolution (README "Offline resolution"): the ref of `name` in
    /// the last COMPLETE inventory of `scope`.
    pub fn lookup_tool(&self, scope: &ScopeKey, name: &str) -> Result<ToolLookup, RegistryError> {
        let Some(s) = self.lock().latest_snapshot(scope)? else {
            return Ok(ToolLookup::NoCompleteInventory);
        };
        Ok(
            match s
                .members
                .iter()
                .find(|(_, n)| n == name)
                .map(|(r, _)| r.clone())
            {
                Some(r) => ToolLookup::Found(r),
                None => ToolLookup::NotInInventory,
            },
        )
    }

    pub fn entry_states(
        &self,
        refs: &[String],
    ) -> Result<HashMap<String, EntryState>, RegistryError> {
        let g = self.lock();
        let mut out = HashMap::new();
        for r in refs {
            if let Some(s) = g.entry_state(r)? {
                out.insert(r.clone(), s);
            }
        }
        Ok(out)
    }

    /// Entries still to upload, oldest first. Entries that were refused before
    /// (a 422 counted against them) are not mixed with the others: with
    /// `include_refused` they are offered one at a time, and only when no other
    /// entry is pending, so one bad entry cannot hold the rest back.
    pub fn pending_entries(
        &self,
        limit: usize,
        include_refused: bool,
    ) -> Result<Vec<EntryRecord>, RegistryError> {
        let g = self.lock();
        let rounds: &[(&str, i64)] = if include_refused {
            &[("attempts = 0", limit as i64), ("attempts > 0", 1)]
        } else {
            &[("attempts = 0", limit as i64)]
        };
        for (cond, lim) in rounds {
            let mut st = g.conn.prepare(&format!(
                "SELECT {ENTRY_COLS} FROM entries WHERE state = 'pending' AND {cond} \
                 ORDER BY attempts, seq LIMIT ?1"
            ))?;
            let rows: Vec<EntryRecord> =
                st.query_map([lim], row_entry)?.collect::<Result<_, _>>()?;
            if !rows.is_empty() {
                return Ok(rows);
            }
        }
        Ok(Vec::new())
    }

    /// Entries quarantined after a registry conflict.
    pub fn quarantined_count(&self) -> Result<u64, RegistryError> {
        let n: i64 = self.lock().conn.query_row(
            "SELECT count(*) FROM entries WHERE state = 'quarantined'",
            [],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    /// Entries refused for good.
    pub fn poisoned_count(&self) -> Result<u64, RegistryError> {
        let n: i64 = self.lock().conn.query_row(
            "SELECT count(*) FROM entries WHERE state = 'poisoned'",
            [],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    pub fn pending_entry_count(&self) -> Result<u64, RegistryError> {
        let n: i64 = self.lock().conn.query_row(
            "SELECT count(*) FROM entries WHERE state = 'pending'",
            [],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    pub fn pending_reports(&self, limit: usize) -> Result<Vec<StoredReport>, RegistryError> {
        let g = self.lock();
        let mut st = g
            .conn
            .prepare("SELECT report_id, complete, body FROM reports ORDER BY seq LIMIT ?1")?;
        let rows = st.query_map([limit as i64], |r| {
            Ok(StoredReport {
                report_id: r.get(0)?,
                complete: r.get::<_, i64>(1)? != 0,
                body: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // ------------------------------------------------------------- mutation

    /// Record the server's ACK: each listed pending entry becomes `Acked` with
    /// the hash of its immutable fields (README N11 iii).
    pub fn mark_acked(&self, refs: &[String]) -> Result<(), RegistryError> {
        let g = self.lock();
        let tx = g.conn.unchecked_transaction()?;
        for r in refs {
            let Some(rec) = g.entry(r)? else { continue };
            if matches!(rec.state, EntryState::Quarantined | EntryState::Poisoned) {
                continue;
            }
            tx.execute(
                "UPDATE entries SET state = 'acked', ack_hash = ?2 WHERE metadata_ref = ?1",
                params![r, rec.immutable_hash()],
            )?;
        }
        Ok(tx.commit()?)
    }

    /// Put acknowledged entries back to pending (the server does not know them:
    /// a 424 named them).
    pub fn mark_unacked(&self, refs: &[String]) -> Result<(), RegistryError> {
        let g = self.lock();
        let tx = g.conn.unchecked_transaction()?;
        for r in refs {
            tx.execute(
                "UPDATE entries SET state = 'pending', ack_hash = NULL, attempts = 0 \
                 WHERE metadata_ref = ?1 AND state = 'acked'",
                [r],
            )?;
        }
        Ok(tx.commit()?)
    }

    /// Quarantine an entry unchanged (README M2b): it is never uploaded again.
    /// The same statement sets a durable "gap pending" mark (with who detected
    /// it) that [`RegistryStore::clear_gap_pending`] removes once the spool
    /// seam has run and the gap is queued, so a crash in between repeats those
    /// steps instead of losing the gap. Returns whether the state changed.
    pub fn quarantine(&self, metadata_ref: &str, detector: &str) -> Result<bool, RegistryError> {
        let n = self.lock().conn.execute(
            "UPDATE entries SET state = 'quarantined', gap_pending = 1, gap_detector = ?2 \
             WHERE metadata_ref = ?1 AND state <> 'quarantined'",
            params![metadata_ref, detector],
        )?;
        Ok(n > 0)
    }

    /// Quarantined entries whose conflict handling did not finish: `(ref, detector)`.
    pub fn gap_pending(&self) -> Result<Vec<(String, String)>, RegistryError> {
        let g = self.lock();
        let mut st = g.conn.prepare(
            "SELECT metadata_ref, COALESCE(gap_detector, '') FROM entries \
             WHERE gap_pending = 1 ORDER BY seq",
        )?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn clear_gap_pending(&self, metadata_ref: &str) -> Result<(), RegistryError> {
        self.lock().conn.execute(
            "UPDATE entries SET gap_pending = 0 WHERE metadata_ref = ?1",
            [metadata_ref],
        )?;
        Ok(())
    }

    /// Make every poisoned entry eligible again, with `attempts` refusals
    /// already counted (so one more poisons it again). Returns how many.
    pub fn unpoison_all(&self, attempts: i64) -> Result<usize, RegistryError> {
        Ok(self.lock().conn.execute(
            "UPDATE entries SET state = 'pending', attempts = ?1 WHERE state = 'poisoned'",
            [attempts],
        )?)
    }

    /// Mark a pending entry refused for good.
    pub fn poison(&self, metadata_ref: &str) -> Result<(), RegistryError> {
        self.lock().conn.execute(
            "UPDATE entries SET state = 'poisoned' WHERE metadata_ref = ?1 AND state = 'pending'",
            [metadata_ref],
        )?;
        Ok(())
    }

    /// Drop the latest snapshot of `scope` if it is `inventory_id`: the server
    /// never saw it, so the next complete listing must be an `initial_baseline`.
    pub fn forget_snapshot(
        &self,
        scope: &ScopeKey,
        inventory_id: &str,
    ) -> Result<(), RegistryError> {
        let g = self.lock();
        if g.latest_snapshot(scope)?
            .is_some_and(|s| s.inventory_id == inventory_id)
        {
            let tx = g.conn.unchecked_transaction()?;
            tx.execute(
                "DELETE FROM snapshot_members WHERE inventory_id = ?1",
                [inventory_id],
            )?;
            tx.execute(
                "DELETE FROM snapshots WHERE inventory_id = ?1",
                [inventory_id],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Replace the bytes of a queued report (used to turn a report whose
    /// previous snapshot was discarded into an `initial_baseline`).
    pub fn replace_report_body(&self, report_id: &str, body: &[u8]) -> Result<(), RegistryError> {
        self.lock().conn.execute(
            "UPDATE reports SET body = ?2 WHERE report_id = ?1",
            params![report_id, body],
        )?;
        Ok(())
    }

    /// Count a refusal (a 422 on the entry). An entry that reaches `poison_at`
    /// refusals becomes `Poisoned`; those refs are returned.
    pub fn bump_attempts(
        &self,
        refs: &[String],
        poison_at: i64,
    ) -> Result<Vec<String>, RegistryError> {
        let g = self.lock();
        let tx = g.conn.unchecked_transaction()?;
        let mut poisoned = Vec::new();
        for r in refs {
            tx.execute(
                "UPDATE entries SET attempts = attempts + 1 WHERE metadata_ref = ?1 AND state = 'pending'",
                [r],
            )?;
            let n = tx.execute(
                "UPDATE entries SET state = 'poisoned' WHERE metadata_ref = ?1 \
                 AND state = 'pending' AND attempts >= ?2",
                params![r, poison_at],
            )?;
            if n > 0 {
                poisoned.push(r.clone());
            }
        }
        tx.commit()?;
        Ok(poisoned)
    }

    pub fn report_done(&self, report_id: &str) -> Result<(), RegistryError> {
        self.lock()
            .conn
            .execute("DELETE FROM reports WHERE report_id = ?1", [report_id])?;
        Ok(())
    }

    /// Recompute the immutable-field hash of the local entry and compare it with
    /// the one recorded at the ACK (README N11 iii). A `Mismatch` goes down the
    /// registry-conflict path (the caller quarantines).
    pub fn verify_entry(&self, metadata_ref: &str) -> Result<EntryCheck, RegistryError> {
        let g = self.lock();
        let Some(rec) = g.entry(metadata_ref)? else {
            return Ok(EntryCheck::Missing);
        };
        match rec.state {
            EntryState::Quarantined => Ok(EntryCheck::Quarantined),
            EntryState::Poisoned => Ok(EntryCheck::Poisoned),
            EntryState::Pending => Ok(EntryCheck::NotAcked),
            EntryState::Acked => {
                let want: Option<String> = g.conn.query_row(
                    "SELECT ack_hash FROM entries WHERE metadata_ref = ?1",
                    [metadata_ref],
                    |r| r.get(0),
                )?;
                Ok(if want.as_deref() == Some(rec.immutable_hash().as_str()) {
                    EntryCheck::Verified
                } else {
                    EntryCheck::Mismatch
                })
            }
        }
    }

    /// Commit a complete listing in one transaction: the entries, the new latest
    /// snapshot of the scope key (replacing the previous one) and the report.
    /// Durable on return.
    pub fn commit_complete(&self, c: &CompleteCommit) -> Result<(), RegistryError> {
        self.lock().commit_complete(c)
    }

    /// Queue an incomplete report. It changes nothing else.
    pub fn commit_incomplete(&self, report: &StoredReport) -> Result<(), RegistryError> {
        self.lock().commit_incomplete(report)
    }
}

/// Offline resolution of a tool name (README "Offline resolution").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolLookup {
    Found(String),
    /// A complete inventory exists and does not list the name
    /// (`not_in_inventory`).
    NotInInventory,
    /// No complete inventory yet (`no_complete_inventory`). An ambiguous name
    /// cannot be found here: a listing with a repeated name never completes
    /// (`ambiguous_name`).
    NoCompleteInventory,
}

impl Inner {
    pub(crate) fn key(&self) -> &Key {
        &self.key
    }

    /// Whether a rotation to `key_id` was declared.
    pub(crate) fn rotation_declared(&self, key_id: &str) -> Result<bool, RegistryError> {
        let n: i64 = self.conn.query_row(
            "SELECT count(*) FROM rotations WHERE key_id = ?1",
            [key_id],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    pub(crate) fn entry_state(&self, r: &str) -> Result<Option<EntryState>, RegistryError> {
        let s: Option<String> = self
            .conn
            .query_row(
                "SELECT state FROM entries WHERE metadata_ref = ?1",
                [r],
                |x| x.get(0),
            )
            .optional()?;
        Ok(s.and_then(|s| EntryState::parse(&s)))
    }

    pub(crate) fn entry(&self, r: &str) -> Result<Option<EntryRecord>, RegistryError> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {ENTRY_COLS} FROM entries WHERE metadata_ref = ?1"),
                [r],
                row_entry,
            )
            .optional()?)
    }

    pub(crate) fn latest_snapshot(
        &self,
        scope: &ScopeKey,
    ) -> Result<Option<SnapshotRecord>, RegistryError> {
        if scope.proxy_id != self.proxy_id {
            return Ok(None);
        }
        let head: Option<(String, String, String, String)> = self
            .conn
            .query_row(
                "SELECT inventory_id, canon, key_id, observed_at FROM snapshots \
                 WHERE upstream_id = ?1 AND credential_scope_id = ?2 \
                 AND protocol_version = ?3 AND observation_source = ?4 \
                 ORDER BY seq DESC LIMIT 1",
                params![
                    scope.upstream_id,
                    scope.credential_scope_id,
                    scope.protocol_version,
                    scope.observation_source
                ],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((inventory_id, canon, key_id, observed_at)) = head else {
            return Ok(None);
        };
        let mut st = self.conn.prepare(
            "SELECT m.metadata_ref, e.tool_name FROM snapshot_members m \
             JOIN entries e ON e.metadata_ref = m.metadata_ref \
             WHERE m.inventory_id = ?1 ORDER BY e.seq",
        )?;
        let members = st
            .query_map([&inventory_id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<(String, String)>, _>>()?;
        Ok(Some(SnapshotRecord {
            inventory_id,
            scope: scope.clone(),
            canon,
            key_id,
            observed_at,
            members,
        }))
    }

    fn insert_entry(tx: &rusqlite::Transaction<'_>, e: &EntryRecord) -> Result<(), RegistryError> {
        if e.definition.len() > MAX_DEFINITION_BYTES {
            return Err(RegistryError::Invalid("definition size"));
        }
        let n = tx.execute(
            "INSERT INTO entries(metadata_ref, proxy_id, upstream_id, credential_scope_id, \
             protocol_version, observation_source, canon, key_id, fingerprint, observed_at, \
             tool_name, definition, state) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'pending') \
             ON CONFLICT(metadata_ref) DO NOTHING",
            params![
                e.metadata_ref,
                e.scope.proxy_id,
                e.scope.upstream_id,
                e.scope.credential_scope_id,
                e.scope.protocol_version,
                e.scope.observation_source,
                e.canon,
                e.key_id,
                e.fingerprint,
                e.observed_at,
                e.tool_name,
                e.definition
            ],
        )?;
        if n == 0 {
            // Already stored (a re-listing): the immutable fields must agree.
            let old = tx.query_row(
                &format!("SELECT {ENTRY_COLS} FROM entries WHERE metadata_ref = ?1"),
                [&e.metadata_ref],
                row_entry,
            )?;
            if old.immutable_hash() != e.immutable_hash() {
                return Err(RegistryError::Integrity);
            }
        }
        Ok(())
    }

    pub(crate) fn commit_complete(&mut self, c: &CompleteCommit) -> Result<(), RegistryError> {
        if c.snapshot.scope.proxy_id != self.proxy_id {
            return Err(RegistryError::Invalid("proxy_id"));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for e in &c.entries {
            Self::insert_entry(&tx, e)?;
        }
        let s = &c.snapshot;
        let sc = &s.scope;
        // Only the latest snapshot of a scope key is kept.
        let old: Vec<String> = {
            let mut st = tx.prepare(
                "SELECT inventory_id FROM snapshots WHERE upstream_id = ?1 \
                 AND credential_scope_id = ?2 AND protocol_version = ?3 \
                 AND observation_source = ?4",
            )?;
            let rows = st.query_map(
                params![
                    sc.upstream_id,
                    sc.credential_scope_id,
                    sc.protocol_version,
                    sc.observation_source
                ],
                |r| r.get(0),
            )?;
            rows.collect::<Result<_, _>>()?
        };
        for id in old {
            tx.execute(
                "DELETE FROM snapshot_members WHERE inventory_id = ?1",
                [&id],
            )?;
            tx.execute("DELETE FROM snapshots WHERE inventory_id = ?1", [&id])?;
        }
        tx.execute(
            "INSERT INTO snapshots(inventory_id, upstream_id, credential_scope_id, \
             protocol_version, observation_source, canon, key_id, observed_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                s.inventory_id,
                sc.upstream_id,
                sc.credential_scope_id,
                sc.protocol_version,
                sc.observation_source,
                s.canon,
                s.key_id,
                s.observed_at
            ],
        )?;
        for (r, _) in &s.members {
            tx.execute(
                "INSERT INTO snapshot_members(inventory_id, metadata_ref) VALUES (?1, ?2)",
                params![s.inventory_id, r],
            )?;
        }
        tx.execute(
            "INSERT INTO reports(report_id, complete, body) VALUES (?1, 1, ?2)",
            params![c.report.report_id, c.report.body],
        )?;
        Ok(tx.commit()?)
    }

    pub(crate) fn commit_incomplete(&mut self, r: &StoredReport) -> Result<(), RegistryError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO reports(report_id, complete, body) VALUES (?1, 0, ?2)",
            params![r.report_id, r.body],
        )?;
        tx.execute(
            "DELETE FROM reports WHERE complete = 0 AND seq NOT IN \
             (SELECT seq FROM reports WHERE complete = 0 ORDER BY seq DESC LIMIT ?1)",
            [MAX_PENDING_INCOMPLETE_REPORTS as i64],
        )?;
        Ok(tx.commit()?)
    }
}

/// The canon of this build.
pub fn current_canon() -> &'static str {
    CANON_V1
}
