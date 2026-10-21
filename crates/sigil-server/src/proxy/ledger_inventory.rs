//! Inventory storage, comparison and projection inside the ledger SQLite file
//! (T-13a-server, issue #304).
//!
//! Spec: registry.md R5 (marker), R7 (report, I-1..I-8, projection, Cases),
//! R7b (read views); ledger-and-query.md L1 (retention), L3 (read
//! conventions), L4 (gaps). PX-005/009/010/011, AC-02/05/06.
//!
//! # Model
//!
//! * `inv_reports`: one row per accepted `report_id` with the SHA-256 of the
//!   canonical report (idempotency, I-4). No payload.
//! * `inv_snapshots`: one row per complete report (a snapshot). Members live in
//!   `inv_members`. A snapshot that names a previous snapshot the server does
//!   not hold yet is `pending_previous`; its `comparison` payload is kept in
//!   `pending` until the previous snapshot arrives (I-5).
//! * `inv_drift`, `inv_markers`, `inv_links`: the derived projection.
//!
//! # Order independence
//!
//! Every derived row is a function of the *set* of accepted reports, never of
//! their arrival order:
//!
//! * a snapshot's comparison state depends on its own report and on the report
//!   of its declared previous snapshot only; when that arrives later the
//!   deferred state is computed by the same function (`evaluate`) that ingest
//!   uses when the previous is already known;
//! * "earlier", "latest" and "first" inside a chain are decided by
//!   `(observed_at, inventory_id)` (the report's own clock value, then the
//!   snapshot id), never by receipt order;
//! * `drift_id`, `marker_id` and the ids of inventory gaps are derived from the
//!   report identity (`det_id`), not random.
//!
//! The one place arrival order is visible is by contract: a report whose
//! previous snapshot is already known and inconsistent is rejected (422),
//! while the same report arriving before its previous is accepted and later
//! marked `inconsistent` (I-3, "a failure never un-ACKs the report").
//!
//! # Errors echo nothing
//!
//! Outcomes carry no request value. Refs appear only in the 424 list the
//! caller already holds.

use super::ledger::{GapKind, Ledger, LedgerError, SweepStats, MAX_GAPS_PER_PROXY};
use super::metadata::enum_text;
use super::projection::timestamp_secs;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sigil_proxy_api::{
    Change, Comparison, Completeness, DefinitionComparison, InventoryReport, Link, MetadataRef,
    RebaselineReason,
};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

/// Longest 424 ref list (the producer re-syncs the registry and resends).
pub const MAX_PENDING_REFS: usize = 100;
/// Snapshots a proxy may hold in `pending_previous`. Bounds the work one
/// arrival can trigger (each waiting snapshot is evaluated once, against the
/// arriving snapshot's members, which are loaded once). Initial test value (D-04).
pub const DEFAULT_PENDING_PER_PROXY: u64 = 256;
/// Snapshots a proxy may hold. Initial test value (D-04).
pub const DEFAULT_SNAPSHOTS_PER_PROXY: u64 = 50_000;
/// Member rows a proxy may hold across its snapshots. Initial test value (D-04).
pub const DEFAULT_MEMBER_ROWS_PER_PROXY: u64 = 2_000_000;

/// Inventory storage bounds (503 `storage_limit` beyond them). Atomics so the
/// test hook can lower them through a shared reference.
pub struct InventoryCaps {
    pub snapshots_per_proxy: AtomicU64,
    pub member_rows_per_proxy: AtomicU64,
    /// Snapshots a proxy may hold in `pending_previous` (their payload is kept
    /// and each one costs work when its previous snapshot arrives).
    pub pending_per_proxy: AtomicU64,
}

impl Default for InventoryCaps {
    fn default() -> Self {
        Self {
            snapshots_per_proxy: AtomicU64::new(DEFAULT_SNAPSHOTS_PER_PROXY),
            member_rows_per_proxy: AtomicU64::new(DEFAULT_MEMBER_ROWS_PER_PROXY),
            pending_per_proxy: AtomicU64::new(DEFAULT_PENDING_PER_PROXY),
        }
    }
}

/// Created on a fresh file and by the v2 -> v3 migration.
pub(super) const INVENTORY_DDL: &str = "
CREATE TABLE inv_reports (
    proxy_id    TEXT NOT NULL,
    report_id   TEXT NOT NULL,
    digest      BLOB NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (proxy_id, report_id)
) WITHOUT ROWID;
CREATE INDEX inv_reports_received ON inv_reports (proxy_id, received_at);
CREATE TABLE inv_snapshots (
    snap_seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_id              TEXT NOT NULL,
    inventory_id          TEXT NOT NULL,
    report_id             TEXT NOT NULL,
    epoch_id              TEXT NOT NULL,
    upstream_id           TEXT NOT NULL,
    credential_scope_id   TEXT NOT NULL,
    protocol_version      TEXT NOT NULL,
    observation_source    TEXT NOT NULL,
    canon                 TEXT NOT NULL,
    key_id                TEXT NOT NULL,
    observed_at           TEXT NOT NULL,
    observed_at_s         INTEGER NOT NULL,
    received_at           INTEGER NOT NULL,
    member_count          INTEGER NOT NULL,
    kind                  TEXT NOT NULL,
    previous_inventory_id TEXT,
    reason                TEXT,
    links_present         INTEGER NOT NULL,
    state                 TEXT NOT NULL,
    superseded_at         INTEGER,
    pending               BLOB,
    UNIQUE (proxy_id, inventory_id)
);
CREATE INDEX inv_snapshots_chain ON inv_snapshots
    (proxy_id, upstream_id, credential_scope_id, protocol_version, observation_source,
     canon, key_id, observed_at_s, inventory_id);
CREATE INDEX inv_snapshots_scope ON inv_snapshots
    (proxy_id, upstream_id, credential_scope_id, protocol_version, observation_source,
     observed_at_s, inventory_id);
CREATE INDEX inv_snapshots_proxy ON inv_snapshots (proxy_id, snap_seq);
CREATE INDEX inv_snapshots_awaiting ON inv_snapshots (proxy_id, previous_inventory_id)
    WHERE state = 'pending_previous';
CREATE TABLE inv_members (
    proxy_id     TEXT NOT NULL,
    inventory_id TEXT NOT NULL,
    metadata_ref TEXT NOT NULL,
    PRIMARY KEY (proxy_id, inventory_id, metadata_ref)
) WITHOUT ROWID;
CREATE TABLE inv_links (
    proxy_id              TEXT NOT NULL,
    inventory_id          TEXT NOT NULL,
    from_metadata_ref     TEXT NOT NULL,
    to_metadata_ref       TEXT NOT NULL,
    definition_comparison TEXT NOT NULL,
    PRIMARY KEY (proxy_id, inventory_id, from_metadata_ref)
) WITHOUT ROWID;
CREATE TABLE inv_gap_overflow (
    proxy_id TEXT PRIMARY KEY,
    dropped  INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE inv_drift (
    drift_seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    drift_id              TEXT NOT NULL UNIQUE,
    proxy_id              TEXT NOT NULL,
    inventory_id          TEXT NOT NULL,
    previous_inventory_id TEXT NOT NULL,
    upstream_id           TEXT NOT NULL,
    credential_scope_id   TEXT NOT NULL,
    protocol_version      TEXT NOT NULL,
    observation_source    TEXT NOT NULL,
    change                TEXT NOT NULL,
    metadata_ref          TEXT NOT NULL,
    previous_metadata_ref TEXT,
    detected_at           INTEGER NOT NULL
);
CREATE INDEX inv_drift_proxy ON inv_drift (proxy_id, drift_seq);
CREATE INDEX inv_drift_detected ON inv_drift (proxy_id, detected_at);
CREATE TABLE inv_markers (
    marker_seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    marker_id             TEXT NOT NULL UNIQUE,
    proxy_id              TEXT NOT NULL,
    inventory_id          TEXT NOT NULL,
    previous_inventory_id TEXT,
    upstream_id           TEXT NOT NULL,
    credential_scope_id   TEXT NOT NULL,
    protocol_version      TEXT NOT NULL,
    observation_source    TEXT NOT NULL,
    from_key_id           TEXT NOT NULL,
    to_key_id             TEXT NOT NULL,
    from_canon            TEXT NOT NULL,
    to_canon              TEXT NOT NULL,
    cause                 TEXT NOT NULL,
    links_present         INTEGER NOT NULL,
    detected_at           INTEGER NOT NULL,
    UNIQUE (proxy_id, inventory_id)
);
CREATE INDEX inv_markers_proxy ON inv_markers (proxy_id, marker_seq);
CREATE INDEX inv_markers_detected ON inv_markers (proxy_id, detected_at);
";

// ---- ids ----------------------------------------------------------------------

/// A deterministic UUID-shaped id (version nibble 8, RFC variant) from the
/// identity of what it names, so a recomputed projection keeps its ids and the
/// result does not depend on arrival order.
pub(super) fn det_id(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(b"sigil-inventory-id-v1\0");
    for p in parts {
        h.update(p.as_bytes());
        h.update([0]);
    }
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex = data_encoding::HEXLOWER.encode(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// SHA-256 of the canonical report: members, changes and links are sets, so
/// they are sorted first; everything else is serialised in declaration order.
pub fn report_digest(r: &InventoryReport) -> [u8; 32] {
    let mut c = r.clone();
    if let Some(m) = c.members.as_mut() {
        m.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    }
    match c.comparison.as_mut() {
        Some(Comparison::Compared { changes, .. }) => {
            changes.sort_by(|a, b| change_name(a).cmp(&change_name(b)))
        }
        Some(Comparison::Rebaseline { links, .. }) => links.sort_by(|a, b| {
            (a.from_metadata_ref.as_str(), a.to_metadata_ref.as_str())
                .cmp(&(b.from_metadata_ref.as_str(), b.to_metadata_ref.as_str()))
        }),
        _ => {}
    }
    let mut h = Sha256::new();
    h.update(b"sigil-inventory-report-v1\0");
    h.update(serde_json::to_vec(&c).unwrap_or_default());
    h.finalize().into()
}

// ---- outcomes and inputs --------------------------------------------------------

/// What the handler learned from the registry about every ref the report
/// names (members, change refs, link refs).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RefCheck {
    /// Some ref is registered, but only under another proxy (422, SV-3 style).
    pub other_proxy: bool,
    /// Refs registered nowhere (424), sorted and de-duplicated.
    pub unregistered: Vec<MetadataRef>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InventoryOutcome {
    /// Stored (and projected) in this call.
    Accepted,
    /// The same `report_id` with an equal canonical report was stored before.
    Duplicate,
    /// 422 `semantic_invalid`. Nothing was stored.
    Invalid,
    /// 409 `conflict`: the `report_id` or the `inventory_id` is taken by a
    /// different report. Nothing was stored.
    Conflict,
    /// 424: these refs are not registered (at most [`MAX_PENDING_REFS`]).
    Pending(Vec<MetadataRef>),
}

// ---- pure comparison rules ------------------------------------------------------

/// I-3: the asserted `changes` are exactly the membership difference. Each ref
/// is used once per side; `changed` pairs a ref of `members \ previous` with a
/// ref of `previous \ members`.
pub fn changes_consistent(
    members: &BTreeSet<String>,
    previous: &BTreeSet<String>,
    changes: &[Change],
) -> bool {
    let added_side: BTreeSet<&str> = members.difference(previous).map(String::as_str).collect();
    let removed_side: BTreeSet<&str> = previous.difference(members).map(String::as_str).collect();
    let mut seen_added: BTreeSet<&str> = BTreeSet::new();
    let mut seen_removed: BTreeSet<&str> = BTreeSet::new();
    for c in changes {
        match c {
            Change::Added { metadata_ref } => {
                let r = metadata_ref.as_str();
                if !added_side.contains(r) || !seen_added.insert(r) {
                    return false;
                }
            }
            Change::Removed { metadata_ref } => {
                let r = metadata_ref.as_str();
                if !removed_side.contains(r) || !seen_removed.insert(r) {
                    return false;
                }
            }
            Change::Changed {
                metadata_ref,
                previous_metadata_ref,
            } => {
                let (n, o) = (metadata_ref.as_str(), previous_metadata_ref.as_str());
                if !added_side.contains(n)
                    || !seen_added.insert(n)
                    || !removed_side.contains(o)
                    || !seen_removed.insert(o)
                {
                    return false;
                }
            }
        }
    }
    seen_added == added_side && seen_removed == removed_side
}

/// I-8 (membership part): every `from` is a member of the previous snapshot,
/// every `to` a member of this one, and no ref is used twice on a side.
pub fn links_consistent(
    members: &BTreeSet<String>,
    previous: &BTreeSet<String>,
    links: &[Link],
) -> bool {
    let mut froms: BTreeSet<&str> = BTreeSet::new();
    let mut tos: BTreeSet<&str> = BTreeSet::new();
    links.iter().all(|l| {
        previous.contains(l.from_metadata_ref.as_str())
            && members.contains(l.to_metadata_ref.as_str())
            && froms.insert(l.from_metadata_ref.as_str())
            && tos.insert(l.to_metadata_ref.as_str())
    })
}

// ---- stored rows ----------------------------------------------------------------

#[derive(Clone, Debug)]
struct SnapRow {
    inventory_id: String,
    epoch_id: String,
    upstream_id: String,
    credential_scope_id: String,
    protocol_version: String,
    observation_source: String,
    canon: String,
    key_id: String,
    observed_at_s: i64,
    received_at: i64,
    kind: String,
    previous_inventory_id: Option<String>,
    reason: Option<String>,
    links_present: bool,
    pending: Option<Vec<u8>>,
}

const SNAP_COLS: &str = "inventory_id, epoch_id, upstream_id, credential_scope_id, \
    protocol_version, observation_source, canon, key_id, observed_at_s, received_at, kind, \
    previous_inventory_id, reason, links_present, pending";

fn snap_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SnapRow> {
    Ok(SnapRow {
        inventory_id: r.get(0)?,
        epoch_id: r.get(1)?,
        upstream_id: r.get(2)?,
        credential_scope_id: r.get(3)?,
        protocol_version: r.get(4)?,
        observation_source: r.get(5)?,
        canon: r.get(6)?,
        key_id: r.get(7)?,
        observed_at_s: r.get(8)?,
        received_at: r.get(9)?,
        kind: r.get(10)?,
        previous_inventory_id: r.get(11)?,
        reason: r.get(12)?,
        links_present: r.get::<_, i64>(13)? != 0,
        pending: r.get(14)?,
    })
}

fn load_snapshot(
    conn: &Connection,
    proxy_id: &str,
    inventory_id: &str,
) -> Result<Option<SnapRow>, LedgerError> {
    Ok(conn
        .query_row(
            &format!(
                "SELECT {SNAP_COLS} FROM inv_snapshots WHERE proxy_id = ?1 AND inventory_id = ?2"
            ),
            params![proxy_id, inventory_id],
            snap_from_row,
        )
        .optional()?)
}

fn load_members(
    conn: &Connection,
    proxy_id: &str,
    inventory_id: &str,
) -> Result<BTreeSet<String>, LedgerError> {
    let mut st = conn.prepare_cached(
        "SELECT metadata_ref FROM inv_members WHERE proxy_id = ?1 AND inventory_id = ?2",
    )?;
    let rows = st.query_map(params![proxy_id, inventory_id], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn same_scope(a: &SnapRow, b: &SnapRow) -> bool {
    a.upstream_id == b.upstream_id
        && a.credential_scope_id == b.credential_scope_id
        && a.protocol_version == b.protocol_version
        && a.observation_source == b.observation_source
}

/// The comparison checks I-3, I-6, I-7 and I-8 (membership part) for `s`
/// against its previous snapshot `p`. The single function used both at ingest
/// (previous known) and when the previous arrives later (I-5).
fn evaluate(
    s: &SnapRow,
    cmp: &Comparison,
    members: &BTreeSet<String>,
    p: &SnapRow,
    previous_members: &BTreeSet<String>,
) -> bool {
    if !same_scope(s, p) {
        return false; // I-6
    }
    let same_domain = s.canon == p.canon && s.key_id == p.key_id;
    match cmp {
        Comparison::InitialBaseline {} => true,
        Comparison::Compared { changes, .. } => {
            same_domain && changes_consistent(members, previous_members, changes)
        }
        Comparison::Rebaseline { links, .. } => {
            !same_domain && links_consistent(members, previous_members, links)
        }
    }
}

fn snap_of_report(r: &InventoryReport, received_at: i64) -> Option<SnapRow> {
    let (kind, previous, reason, links_present) = match r.comparison.as_ref()? {
        Comparison::InitialBaseline {} => ("initial_baseline", None, None, false),
        Comparison::Compared {
            previous_inventory_id,
            ..
        } => (
            "compared",
            Some(previous_inventory_id.as_str().to_string()),
            None,
            false,
        ),
        Comparison::Rebaseline {
            previous_inventory_id,
            reason,
            links,
        } => (
            "rebaseline",
            Some(previous_inventory_id.as_str().to_string()),
            Some(enum_text(reason)),
            !links.is_empty(),
        ),
    };
    Some(SnapRow {
        inventory_id: r.inventory_id.as_ref()?.as_str().to_string(),
        epoch_id: r.epoch_id.as_str().to_string(),
        upstream_id: r.scope.upstream_id.as_str().to_string(),
        credential_scope_id: r.scope.credential_scope_id.as_str().to_string(),
        protocol_version: enum_text(&r.scope.protocol_version),
        observation_source: enum_text(&r.scope.observation_source),
        canon: enum_text(&r.canon),
        key_id: r.key_id.as_str().to_string(),
        observed_at_s: timestamp_secs(r.observed_at.as_str()).unwrap_or(0),
        received_at,
        kind: kind.to_string(),
        previous_inventory_id: previous,
        reason,
        links_present,
        pending: None,
    })
}

/// SQL: rows of the chain `(scope key, canon, key_id)` of `alias`.
fn chain_pred(a: &str, b: &str) -> String {
    format!(
        "{b}.proxy_id = {a}.proxy_id AND {b}.upstream_id = {a}.upstream_id \
         AND {b}.credential_scope_id = {a}.credential_scope_id \
         AND {b}.protocol_version = {a}.protocol_version \
         AND {b}.observation_source = {a}.observation_source \
         AND {b}.canon = {a}.canon AND {b}.key_id = {a}.key_id"
    )
}

/// SQL: `b` is strictly earlier than `a` in `(observed_at_s, inventory_id)`.
fn earlier_pred(a: &str, b: &str) -> String {
    // Row-value comparison: one range scan on the chain index
    // `(.., canon, key_id, observed_at_s, inventory_id)`.
    format!("({b}.observed_at_s, {b}.inventory_id) < ({a}.observed_at_s, {a}.inventory_id)")
}

fn change_name(c: &Change) -> (&'static str, &str, Option<&str>) {
    match c {
        Change::Added { metadata_ref } => ("added", metadata_ref.as_str(), None),
        Change::Removed { metadata_ref } => ("removed", metadata_ref.as_str(), None),
        Change::Changed {
            metadata_ref,
            previous_metadata_ref,
        } => (
            "changed",
            metadata_ref.as_str(),
            Some(previous_metadata_ref.as_str()),
        ),
    }
}

// ---- projection writers ---------------------------------------------------------

fn insert_drift(
    conn: &Connection,
    proxy_id: &str,
    s: &SnapRow,
    previous_id: &str,
    changes: &[Change],
) -> Result<(), LedgerError> {
    let mut rows: Vec<(&'static str, &str, Option<&str>)> =
        changes.iter().map(change_name).collect();
    rows.sort_unstable();
    let mut st = conn.prepare_cached(
        "INSERT OR IGNORE INTO inv_drift (drift_id, proxy_id, inventory_id, previous_inventory_id,
             upstream_id, credential_scope_id, protocol_version, observation_source, change,
             metadata_ref, previous_metadata_ref, detected_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )?;
    for (change, mref, prev) in rows {
        let id = det_id(&[
            "drift",
            proxy_id,
            &s.inventory_id,
            change,
            mref,
            prev.unwrap_or(""),
        ]);
        st.execute(params![
            id,
            proxy_id,
            s.inventory_id,
            previous_id,
            s.upstream_id,
            s.credential_scope_id,
            s.protocol_version,
            s.observation_source,
            change,
            mref,
            prev,
            s.received_at,
        ])?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn upsert_marker(
    conn: &Connection,
    proxy_id: &str,
    s: &SnapRow,
    previous_inventory_id: Option<&str>,
    from_key_id: &str,
    from_canon: &str,
    cause: &str,
    links_present: bool,
) -> Result<(), LedgerError> {
    conn.execute(
        "INSERT INTO inv_markers (marker_id, proxy_id, inventory_id, previous_inventory_id,
             upstream_id, credential_scope_id, protocol_version, observation_source,
             from_key_id, to_key_id, from_canon, to_canon, cause, links_present, detected_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
         ON CONFLICT (proxy_id, inventory_id) DO UPDATE SET
             previous_inventory_id = excluded.previous_inventory_id,
             from_key_id = excluded.from_key_id, to_key_id = excluded.to_key_id,
             from_canon = excluded.from_canon, to_canon = excluded.to_canon,
             cause = excluded.cause, links_present = excluded.links_present",
        params![
            det_id(&["marker", proxy_id, &s.inventory_id]),
            proxy_id,
            s.inventory_id,
            previous_inventory_id,
            s.upstream_id,
            s.credential_scope_id,
            s.protocol_version,
            s.observation_source,
            from_key_id,
            s.key_id,
            from_canon,
            s.canon,
            cause,
            i64::from(links_present),
            s.received_at,
        ],
    )?;
    Ok(())
}

/// R5 rule 2/3 for an `initial_baseline` snapshot: compare it with the latest
/// earlier snapshot of the same scope key (any canon or key). No earlier
/// snapshot: it is the initial baseline of the scope key and has no marker.
fn recompute_baseline_marker(
    conn: &Connection,
    proxy_id: &str,
    inventory_id: &str,
) -> Result<(), LedgerError> {
    let Some(s) = load_snapshot(conn, proxy_id, inventory_id)? else {
        return Ok(());
    };
    if s.kind != "initial_baseline" {
        return Ok(());
    }
    let earlier: Option<(String, String, String, String)> = conn
        .query_row(
            "SELECT inventory_id, canon, key_id, epoch_id FROM inv_snapshots
             WHERE proxy_id = ?1 AND upstream_id = ?2 AND credential_scope_id = ?3
               AND protocol_version = ?4 AND observation_source = ?5
               AND (observed_at_s, inventory_id) < (?6, ?7)
             ORDER BY observed_at_s DESC, inventory_id DESC LIMIT 1",
            params![
                proxy_id,
                s.upstream_id,
                s.credential_scope_id,
                s.protocol_version,
                s.observation_source,
                s.observed_at_s,
                s.inventory_id
            ],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((q_id, q_canon, q_key, q_epoch)) = earlier else {
        conn.execute(
            "DELETE FROM inv_markers WHERE proxy_id = ?1 AND inventory_id = ?2",
            params![proxy_id, inventory_id],
        )?;
        return Ok(());
    };
    // OPEN (registry.md R5 rule 2): "epoch_change_detected when a
    // producer_epoch_change gap exists between the two". The gap table is built
    // from event arrival, so it cannot give an order-independent answer; the
    // two reports' own epoch ids are used instead.
    let cause = if q_canon == s.canon && q_key == s.key_id {
        "baseline_restated"
    } else if q_epoch != s.epoch_id {
        "epoch_change_detected"
    } else {
        "key_change_undeclared"
    };
    upsert_marker(
        conn,
        proxy_id,
        &s,
        Some(&q_id),
        &q_key,
        &q_canon,
        cause,
        false,
    )
}

/// Marker of a resolved declared rebaseline (R5 rule 1).
fn apply_rebaseline(
    conn: &Connection,
    proxy_id: &str,
    s: &SnapRow,
    p: &SnapRow,
    links: &[Link],
) -> Result<(), LedgerError> {
    {
        let mut st = conn.prepare_cached(
            "INSERT OR IGNORE INTO inv_links (proxy_id, inventory_id, from_metadata_ref,
                 to_metadata_ref, definition_comparison) VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for l in links {
            st.execute(params![
                proxy_id,
                s.inventory_id,
                l.from_metadata_ref.as_str(),
                l.to_metadata_ref.as_str(),
                definition_text(l.definition_comparison),
            ])?;
        }
    }
    let cause = match s.reason.as_deref() {
        Some("canon_version_change") => "declared_canon_change",
        _ => "declared_key_rotation",
    };
    upsert_marker(
        conn,
        proxy_id,
        s,
        Some(&p.inventory_id),
        &p.key_id,
        &p.canon,
        cause,
        s.links_present,
    )
}

fn definition_text(d: DefinitionComparison) -> &'static str {
    match d {
        DefinitionComparison::Identical => "identical",
        DefinitionComparison::Different => "different",
        DefinitionComparison::NotComparable => "not_comparable",
    }
}

fn reason_text(r: RebaselineReason) -> &'static str {
    match r {
        RebaselineReason::KeyRotation => "key_rotation",
        RebaselineReason::CanonVersionChange => "canon_version_change",
    }
}

/// Insert one inventory gap (never closes). `Ok(false)` when the id exists.
#[allow(clippy::too_many_arguments)]
fn insert_inventory_gap(
    conn: &Connection,
    proxy_id: &str,
    kind: GapKind,
    gap_id: &str,
    detected_at: i64,
    epoch_id: &str,
    details: &serde_json::Value,
    drop_when_full: bool,
) -> Result<bool, LedgerError> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM gaps WHERE gap_id = ?1)",
        params![gap_id],
        |r| r.get(0),
    )?;
    if exists {
        return Ok(false);
    }
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM gaps WHERE proxy_id = ?1 AND open = 1
           AND kind IN ('inventory_incomplete', 'comparison_inconsistent')",
        params![proxy_id],
        |r| r.get(0),
    )?;
    if n >= MAX_GAPS_PER_PROXY {
        if drop_when_full {
            // A legitimate snapshot is never refused for the gap budget: the
            // record is dropped and counted (shown in `audit_gaps_dropped`).
            conn.execute(
                "INSERT INTO inv_gap_overflow (proxy_id, dropped) VALUES (?1, 1)
                 ON CONFLICT (proxy_id) DO UPDATE SET dropped = dropped + 1",
                params![proxy_id],
            )?;
            return Ok(false);
        }
        return Err(LedgerError::StorageLimit);
    }
    conn.execute(
        "INSERT INTO gaps (gap_id, proxy_id, kind, detected_at, epoch_id, open, tail, details)
         VALUES (?1, ?2, ?3, ?4, ?5, 1, 0, ?6)",
        params![
            gap_id,
            proxy_id,
            kind.as_str(),
            detected_at,
            epoch_id,
            details.to_string()
        ],
    )?;
    Ok(true)
}

/// The previous snapshot of `waiting` has arrived (or `waiting` was stored with
/// its previous known): compute the deferred state.
fn resolve_one(
    conn: &Connection,
    proxy_id: &str,
    waiting: &SnapRow,
    p: &SnapRow,
    pmembers: &BTreeSet<String>,
) -> Result<(), LedgerError> {
    let cmp: Option<Comparison> = waiting
        .pending
        .as_deref()
        .and_then(|b| serde_json::from_slice(b).ok());
    let members = load_members(conn, proxy_id, &waiting.inventory_id)?;
    let ok = cmp
        .as_ref()
        .is_some_and(|c| evaluate(waiting, c, &members, p, pmembers));
    if !ok {
        conn.execute(
            "UPDATE inv_snapshots SET state = 'inconsistent', pending = NULL
             WHERE proxy_id = ?1 AND inventory_id = ?2",
            params![proxy_id, waiting.inventory_id],
        )?;
        insert_inventory_gap(
            conn,
            proxy_id,
            GapKind::ComparisonInconsistent,
            &det_id(&[
                "gap",
                proxy_id,
                &waiting.inventory_id,
                "comparison_inconsistent",
            ]),
            // The waiting report's own receipt time, so the record does not
            // depend on when its previous snapshot happened to arrive.
            waiting.received_at,
            &waiting.epoch_id,
            &serde_json::json!({ "inventory_id": waiting.inventory_id }),
            true,
        )?;
        return Ok(());
    }
    let state = match cmp.as_ref() {
        Some(Comparison::Compared { changes, .. }) => {
            insert_drift(conn, proxy_id, waiting, &p.inventory_id, changes)?;
            "compared"
        }
        Some(Comparison::Rebaseline { links, .. }) => {
            apply_rebaseline(conn, proxy_id, waiting, p, links)?;
            "rebaseline"
        }
        _ => "baseline",
    };
    conn.execute(
        "UPDATE inv_snapshots SET state = ?3, pending = NULL
         WHERE proxy_id = ?1 AND inventory_id = ?2",
        params![proxy_id, waiting.inventory_id, state],
    )?;
    Ok(())
}

// ---- write path -----------------------------------------------------------------

impl Ledger {
    /// Is `report_id` stored with an equal canonical report? Read only; the
    /// handler skips the registry lookups for these (a retransmission after the
    /// route scopes moved on must stay a duplicate).
    pub fn inventory_report_equal(
        &self,
        proxy_id: &str,
        report_id: &str,
        digest: &[u8; 32],
    ) -> Result<bool, LedgerError> {
        let conn = self.conn.lock();
        let d: Option<Vec<u8>> = conn
            .query_row(
                "SELECT digest FROM inv_reports WHERE proxy_id = ?1 AND report_id = ?2",
                params![proxy_id, report_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(d.is_some_and(|d| d == digest))
    }

    /// Store one validated report atomically, derive the projection in the same
    /// transaction and answer. `refs` is the registry view the handler took;
    /// `now` is the server clock (unix seconds), the report's `received_at`.
    ///
    /// Answer order, first match wins: duplicate; 422 (other-proxy ref, or a
    /// known previous snapshot failing I-3/I-6/I-7/I-8); 409 (the report id or
    /// the snapshot id is taken by another report); 424 (refs nobody
    /// registered); store.
    pub fn ingest_inventory(
        &self,
        proxy_id: &str,
        report: &InventoryReport,
        digest: &[u8; 32],
        refs: &RefCheck,
        now: i64,
    ) -> Result<InventoryOutcome, LedgerError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let report_id = report.report_id.as_str();
        let stored: Option<Vec<u8>> = tx
            .query_row(
                "SELECT digest FROM inv_reports WHERE proxy_id = ?1 AND report_id = ?2",
                params![proxy_id, report_id],
                |r| r.get(0),
            )
            .optional()?;
        let mut conflict = false;
        if let Some(d) = stored {
            if d == digest {
                return Ok(InventoryOutcome::Duplicate);
            }
            conflict = true;
        }

        let complete = report.completeness == Completeness::Complete;
        let snap = if complete {
            // Defensive: parsing already requires a comparison on a complete
            // report; never treat one without it as an incomplete report.
            match snap_of_report(report, now) {
                Some(s) => Some(s),
                None => return Ok(InventoryOutcome::Invalid),
            }
        } else {
            None
        };
        let members: BTreeSet<String> = report
            .members
            .iter()
            .flatten()
            .map(|m| m.as_str().to_string())
            .collect();
        let mut invalid = refs.other_proxy;
        let mut previous: Option<SnapRow> = None;
        if let Some(s) = snap.as_ref() {
            let taken: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM inv_snapshots WHERE proxy_id = ?1 AND inventory_id = ?2)",
                params![proxy_id, s.inventory_id],
                |r| r.get(0),
            )?;
            conflict |= taken;
            if let Some(pid) = s.previous_inventory_id.as_deref() {
                if pid == s.inventory_id {
                    invalid = true;
                } else {
                    previous = load_snapshot(&tx, proxy_id, pid)?;
                }
            }
            if let (Some(p), Some(cmp)) = (previous.as_ref(), report.comparison.as_ref()) {
                let pm = load_members(&tx, proxy_id, &p.inventory_id)?;
                if !evaluate(s, cmp, &members, p, &pm) {
                    invalid = true;
                }
            }
        }
        if invalid {
            return Ok(InventoryOutcome::Invalid);
        }
        if conflict {
            return Ok(InventoryOutcome::Conflict);
        }
        if !refs.unregistered.is_empty() {
            return Ok(InventoryOutcome::Pending(
                refs.unregistered
                    .iter()
                    .take(MAX_PENDING_REFS)
                    .cloned()
                    .collect(),
            ));
        }

        if snap
            .as_ref()
            .is_some_and(|s| s.previous_inventory_id.is_some())
            && previous.is_none()
        {
            // This report would wait for a previous snapshot. The wait list is
            // bounded (503, not 422: the report is valid, the producer should
            // retry once earlier snapshots have been delivered or have aged out).
            let waiting_now: i64 = tx.query_row(
                "SELECT COUNT(*) FROM inv_snapshots WHERE proxy_id = ?1 AND state = 'pending_previous'",
                params![proxy_id],
                |r| r.get(0),
            )?;
            let cap = self.inv_caps.pending_per_proxy.load(Ordering::Relaxed);
            if u64::try_from(waiting_now).is_ok_and(|n| n >= cap) {
                return Err(LedgerError::StorageLimit);
            }
        }
        tx.execute(
            "INSERT INTO inv_reports (proxy_id, report_id, digest, received_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![proxy_id, report_id, digest.as_slice(), now],
        )?;

        let Some(s) = snap else {
            // Incomplete: one gap, nothing else changes (R7).
            let reason = report
                .incomplete_reason
                .as_ref()
                .map(enum_text)
                .unwrap_or_default();
            insert_inventory_gap(
                &tx,
                proxy_id,
                GapKind::InventoryIncomplete,
                &det_id(&["gap", proxy_id, report_id, "inventory_incomplete"]),
                now,
                report.epoch_id.as_str(),
                &serde_json::json!({
                    "upstream_id": report.scope.upstream_id.as_str(),
                    "credential_scope_id": report.scope.credential_scope_id.as_str(),
                    "incomplete_reason": reason,
                    "observed_at": report.observed_at.as_str(),
                }),
                false,
            )?;
            if self.file_over_cap(&tx)? {
                return Err(LedgerError::StorageLimit);
            }
            tx.commit()?;
            return Ok(InventoryOutcome::Accepted);
        };

        // Complete: the snapshot.
        let (state, pending) = match (&report.comparison, previous.is_some()) {
            (Some(Comparison::InitialBaseline {}), _) | (None, _) => ("baseline", None),
            (Some(Comparison::Compared { .. }), true) => ("compared", None),
            (Some(Comparison::Rebaseline { .. }), true) => ("rebaseline", None),
            (Some(c), false) => (
                "pending_previous",
                Some(serde_json::to_vec(c).unwrap_or_default()),
            ),
        };
        // Chain bookkeeping for retention: who is superseded by whom.
        let latest: Option<(String, i64)> = tx
            .query_row(
                "SELECT inventory_id, observed_at_s FROM inv_snapshots
                 WHERE proxy_id = ?1 AND upstream_id = ?2 AND credential_scope_id = ?3
                   AND protocol_version = ?4 AND observation_source = ?5
                   AND canon = ?6 AND key_id = ?7
                 ORDER BY observed_at_s DESC, inventory_id DESC LIMIT 1",
                params![
                    proxy_id,
                    s.upstream_id,
                    s.credential_scope_id,
                    s.protocol_version,
                    s.observation_source,
                    s.canon,
                    s.key_id
                ],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let mut superseded_at: Option<i64> = None;
        if let Some((lid, ls)) = latest {
            if (ls, lid.as_str()) > (s.observed_at_s, s.inventory_id.as_str()) {
                superseded_at = Some(now);
            } else {
                tx.execute(
                    "UPDATE inv_snapshots SET superseded_at = COALESCE(superseded_at, ?3)
                     WHERE proxy_id = ?1 AND inventory_id = ?2",
                    params![proxy_id, lid, now],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO inv_snapshots (proxy_id, inventory_id, report_id, epoch_id, upstream_id,
                 credential_scope_id, protocol_version, observation_source, canon, key_id,
                 observed_at, observed_at_s, received_at, member_count, kind,
                 previous_inventory_id, reason, links_present, state, superseded_at, pending)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                     ?18, ?19, ?20, ?21)",
            params![
                proxy_id,
                s.inventory_id,
                report_id,
                s.epoch_id,
                s.upstream_id,
                s.credential_scope_id,
                s.protocol_version,
                s.observation_source,
                s.canon,
                s.key_id,
                report.observed_at.as_str(),
                s.observed_at_s,
                now,
                members.len() as i64,
                s.kind,
                s.previous_inventory_id,
                s.reason,
                i64::from(s.links_present),
                state,
                superseded_at,
                pending,
            ],
        )?;
        {
            let mut st = tx.prepare_cached(
                "INSERT INTO inv_members (proxy_id, inventory_id, metadata_ref) VALUES (?1, ?2, ?3)",
            )?;
            for m in &members {
                st.execute(params![proxy_id, s.inventory_id, m])?;
            }
        }

        // Derive what this snapshot decides now (previous known) ...
        if let (Some(p), Some(cmp)) = (previous.as_ref(), report.comparison.as_ref()) {
            match cmp {
                Comparison::Compared { changes, .. } => {
                    insert_drift(&tx, proxy_id, &s, &p.inventory_id, changes)?;
                }
                Comparison::Rebaseline { links, reason, .. } => {
                    debug_assert_eq!(s.reason.as_deref(), Some(reason_text(*reason)));
                    apply_rebaseline(&tx, proxy_id, &s, p, links)?;
                }
                Comparison::InitialBaseline {} => {}
            }
        }
        // ... and what it unblocks (snapshots that named it as their previous).
        let waiting: Vec<SnapRow> = {
            let mut st = tx.prepare(&format!(
                "SELECT {SNAP_COLS} FROM inv_snapshots
                 WHERE proxy_id = ?1 AND previous_inventory_id = ?2 AND state = 'pending_previous'
                 ORDER BY snap_seq"
            ))?;
            let rows = st.query_map(params![proxy_id, s.inventory_id], snap_from_row)?;
            rows.collect::<Result<_, _>>()?
        };
        for w in &waiting {
            resolve_one(&tx, proxy_id, w, &s, &members)?;
        }
        // Markers that depend on chain order: this snapshot and its successor.
        recompute_baseline_marker(&tx, proxy_id, &s.inventory_id)?;
        let successor: Option<String> = tx
            .query_row(
                "SELECT inventory_id FROM inv_snapshots
                 WHERE proxy_id = ?1 AND upstream_id = ?2 AND credential_scope_id = ?3
                   AND protocol_version = ?4 AND observation_source = ?5
                   AND (observed_at_s, inventory_id) > (?6, ?7)
                 ORDER BY observed_at_s ASC, inventory_id ASC LIMIT 1",
                params![
                    proxy_id,
                    s.upstream_id,
                    s.credential_scope_id,
                    s.protocol_version,
                    s.observation_source,
                    s.observed_at_s,
                    s.inventory_id
                ],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(next) = successor {
            recompute_baseline_marker(&tx, proxy_id, &next)?;
        }

        if self.inventory_over_caps(&tx, proxy_id)? {
            return Err(LedgerError::StorageLimit);
        }
        tx.commit()?;
        Ok(InventoryOutcome::Accepted)
    }

    fn file_over_cap(&self, tx: &Transaction<'_>) -> Result<bool, LedgerError> {
        let pages: i64 = tx.pragma_query_value(None, "page_count", |r| r.get(0))?;
        let free: i64 = tx.pragma_query_value(None, "freelist_count", |r| r.get(0))?;
        let page_size: i64 = tx.pragma_query_value(None, "page_size", |r| r.get(0))?;
        let live = (pages - free).saturating_mul(page_size);
        Ok(u64::try_from(live).is_ok_and(|v| v > self.opts.caps.file_bytes))
    }

    fn inventory_over_caps(
        &self,
        tx: &Transaction<'_>,
        proxy_id: &str,
    ) -> Result<bool, LedgerError> {
        let (snaps, members): (i64, i64) = tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(member_count), 0) FROM inv_snapshots WHERE proxy_id = ?1",
            params![proxy_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let over = |v: i64, cap: u64| u64::try_from(v).is_ok_and(|v| v > cap);
        Ok(over(
            snaps,
            self.inv_caps.snapshots_per_proxy.load(Ordering::Relaxed),
        ) || over(
            members,
            self.inv_caps.member_rows_per_proxy.load(Ordering::Relaxed),
        ) || self.file_over_cap(tx)?)
    }

    /// Inventory gap records dropped because the gap budget was full.
    pub fn inventory_gap_overflow(&self, proxy_id: &str) -> Result<i64, LedgerError> {
        let conn = self.read.acquire();
        Ok(conn
            .query_row(
                "SELECT dropped FROM inv_gap_overflow WHERE proxy_id = ?1",
                params![proxy_id],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    /// Test hook: lower the pending-snapshot bound.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_pending_cap_for_test(&self, n: u64) {
        self.inv_caps.pending_per_proxy.store(n, Ordering::Relaxed);
    }

    /// Test hook: fill the inventory gap budget (`n` filler gaps for `proxy_id`).
    #[cfg(any(test, feature = "test-support"))]
    pub fn fill_inventory_gaps_for_test(&self, proxy_id: &str, n: i64) -> Result<(), LedgerError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        for i in 0..n {
            tx.execute(
                "INSERT INTO gaps (gap_id, proxy_id, kind, detected_at, epoch_id, open, tail, details)
                 VALUES (?1, ?2, 'inventory_incomplete', 1, 'e', 1, 0, '{}')",
                params![format!("filler-{proxy_id}-{i}"), proxy_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Test hook: lower the per-proxy inventory bounds.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_inventory_caps_for_test(&self, snapshots: u64, member_rows: u64) {
        self.inv_caps
            .snapshots_per_proxy
            .store(snapshots, Ordering::Relaxed);
        self.inv_caps
            .member_rows_per_proxy
            .store(member_rows, Ordering::Relaxed);
    }
}

// ---- retention ------------------------------------------------------------------

/// Retention of one proxy's inventory rows (called from the ledger sweep, same
/// transaction). Registry L1: the latest snapshot and the first baseline of a
/// chain live as long as the chain; a superseded non-baseline snapshot lives E
/// after it was superseded; drift records and markers live E from detection;
/// report ids (the idempotency memory) live `max(E, T)`.
pub(super) fn sweep_proxy(
    conn: &Connection,
    proxy_id: &str,
    now: i64,
    e: i64,
    t: i64,
    s: &mut SweepStats,
) -> Result<(), LedgerError> {
    let cutoff = now.saturating_sub(e);
    s.inventory_reports += conn.execute(
        "DELETE FROM inv_reports WHERE proxy_id = ?1 AND received_at < ?2",
        params![proxy_id, now.saturating_sub(e.max(t))],
    )?;
    s.inventory_drift += conn.execute(
        "DELETE FROM inv_drift WHERE proxy_id = ?1 AND detected_at < ?2",
        params![proxy_id, cutoff],
    )?;
    s.inventory_markers += conn.execute(
        "DELETE FROM inv_markers WHERE proxy_id = ?1 AND detected_at < ?2",
        params![proxy_id, cutoff],
    )?;
    let doomed = format!(
        "d.proxy_id = ?1 AND d.superseded_at IS NOT NULL AND d.superseded_at < ?2
         AND EXISTS (SELECT 1 FROM inv_snapshots f WHERE {} AND {})",
        chain_pred("d", "f"),
        earlier_pred("d", "f")
    );
    // A snapshot still waiting for its previous one ages out E after receipt
    // (its previous was swept, or never arrives); the report id stays
    // remembered for max(E, T), so a replay in that window is a duplicate and
    // never makes a new waiting row.
    let doomed = format!(
        "({doomed}) OR (d.proxy_id = ?1 AND d.state = 'pending_previous' AND d.received_at < ?2)"
    );
    for table in ["inv_members", "inv_links"] {
        conn.execute(
            &format!(
                "DELETE FROM {table} WHERE proxy_id = ?1 AND inventory_id IN
                 (SELECT d.inventory_id FROM inv_snapshots d WHERE {doomed})"
            ),
            params![proxy_id, cutoff],
        )?;
    }
    s.inventory_snapshots += conn.execute(
        &format!("DELETE FROM inv_snapshots WHERE snap_seq IN (SELECT d.snap_seq FROM inv_snapshots d WHERE {doomed})"),
        params![proxy_id, cutoff],
    )?;
    conn.execute(
        "DELETE FROM inv_gap_overflow WHERE proxy_id = ?1 AND NOT EXISTS
           (SELECT 1 FROM gaps WHERE proxy_id = ?1
              AND kind IN ('inventory_incomplete', 'comparison_inconsistent'))",
        params![proxy_id],
    )?;
    Ok(())
}

// ---- read path (R7b) ------------------------------------------------------------

/// Filters of the three read views. `change` applies to drift only.
#[derive(Clone, Debug, Default)]
pub struct InvFilter {
    pub upstream_id: Option<String>,
    pub credential_scope_id: Option<String>,
    pub change: Option<String>,
    /// `received_at` / `detected_at` bounds, unix seconds, `from` inclusive,
    /// `to` exclusive.
    pub from: Option<i64>,
    pub to: Option<i64>,
}

/// A page and the commit counter of its last row when more rows follow.
#[derive(Debug)]
pub struct KeyedPage<T> {
    pub items: Vec<T>,
    pub next_key: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SnapshotView {
    #[serde(skip)]
    pub seq: i64,
    pub inventory_id: String,
    pub proxy_id: String,
    pub upstream_id: String,
    pub credential_scope_id: String,
    pub protocol_version: String,
    pub observation_source: String,
    pub canon: String,
    pub key_id: String,
    pub member_count: i64,
    pub observed_at: String,
    pub received_at: String,
    pub is_latest: bool,
    pub is_first_baseline: bool,
    pub comparison_state: String,
    pub awaiting_inventory_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftView {
    #[serde(skip)]
    pub seq: i64,
    pub drift_id: String,
    pub proxy_id: String,
    pub inventory_id: String,
    pub previous_inventory_id: String,
    pub upstream_id: String,
    pub credential_scope_id: String,
    pub protocol_version: String,
    pub observation_source: String,
    pub change: String,
    pub metadata_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_metadata_ref: Option<String>,
    pub detected_at: String,
}

#[derive(Debug, Serialize)]
pub struct MarkerView {
    #[serde(skip)]
    pub seq: i64,
    pub marker_id: String,
    pub proxy_id: String,
    pub upstream_id: String,
    pub credential_scope_id: String,
    pub protocol_version: String,
    pub observation_source: String,
    pub inventory_id: String,
    pub previous_inventory_id: Option<String>,
    pub from_key_id: String,
    pub to_key_id: String,
    pub from_canon: String,
    pub to_canon: String,
    pub cause: String,
    pub links_present: bool,
    pub drift_computed: bool,
    pub detected_at: String,
}

fn rfc(secs: i64) -> String {
    super::query::rfc3339(secs)
}

/// Common WHERE tail of the three views. `alias` is the table alias, `time`
/// the column the `from`/`to` bounds apply to.
fn view_where(
    sql: &mut String,
    args: &mut Vec<rusqlite::types::Value>,
    alias: &str,
    time: &str,
    seq: &str,
    f: &InvFilter,
    after: Option<i64>,
) {
    use rusqlite::types::Value as V;
    if let Some(v) = &f.upstream_id {
        sql.push_str(&format!(" AND {alias}.upstream_id = ?"));
        args.push(V::Text(v.clone()));
    }
    if let Some(v) = &f.credential_scope_id {
        sql.push_str(&format!(" AND {alias}.credential_scope_id = ?"));
        args.push(V::Text(v.clone()));
    }
    if let Some(v) = f.from {
        sql.push_str(&format!(" AND {alias}.{time} >= ?"));
        args.push(V::Integer(v));
    }
    if let Some(v) = f.to {
        sql.push_str(&format!(" AND {alias}.{time} < ?"));
        args.push(V::Integer(v));
    }
    if let Some(k) = after {
        sql.push_str(&format!(" AND {alias}.{seq} < ?"));
        args.push(V::Integer(k));
    }
}

fn finish_page<T>(mut items: Vec<T>, limit: usize, seq: impl Fn(&T) -> i64) -> KeyedPage<T> {
    let next_key = if items.len() > limit {
        items.truncate(limit);
        items.last().map(seq)
    } else {
        None
    };
    KeyedPage { items, next_key }
}

impl Ledger {
    /// Snapshots of `proxy_id`, newest commit first (`snap_seq` descending).
    pub fn list_inventory_snapshots(
        &self,
        proxy_id: &str,
        f: &InvFilter,
        after: Option<i64>,
        limit: usize,
    ) -> Result<KeyedPage<SnapshotView>, LedgerError> {
        use rusqlite::types::Value as V;
        let mut sql = format!(
            "SELECT s.snap_seq, s.inventory_id, s.proxy_id, s.upstream_id, s.credential_scope_id,
                    s.protocol_version, s.observation_source, s.canon, s.key_id, s.member_count,
                    s.observed_at, s.received_at, s.state, s.previous_inventory_id,
                    NOT EXISTS (SELECT 1 FROM inv_snapshots n WHERE {} AND {}) AS is_latest,
                    NOT EXISTS (SELECT 1 FROM inv_snapshots e WHERE {} AND {}) AS is_first
             FROM inv_snapshots s WHERE s.proxy_id = ?",
            chain_pred("s", "n"),
            earlier_pred("n", "s"),
            chain_pred("s", "e"),
            earlier_pred("s", "e"),
        );
        let mut args = vec![V::Text(proxy_id.to_string())];
        view_where(
            &mut sql,
            &mut args,
            "s",
            "received_at",
            "snap_seq",
            f,
            after,
        );
        sql.push_str(" ORDER BY s.snap_seq DESC LIMIT ?");
        args.push(V::Integer(limit as i64 + 1));
        let conn = self.read.acquire();
        let mut st = conn.prepare(&sql)?;
        let rows = st.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            let state: String = r.get(12)?;
            let previous: Option<String> = r.get(13)?;
            Ok(SnapshotView {
                seq: r.get(0)?,
                inventory_id: r.get(1)?,
                proxy_id: r.get(2)?,
                upstream_id: r.get(3)?,
                credential_scope_id: r.get(4)?,
                protocol_version: r.get(5)?,
                observation_source: r.get(6)?,
                canon: r.get(7)?,
                key_id: r.get(8)?,
                member_count: r.get(9)?,
                observed_at: r.get(10)?,
                received_at: rfc(r.get(11)?),
                is_latest: r.get::<_, i64>(14)? != 0,
                is_first_baseline: r.get::<_, i64>(15)? != 0,
                awaiting_inventory_id: if state == "pending_previous" {
                    previous
                } else {
                    None
                },
                comparison_state: state,
            })
        })?;
        let items: Vec<SnapshotView> = rows.collect::<Result<_, _>>()?;
        Ok(finish_page(items, limit, |i| i.seq))
    }

    /// Drift records of `proxy_id`, newest commit first.
    pub fn list_inventory_drift(
        &self,
        proxy_id: &str,
        f: &InvFilter,
        after: Option<i64>,
        limit: usize,
    ) -> Result<KeyedPage<DriftView>, LedgerError> {
        use rusqlite::types::Value as V;
        let mut sql = String::from(
            "SELECT d.drift_seq, d.drift_id, d.proxy_id, d.inventory_id, d.previous_inventory_id,
                    d.upstream_id, d.credential_scope_id, d.protocol_version,
                    d.observation_source, d.change, d.metadata_ref, d.previous_metadata_ref,
                    d.detected_at
             FROM inv_drift d WHERE d.proxy_id = ?",
        );
        let mut args = vec![V::Text(proxy_id.to_string())];
        if let Some(c) = &f.change {
            sql.push_str(" AND d.change = ?");
            args.push(V::Text(c.clone()));
        }
        view_where(
            &mut sql,
            &mut args,
            "d",
            "detected_at",
            "drift_seq",
            f,
            after,
        );
        sql.push_str(" ORDER BY d.drift_seq DESC LIMIT ?");
        args.push(V::Integer(limit as i64 + 1));
        let conn = self.read.acquire();
        let mut st = conn.prepare(&sql)?;
        let rows = st.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok(DriftView {
                seq: r.get(0)?,
                drift_id: r.get(1)?,
                proxy_id: r.get(2)?,
                inventory_id: r.get(3)?,
                previous_inventory_id: r.get(4)?,
                upstream_id: r.get(5)?,
                credential_scope_id: r.get(6)?,
                protocol_version: r.get(7)?,
                observation_source: r.get(8)?,
                change: r.get(9)?,
                metadata_ref: r.get(10)?,
                previous_metadata_ref: r.get(11)?,
                detected_at: rfc(r.get(12)?),
            })
        })?;
        let items: Vec<DriftView> = rows.collect::<Result<_, _>>()?;
        Ok(finish_page(items, limit, |i| i.seq))
    }

    /// Re-baseline markers of `proxy_id`, newest commit first.
    pub fn list_inventory_markers(
        &self,
        proxy_id: &str,
        f: &InvFilter,
        after: Option<i64>,
        limit: usize,
    ) -> Result<KeyedPage<MarkerView>, LedgerError> {
        use rusqlite::types::Value as V;
        let mut sql = String::from(
            "SELECT m.marker_seq, m.marker_id, m.proxy_id, m.upstream_id, m.credential_scope_id,
                    m.protocol_version, m.observation_source, m.inventory_id,
                    m.previous_inventory_id, m.from_key_id, m.to_key_id, m.from_canon,
                    m.to_canon, m.cause, m.links_present, m.detected_at
             FROM inv_markers m WHERE m.proxy_id = ?",
        );
        let mut args = vec![V::Text(proxy_id.to_string())];
        view_where(
            &mut sql,
            &mut args,
            "m",
            "detected_at",
            "marker_seq",
            f,
            after,
        );
        sql.push_str(" ORDER BY m.marker_seq DESC LIMIT ?");
        args.push(V::Integer(limit as i64 + 1));
        let conn = self.read.acquire();
        let mut st = conn.prepare(&sql)?;
        let rows = st.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok(MarkerView {
                seq: r.get(0)?,
                marker_id: r.get(1)?,
                proxy_id: r.get(2)?,
                upstream_id: r.get(3)?,
                credential_scope_id: r.get(4)?,
                protocol_version: r.get(5)?,
                observation_source: r.get(6)?,
                inventory_id: r.get(7)?,
                previous_inventory_id: r.get(8)?,
                from_key_id: r.get(9)?,
                to_key_id: r.get(10)?,
                from_canon: r.get(11)?,
                to_canon: r.get(12)?,
                cause: r.get(13)?,
                links_present: r.get::<_, i64>(14)? != 0,
                drift_computed: false,
                detected_at: rfc(r.get(15)?),
            })
        })?;
        let items: Vec<MarkerView> = rows.collect::<Result<_, _>>()?;
        Ok(finish_page(items, limit, |i| i.seq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_proxy_api::MetadataRef;

    fn r(n: u32) -> MetadataRef {
        MetadataRef::new(format!("00000000-0000-8000-8000-{n:012}")).unwrap()
    }
    fn set(ns: &[u32]) -> BTreeSet<String> {
        ns.iter().map(|n| r(*n).as_str().to_string()).collect()
    }
    fn added(n: u32) -> Change {
        Change::Added { metadata_ref: r(n) }
    }
    fn removed(n: u32) -> Change {
        Change::Removed { metadata_ref: r(n) }
    }
    fn changed(n: u32, old: u32) -> Change {
        Change::Changed {
            metadata_ref: r(n),
            previous_metadata_ref: r(old),
        }
    }

    #[test]
    fn changes_must_equal_the_membership_difference() {
        let prev = set(&[1, 2, 3]);
        let cur = set(&[1, 4, 5]);
        // 2 -> 4 changed, 3 removed, 5 added
        assert!(changes_consistent(
            &cur,
            &prev,
            &[changed(4, 2), removed(3), added(5)]
        ));
        assert!(changes_consistent(
            &cur,
            &prev,
            &[added(5), removed(3), changed(4, 2)]
        ));
        // missing a change
        assert!(!changes_consistent(&cur, &prev, &[changed(4, 2), added(5)]));
        // extra change that is not part of the difference
        assert!(!changes_consistent(
            &cur,
            &prev,
            &[changed(4, 2), removed(3), added(5), added(1)]
        ));
        // wrong side
        assert!(!changes_consistent(
            &cur,
            &prev,
            &[added(3), removed(5), changed(4, 2)]
        ));
        // a ref used twice
        assert!(!changes_consistent(
            &cur,
            &prev,
            &[changed(4, 2), added(4), removed(3), added(5)]
        ));
        assert!(!changes_consistent(
            &cur,
            &prev,
            &[changed(4, 2), changed(5, 2), removed(3)]
        ));
        // identical snapshots: no changes
        assert!(changes_consistent(&prev, &prev, &[]));
        assert!(!changes_consistent(&prev, &prev, &[added(1)]));
    }

    fn link(a: u32, b: u32) -> Link {
        Link {
            from_metadata_ref: r(a),
            to_metadata_ref: r(b),
            definition_comparison: DefinitionComparison::Identical,
        }
    }

    #[test]
    fn links_must_pair_previous_members_with_current_members_once() {
        let prev = set(&[1, 2]);
        let cur = set(&[11, 12, 13]);
        assert!(links_consistent(&cur, &prev, &[]));
        assert!(links_consistent(&cur, &prev, &[link(1, 11), link(2, 12)]));
        assert!(
            !links_consistent(&cur, &prev, &[link(9, 11)]),
            "from not in previous"
        );
        assert!(
            !links_consistent(&cur, &prev, &[link(1, 99)]),
            "to not in current"
        );
        assert!(
            !links_consistent(&cur, &prev, &[link(1, 11), link(1, 12)]),
            "from twice"
        );
        assert!(
            !links_consistent(&cur, &prev, &[link(1, 11), link(2, 11)]),
            "to twice"
        );
    }

    #[test]
    fn deterministic_ids_are_stable_and_uuid_shaped() {
        let a = det_id(&["drift", "px", "x"]);
        assert_eq!(a, det_id(&["drift", "px", "x"]));
        assert_ne!(a, det_id(&["drift", "px", "y"]));
        assert_ne!(
            det_id(&["a", "bc"]),
            det_id(&["ab", "c"]),
            "parts are delimited"
        );
        assert!(sigil_proxy_api::Uuid::new(a.as_str()).is_ok());
    }
}
