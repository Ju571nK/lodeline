//! Registry upload and inventory clients (`contracts/registry.md` R2/R7, README
//! "Sync ordering" and "Registry 409 (M2b)").
//!
//! Order of work in [`RegistryClient::sync_once`]: pending ENTRIES go first
//! (`POST /v1/proxy-metadata`, at most 100 entries and 4 MiB per request); only
//! when none is pending are the queued inventory REPORTS sent, oldest first
//! (`POST /v1/proxy-inventory`), because the server answers 424 for a member ref
//! it has not registered.
//!
//! Answer rules, all fail closed:
//!
//! | endpoint | answer | effect |
//! |---|---|---|
//! | metadata | 200 | listed refs become `Acked` (immutable-field hash recorded) |
//! | metadata | 409 `registry_conflict` by item | those entries are quarantined unchanged, a gap is queued, the [`ConflictHandler`] rewrites dependent never-accepted starts (M2b); the rest is resent |
//! | metadata | 409 naming nothing | single entries are tried until the culprit is found, then it is quarantined |
//! | metadata | 422 | the named entries (or all) are counted as refused and from then on offered one at a time, after every other pending entry; backoff |
//! | metadata | 413 | halve the batch |
//! | inventory | 200 | the report is done |
//! | inventory | 424 | the named refs are uploaded again, the report is retried |
//! | inventory | 422, 409, 413 | the report cannot be accepted as it is: discarded and counted |
//! | both | 404, 429, 403, 5xx, no answer | backoff |
//!
//! A report whose members include a quarantined entry is discarded without
//! sending (the server could never register it).
//!
//! Nothing here logs a body, a definition, a name, a ref or an address.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use sigil_proxy_api::registry::{
    Canon, Comparison, InventoryReport, ObservationSource, RegistryEntry, RegistryProtocolVersion,
    UploadRequest,
};
use sigil_proxy_api::status::{ConflictDetector, RegistryConflictGap};
use sigil_proxy_api::{
    ErrorCode, Fingerprint, GapReport, Id, KeyId, MetadataRef, PositiveI64, SchemaVersion,
    Timestamp, Uuid, Validate,
};

use crate::ingest_client::STALL_ATTEMPTS;
use crate::jcs;
use crate::registry_key::ScopeKey;
use crate::registry_store::{
    EntryCheck, EntryRecord, EntryState, RegistryError, RegistryStore, StoredReport,
};
use crate::status_report::{GapQueue, PostFuture, RegistryProbe, RegistrySnapshot, StatusReply};

/// The `gap_id` of one registry-conflict chunk: SHA-256 over the ref, the
/// `key_id` and the sorted chunk event ids, as a version-8 UUID. A re-run after
/// a crash therefore produces the same gap, which the server dedupes by id.
pub fn gap_id_for(metadata_ref: &str, key_id: &str, sorted_event_ids: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"sigil-registry-conflict-gap-v1\0");
    for part in [metadata_ref, key_id] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    for id in sorted_event_ids {
        h.update(id.as_bytes());
        h.update([0]);
    }
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(b).hyphenated().to_string()
}

fn detector_str(d: ConflictDetector) -> &'static str {
    match d {
        ConflictDetector::Central409 => "central_409",
        ConflictDetector::LocalHashCheck => "local_hash_check",
    }
}

fn detector_from(s: &str) -> ConflictDetector {
    if s == "central_409" {
        ConflictDetector::Central409
    } else {
        ConflictDetector::LocalHashCheck
    }
}

/// Entries per request (registry.md R2).
pub const MAX_UPLOAD_ENTRIES: usize = 100;
/// Serialized bytes per upload request.
pub const MAX_UPLOAD_BYTES: usize = 4 * 1024 * 1024;
/// Largest answer read from the server.
pub const MAX_REGISTRY_RESPONSE_BYTES: usize = 64 * 1024;
/// Largest `event_ids` of one gap.
const GAP_EVENT_IDS: usize = 100;

/// How requests are sent. `None` means no answer (transport error, timeout, bad
/// TLS material).
pub trait RegistryTransport: Send + Sync {
    fn post_metadata(&self, body: Vec<u8>) -> PostFuture<'_>;
    fn post_inventory(&self, body: Vec<u8>) -> PostFuture<'_>;
}

/// The seam to the spool (T-14), implemented by T-13c.
pub trait ConflictHandler: Send {
    /// The entry `metadata_ref` (minted under `key_id`) is quarantined. Rewrite
    /// ONLY the `tool` field of each dependent start that was never centrally
    /// accepted to `{"status":"metadata_unavailable","reason":"registry_conflict"}`
    /// (M2b; the original bytes stay in quarantine) and return the `event_id`s
    /// of ALL events that depend on the entry, rewritten or not.
    fn registry_conflict(&mut self, metadata_ref: &str, key_id: &str) -> Vec<String>;
}

/// A handler for a proxy with no spool wired yet: no dependents.
pub struct NoDependents;

impl ConflictHandler for NoDependents {
    fn registry_conflict(&mut self, _: &str, _: &str) -> Vec<String> {
        Vec::new()
    }
}

/// Quarantines a conflicting entry, calls the spool seam and queues the central
/// integrity gap (`kind=registry_conflict`, ref, `key_id`, event ids, no field
/// values). Clone it freely; T-13c uses [`ConflictReporter::check_entries`]
/// before sending events (README N11 iii).
#[derive(Clone)]
pub struct ConflictReporter {
    store: RegistryStore,
    gaps: GapQueue,
    handler: Arc<Mutex<Box<dyn ConflictHandler>>>,
}

impl ConflictReporter {
    pub fn new(
        store: RegistryStore,
        gaps: GapQueue,
        handler: Box<dyn ConflictHandler>,
    ) -> ConflictReporter {
        ConflictReporter {
            store,
            gaps,
            handler: Arc::new(Mutex::new(handler)),
        }
    }

    /// The registry-conflict path for one entry. Returns the number of events
    /// that depend on it.
    ///
    /// Idempotent across a crash: quarantine sets a durable "gap pending" mark in
    /// the same statement; the mark is cleared only after the spool seam ran and
    /// the gap is queued. A repeated call (or [`ConflictReporter::resume`] after a
    /// restart) finishes whatever did not finish. At worst the gap is queued twice
    /// (with different `gap_id`s), never zero times.
    pub fn report_conflict(
        &self,
        metadata_ref: &str,
        detected_by: ConflictDetector,
    ) -> Result<usize, RegistryError> {
        let Some(rec) = self.store.entry(metadata_ref)? else {
            return Ok(0);
        };
        let changed = self
            .store
            .quarantine(metadata_ref, detector_str(detected_by))?;
        let unfinished = self
            .store
            .gap_pending()?
            .iter()
            .any(|(r, _)| r == metadata_ref);
        if !changed && !unfinished {
            return Ok(0); // already handled
        }
        self.finish(&rec, detected_by)
    }

    fn finish(
        &self,
        rec: &EntryRecord,
        detected_by: ConflictDetector,
    ) -> Result<usize, RegistryError> {
        let ids = self
            .handler
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .registry_conflict(&rec.metadata_ref, &rec.key_id);
        self.queue_gap(rec, &ids, detected_by);
        self.store.clear_gap_pending(&rec.metadata_ref)?;
        Ok(ids.len())
    }

    /// Finish conflicts whose handling was cut short (crash between quarantine
    /// and the queued gap). Call once at start; [`RegistryClient`] does.
    pub fn resume(&self) -> Result<usize, RegistryError> {
        let mut n = 0;
        for (r, det) in self.store.gap_pending()? {
            if let Some(rec) = self.store.entry(&r)? {
                self.finish(&rec, detector_from(&det))?;
                n += 1;
            }
        }
        Ok(n)
    }

    fn queue_gap(&self, rec: &EntryRecord, ids: &[String], detected_by: ConflictDetector) {
        // A gap needs at least one event id; with no dependents there is
        // nothing to attribute (the quarantine itself is local and durable).
        if ids.is_empty() {
            return;
        }
        let (Ok(r), Ok(k)) = (MetadataRef::new(&rec.metadata_ref), KeyId::new(&rec.key_id)) else {
            return;
        };
        let Ok(total) = PositiveI64::new(ids.len() as i64) else {
            return;
        };
        let at = crate::status_report::rfc3339(time::OffsetDateTime::now_utc());
        // Sorted, so the chunks and their gap ids do not depend on the order the
        // spool seam lists the events in.
        let mut sorted: Vec<String> = ids.to_vec();
        sorted.sort();
        sorted.dedup();
        for chunk in sorted.chunks(GAP_EVENT_IDS) {
            let event_ids: Result<Vec<Uuid>, _> =
                chunk.iter().map(|i| Uuid::new(i.clone())).collect();
            let (Ok(event_ids), Ok(detected_at), Ok(gap_id)) = (
                event_ids,
                Timestamp::new(at.clone()),
                Uuid::new(gap_id_for(&rec.metadata_ref, &rec.key_id, chunk)),
            ) else {
                continue;
            };
            let gap = GapReport::RegistryConflict(RegistryConflictGap {
                gap_id,
                detected_at,
                metadata_ref: r.clone(),
                key_id: k.clone(),
                event_ids,
                detected_by,
                affected_event_count: total,
            });
            if gap.validate().is_ok() {
                self.gaps.record(gap);
            }
        }
    }

    /// README N11 iii: before sending events, recompute the immutable-field hash
    /// of each referenced local entry and compare it with the one recorded at
    /// the ACK. A mismatch takes the registry-conflict path. Returns the refs
    /// that must NOT be used (mismatched or quarantined).
    pub fn check_entries(&self, refs: &[String]) -> Result<Vec<String>, RegistryError> {
        let mut bad = Vec::new();
        for r in refs {
            match self.store.verify_entry(r)? {
                EntryCheck::Verified | EntryCheck::NotAcked => {}
                EntryCheck::Mismatch => {
                    self.report_conflict(r, ConflictDetector::LocalHashCheck)?;
                    bad.push(r.clone());
                }
                EntryCheck::Quarantined | EntryCheck::Missing => bad.push(r.clone()),
            }
        }
        Ok(bad)
    }
}

// ------------------------------------------------------------------ outcomes

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadOutcome {
    /// 200: these (sent) refs are durable on the server.
    Done {
        refs: Vec<String>,
    },
    /// 409 `registry_conflict` naming entries.
    Conflict {
        refs: Vec<String>,
    },
    /// 409 naming nothing usable.
    UnattributedConflict,
    /// 422: the named (sent) refs, possibly none.
    Invalid {
        refs: Vec<String>,
    },
    TooLarge,
    /// 404 `proxy_unknown`.
    Unregistered,
    RateLimited,
    /// 403 `disabled` / `retired`.
    Rejected,
    Unreachable,
    Unavailable,
    Retry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportOutcome {
    Done,
    /// 424: these refs are not registered on the server.
    Pending {
        refs: Vec<String>,
    },
    /// 409, 413, 422: retrying the same bytes cannot succeed.
    Discard {
        status: u16,
    },
    Unregistered,
    RateLimited,
    Rejected,
    Unreachable,
    Unavailable,
    Retry,
}

fn api_error(r: &StatusReply) -> Option<sigil_proxy_api::ApiError> {
    sigil_proxy_api::parse_api_error(&r.body).ok()
}

/// Reduce an upload answer. `sent` are the refs in the request, in order. Pure.
pub fn classify_upload(reply: Option<&StatusReply>, sent: &[String]) -> UploadOutcome {
    let Some(r) = reply else {
        return UploadOutcome::Unreachable;
    };
    let in_sent = |s: &str| sent.iter().any(|x| x == s);
    match r.status {
        200 => match sigil_proxy_api::parse_upload_response(&r.body) {
            Ok(ok) => {
                let mut refs: Vec<String> = Vec::new();
                for m in ok
                    .registered_metadata_refs
                    .iter()
                    .chain(ok.duplicate_metadata_refs.iter())
                {
                    if in_sent(m.as_str()) && !refs.iter().any(|x| x == m.as_str()) {
                        refs.push(m.as_str().to_string());
                    }
                }
                if refs.is_empty() {
                    UploadOutcome::Retry
                } else {
                    UploadOutcome::Done { refs }
                }
            }
            Err(_) => UploadOutcome::Retry,
        },
        403 => match api_error(r).map(|e| e.error.code) {
            Some(ErrorCode::Disabled | ErrorCode::Retired) => UploadOutcome::Rejected,
            _ => UploadOutcome::Retry,
        },
        409 | 422 => {
            let items = api_error(r).and_then(|e| e.error.items).unwrap_or_default();
            let mut refs: Vec<String> = Vec::new();
            for it in &items {
                let named = it
                    .metadata_ref
                    .as_ref()
                    .map(|m| m.as_str().to_string())
                    .filter(|m| in_sent(m))
                    .or_else(|| sent.get(it.index as usize).cloned());
                if let Some(n) = named {
                    if !refs.contains(&n) {
                        refs.push(n);
                    }
                }
            }
            if r.status == 409 {
                if refs.is_empty() {
                    UploadOutcome::UnattributedConflict
                } else {
                    UploadOutcome::Conflict { refs }
                }
            } else {
                UploadOutcome::Invalid { refs }
            }
        }
        404 => UploadOutcome::Unregistered,
        413 => UploadOutcome::TooLarge,
        429 => UploadOutcome::RateLimited,
        s if (500..600).contains(&s) => UploadOutcome::Unavailable,
        _ => UploadOutcome::Retry,
    }
}

/// Reduce an inventory answer. Pure.
pub fn classify_report(reply: Option<&StatusReply>) -> ReportOutcome {
    let Some(r) = reply else {
        return ReportOutcome::Unreachable;
    };
    match r.status {
        200 => ReportOutcome::Done,
        424 => match api_error(r) {
            Some(e) if e.error.code == ErrorCode::MetadataRefPending => {
                let mut refs: Vec<String> = e
                    .error
                    .pending_metadata_refs
                    .unwrap_or_default()
                    .iter()
                    .map(|m| m.as_str().to_string())
                    .collect();
                for it in e.error.items.unwrap_or_default() {
                    if let Some(m) = it.metadata_ref {
                        refs.push(m.as_str().to_string());
                    }
                }
                refs.sort();
                refs.dedup();
                ReportOutcome::Pending { refs }
            }
            _ => ReportOutcome::Retry,
        },
        s @ (409 | 413 | 422) => ReportOutcome::Discard { status: s },
        403 => match api_error(r).map(|e| e.error.code) {
            Some(ErrorCode::Disabled | ErrorCode::Retired) => ReportOutcome::Rejected,
            _ => ReportOutcome::Retry,
        },
        404 => ReportOutcome::Unregistered,
        429 => ReportOutcome::RateLimited,
        s if (500..600).contains(&s) => ReportOutcome::Unavailable,
        _ => ReportOutcome::Retry,
    }
}

// -------------------------------------------------------------------- client

#[derive(Debug, Clone, Copy)]
pub struct RegistryParams {
    /// Wait when nothing is queued.
    pub poll: Duration,
    /// First retry delay after a failure; doubles up to `max_backoff`.
    pub retry: Duration,
    pub max_backoff: Duration,
    /// Least spacing between two requests.
    pub min_spacing: Duration,
}

impl Default for RegistryParams {
    /// Proposed values (unmeasured), like the status reporter.
    fn default() -> Self {
        RegistryParams {
            poll: Duration::from_secs(1),
            retry: Duration::from_secs(5),
            max_backoff: Duration::from_secs(300),
            min_spacing: Duration::from_millis(200),
        }
    }
}

/// What one [`RegistryClient::sync_once`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepKind {
    /// Nothing was queued.
    Idle,
    Upload(UploadOutcome),
    Report(ReportOutcome),
    /// A report was dropped without sending (it names a quarantined or unknown
    /// entry, or is unreadable).
    Dropped,
    /// The local store failed; nothing was sent.
    StoreError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStep {
    pub kind: StepKind,
    /// The step moved work on. Without it the next attempt backs off.
    pub progressed: bool,
}

/// Refusals (422) after which an entry is poisoned.
pub const POISON_AFTER: i64 = 3;
/// A poisoned entry is offered again after about this long (jittered to between
/// half and all of it), and on every process start. Poison is a pause, not a
/// verdict: the server's view (scope assignment, limits) can change. One more
/// refusal poisons it again at once. Poisoned entries are counted meanwhile.
pub const POISON_RETRY: Duration = Duration::from_secs(3600);
/// Consecutive 424s for one report after which it is given up (and its chain
/// reset).
pub const MAX_REPORT_424: u32 = 5;
/// Queued reports looked at per step.
const REPORT_SCAN: usize = 32;
/// Largest serialized entry (registry.md R2).
pub const MAX_ENTRY_BYTES: usize = 256 * 1024;

/// What T-13c needs for a status/health view of the sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHealth {
    pub pending_entries: u64,
    pub pending_reports: u64,
    /// Entries refused for good (counted, never retried).
    pub poisoned_entries: u64,
    /// Reports given up on since start (each reset its scope chain).
    pub discarded_reports: u64,
    pub consecutive_failures: u32,
    /// Entries quarantined after a registry conflict.
    pub quarantined_entries: u64,
}

pub struct RegistryClient<T: RegistryTransport> {
    store: RegistryStore,
    transport: T,
    conflicts: ConflictReporter,
    params: RegistryParams,
    proxy_id: String,
    /// Current entries-per-request cap (halved by 413, 1 while isolating).
    cap: usize,
    failures: u32,
    discarded_reports: u64,
    /// Mirrors of `discarded_reports` and `failures` for the status probe.
    shared_discarded: Arc<AtomicU64>,
    shared_failures: Arc<AtomicU32>,
    resumed: bool,
    /// When poisoned entries are next made eligible again.
    next_unpoison: Option<Instant>,
    /// Consecutive 424s per queued report.
    report_424: HashMap<String, u32>,
    /// Refused entries are not retried before this instant, so a bad entry never
    /// delays good ones.
    refused_not_before: Option<Instant>,
    refused_streak: u32,
}

impl<T: RegistryTransport> RegistryClient<T> {
    pub fn new(
        store: RegistryStore,
        transport: T,
        conflicts: ConflictReporter,
        params: RegistryParams,
    ) -> RegistryClient<T> {
        let proxy_id = store.proxy_id();
        RegistryClient {
            store,
            transport,
            conflicts,
            params,
            proxy_id,
            cap: MAX_UPLOAD_ENTRIES,
            failures: 0,
            discarded_reports: 0,
            shared_discarded: Arc::new(AtomicU64::new(0)),
            shared_failures: Arc::new(AtomicU32::new(0)),
            resumed: false,
            next_unpoison: None,
            report_424: HashMap::new(),
            refused_not_before: None,
            refused_streak: 0,
        }
    }

    pub fn conflicts(&self) -> &ConflictReporter {
        &self.conflicts
    }

    /// Reports given up on (409, 413, 422, a repeated 424, or a member that can
    /// never be registered).
    pub fn discarded_reports(&self) -> u64 {
        self.discarded_reports
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.failures
    }

    pub fn health(&self) -> Result<ClientHealth, RegistryError> {
        Ok(ClientHealth {
            pending_entries: self.store.pending_entry_count()?,
            pending_reports: self.store.pending_reports(10_000)?.len() as u64,
            poisoned_entries: self.store.poisoned_count()?,
            discarded_reports: self.discarded_reports,
            consecutive_failures: self.failures,
            quarantined_entries: self.store.quarantined_count()?,
        })
    }

    /// The source of the status report's `registry` section. Hand it to
    /// `StatusBuilder::set_registry` (T-13c does, next to the spool): real counts
    /// from the registry store, the discard count since start, and `sync_stalled`
    /// after [`STALL_ATTEMPTS`] consecutive failed steps.
    pub fn health_probe(&self) -> RegistryProbe {
        let store = self.store.clone();
        let discarded = self.shared_discarded.clone();
        let failures = self.shared_failures.clone();
        Arc::new(move || {
            Some(RegistrySnapshot {
                pending_entries: store.pending_entry_count().ok()?,
                sync_stalled: failures.load(Ordering::Relaxed) >= STALL_ATTEMPTS,
                quarantined_entries: store.quarantined_count().ok()?,
                poisoned_entries: store.poisoned_count().ok()?,
                discarded_reports: discarded.load(Ordering::Relaxed),
            })
        })
    }

    /// One request's worth of work.
    pub async fn sync_once(&mut self) -> SyncStep {
        let r = self.sync_step().await;
        self.shared_failures.store(self.failures, Ordering::Relaxed);
        r
    }

    async fn sync_step(&mut self) -> SyncStep {
        match self.step().await {
            Ok(s) => {
                if s.progressed {
                    self.failures = 0;
                } else if s.kind != StepKind::Idle {
                    self.failures = self.failures.saturating_add(1);
                }
                s
            }
            Err(_) => {
                self.failures = self.failures.saturating_add(1);
                SyncStep {
                    kind: StepKind::StoreError,
                    progressed: false,
                }
            }
        }
    }

    async fn step(&mut self) -> Result<SyncStep, RegistryError> {
        if !self.resumed {
            self.conflicts.resume()?;
            self.resumed = true;
            // A restart gives poisoned entries another chance.
            self.store.unpoison_all(POISON_AFTER - 1)?;
        }
        let now = Instant::now();
        match self.next_unpoison {
            None => self.next_unpoison = Some(now + jittered(POISON_RETRY)),
            Some(t) if now >= t => {
                self.store.unpoison_all(POISON_AFTER - 1)?;
                self.next_unpoison = Some(now + jittered(POISON_RETRY));
            }
            Some(_) => {}
        }
        let allow_refused = self.refused_not_before.is_none_or(|t| Instant::now() >= t);
        let pending = self.store.pending_entries(self.cap, allow_refused)?;
        if !pending.is_empty() {
            return self.upload(pending).await;
        }
        // Reports are sent whether or not a refused entry is still waiting; only
        // a report that names a pending entry waits.
        for report in self.store.pending_reports(REPORT_SCAN)? {
            let parsed = sigil_proxy_api::parse_inventory_report(&report.body).ok();
            let Some(parsed) = parsed else {
                self.drop_report(&report, None)?;
                return Ok(SyncStep {
                    kind: StepKind::Dropped,
                    progressed: true,
                });
            };
            let members: Vec<String> = parsed
                .members
                .iter()
                .flatten()
                .map(|m| m.as_str().to_string())
                .collect();
            let states = self.store.entry_states(&members)?;
            if members.iter().any(|m| {
                matches!(
                    states.get(m),
                    None | Some(EntryState::Quarantined | EntryState::Poisoned)
                )
            }) {
                // The server can never register a member: give up on the report
                // and reset the chain it belonged to.
                self.drop_report(&report, Some(&parsed))?;
                return Ok(SyncStep {
                    kind: StepKind::Dropped,
                    progressed: true,
                });
            }
            if members
                .iter()
                .any(|m| states.get(m) == Some(&EntryState::Pending))
            {
                continue; // waits for its entries; later reports may go first
            }
            return self.send_report(report, parsed).await;
        }
        Ok(SyncStep {
            kind: StepKind::Idle,
            progressed: true,
        })
    }

    // ----------------------------------------------------------------- entries

    fn wire_entry(&self, e: &EntryRecord) -> Option<RegistryEntry> {
        Some(RegistryEntry {
            proxy_id: Id::new(&e.scope.proxy_id).ok()?,
            metadata_ref: MetadataRef::new(&e.metadata_ref).ok()?,
            upstream_id: Id::new(&e.scope.upstream_id).ok()?,
            credential_scope_id: Id::new(&e.scope.credential_scope_id).ok()?,
            protocol_version: match e.scope.protocol_version.as_str() {
                "2025-11-25" => RegistryProtocolVersion::V2025_11_25,
                _ => return None,
            },
            observation_source: match e.scope.observation_source.as_str() {
                "proxy_live" => ObservationSource::ProxyLive,
                _ => return None,
            },
            canon: match e.canon.as_str() {
                crate::registry_key::CANON_V1 => Canon::SigilTooldefFpV1,
                _ => return None,
            },
            key_id: KeyId::new(&e.key_id).ok()?,
            fingerprint: Fingerprint::new(&e.fingerprint).ok()?,
            observed_at: Timestamp::new(&e.observed_at).ok()?,
            definition: jcs::parse_strict(&e.definition).ok()?,
        })
    }

    async fn upload(&mut self, pending: Vec<EntryRecord>) -> Result<SyncStep, RegistryError> {
        let mut entries = Vec::new();
        let mut sent = Vec::new();
        let mut bytes = 64usize;
        let mut skipped = false;
        for rec in &pending {
            // A stored entry that cannot be rebuilt was damaged: quarantine it.
            let Some(w) = self.wire_entry(rec) else {
                self.conflicts
                    .report_conflict(&rec.metadata_ref, ConflictDetector::LocalHashCheck)?;
                skipped = true;
                continue;
            };
            let len = serde_json::to_vec(&w)
                .map(|v| v.len())
                .unwrap_or(usize::MAX);
            if len > MAX_ENTRY_BYTES {
                // Cannot be accepted whatever the server says.
                self.store.poison(&rec.metadata_ref)?;
                skipped = true;
                continue;
            }
            if !entries.is_empty() && bytes + len + 1 > MAX_UPLOAD_BYTES {
                break;
            }
            bytes += len + 1;
            sent.push(rec.metadata_ref.clone());
            entries.push(w);
        }
        if entries.is_empty() {
            return Ok(SyncStep {
                kind: StepKind::Dropped,
                progressed: skipped,
            });
        }
        let req = UploadRequest {
            schema_version: SchemaVersion,
            proxy_id: Id::new(&self.proxy_id).map_err(|_| RegistryError::Invalid("proxy_id"))?,
            entries,
        };
        req.validate()
            .map_err(|_| RegistryError::Invalid("upload"))?;
        let body = serde_json::to_vec(&req).map_err(|_| RegistryError::Invalid("upload"))?;
        let reply = self.transport.post_metadata(body).await;
        let outcome = classify_upload(reply.as_ref(), &sent);
        let progressed = self.apply_upload(&outcome, &sent)?;
        Ok(SyncStep {
            kind: StepKind::Upload(outcome),
            progressed,
        })
    }

    fn apply_upload(&mut self, o: &UploadOutcome, sent: &[String]) -> Result<bool, RegistryError> {
        Ok(match o {
            UploadOutcome::Done { refs } => {
                self.store.mark_acked(refs)?;
                self.cap = (self.cap * 2).clamp(1, MAX_UPLOAD_ENTRIES);
                self.refused_streak = 0;
                true
            }
            UploadOutcome::Conflict { refs } => {
                for r in refs {
                    self.conflicts
                        .report_conflict(r, ConflictDetector::Central409)?;
                }
                true
            }
            UploadOutcome::UnattributedConflict => {
                if sent.len() == 1 {
                    // The only entry sent: it is the culprit.
                    self.conflicts
                        .report_conflict(&sent[0], ConflictDetector::Central409)?;
                } else {
                    // Send singles until the failing entry is found.
                    self.cap = 1;
                }
                true
            }
            UploadOutcome::Invalid { refs } => {
                if refs.is_empty() && sent.len() > 1 {
                    // Nothing named: find the culprit by singles, count nothing.
                    self.cap = 1;
                } else {
                    let named = if refs.is_empty() {
                        sent
                    } else {
                        refs.as_slice()
                    };
                    self.store.bump_attempts(named, POISON_AFTER)?;
                    self.refused_streak = self.refused_streak.saturating_add(1);
                    let d = self.backoff(self.refused_streak);
                    self.refused_not_before = Some(Instant::now() + d);
                }
                // Not a failure of the link: good entries carry on at once.
                true
            }
            UploadOutcome::TooLarge => {
                if sent.len() == 1 {
                    // Alone and still too large: it can never be accepted.
                    self.store.poison(&sent[0])?;
                } else {
                    self.cap = (sent.len() / 2).max(1);
                }
                true
            }
            _ => false,
        })
    }

    // ----------------------------------------------------------------- reports

    async fn send_report(
        &mut self,
        report: StoredReport,
        parsed: InventoryReport,
    ) -> Result<SyncStep, RegistryError> {
        let reply = self.transport.post_inventory(report.body.clone()).await;
        let outcome = classify_report(reply.as_ref());
        let progressed = match &outcome {
            ReportOutcome::Done => {
                self.store.report_done(&report.report_id)?;
                self.report_424.remove(&report.report_id);
                true
            }
            ReportOutcome::Pending { refs } => {
                let n = self.report_424.entry(report.report_id.clone()).or_insert(0);
                *n += 1;
                if *n >= MAX_REPORT_424 {
                    // The server keeps not knowing members: give up on it.
                    self.report_424.remove(&report.report_id);
                    self.drop_report(&report, Some(&parsed))?;
                    true
                } else {
                    self.store.mark_unacked(refs)?;
                    false // backs off, growing with the failure streak
                }
            }
            ReportOutcome::Discard { .. } => {
                self.drop_report(&report, Some(&parsed))?;
                true
            }
            _ => false,
        };
        Ok(SyncStep {
            kind: StepKind::Report(outcome),
            progressed,
        })
    }

    /// Give up on a report. A discarded COMPLETE report breaks the server's
    /// chain for its scope key (the server never saw that snapshot), so:
    ///
    /// * the local latest snapshot is forgotten if it is that one, making the
    ///   next complete listing an `initial_baseline`;
    /// * queued reports that name it as their previous snapshot are rewritten to
    ///   `initial_baseline` (their own members and snapshot stay valid).
    fn drop_report(
        &mut self,
        report: &StoredReport,
        parsed: Option<&InventoryReport>,
    ) -> Result<(), RegistryError> {
        self.store.report_done(&report.report_id)?;
        self.discarded_reports += 1;
        self.shared_discarded
            .store(self.discarded_reports, Ordering::Relaxed);
        let Some(p) = parsed else { return Ok(()) };
        let Some(inv) = p.inventory_id.as_ref() else {
            return Ok(()); // an incomplete report is not part of the chain
        };
        let scope = ScopeKey {
            proxy_id: p.proxy_id.as_str().to_string(),
            upstream_id: p.scope.upstream_id.as_str().to_string(),
            credential_scope_id: p.scope.credential_scope_id.as_str().to_string(),
            protocol_version: "2025-11-25".to_string(),
            observation_source: "proxy_live".to_string(),
        };
        self.store.forget_snapshot(&scope, inv.as_str())?;
        for r in self.store.pending_reports(10_000)? {
            let Ok(mut q) = sigil_proxy_api::parse_inventory_report(&r.body) else {
                continue;
            };
            let names_it = match &q.comparison {
                Some(Comparison::Compared {
                    previous_inventory_id,
                    ..
                })
                | Some(Comparison::Rebaseline {
                    previous_inventory_id,
                    ..
                }) => previous_inventory_id.as_str() == inv.as_str(),
                _ => false,
            };
            if names_it {
                q.comparison = Some(Comparison::InitialBaseline {});
                if let Ok(body) = serde_json::to_vec(&q) {
                    self.store.replace_report_body(&r.report_id, &body)?;
                }
            }
        }
        Ok(())
    }

    // --------------------------------------------------------------------- run

    /// Bounded exponential backoff for failure streak `n` (1-based) with
    /// "equal jitter": uniform in `[d/2, d]`.
    fn backoff(&self, n: u32) -> Duration {
        let shift = n.saturating_sub(1).min(16);
        let d = self
            .params
            .retry
            .saturating_mul(1u32 << shift)
            .min(self.params.max_backoff);
        let r = (uuid::Uuid::new_v4().as_u128() & 0xffff) as u32; // 0..=65535
        d / 2 + d.mul_f64(f64::from(r) / 131_072.0)
    }

    /// Delay before the next step: spacing after progress, the poll interval
    /// when idle, else jittered bounded exponential backoff.
    pub fn next_delay(&self, step: &SyncStep) -> Duration {
        if step.kind == StepKind::Idle {
            return self.params.poll;
        }
        if step.progressed {
            return self.params.min_spacing;
        }
        self.backoff(self.failures)
    }

    /// Paced loop until `shutdown` completes.
    pub async fn run(mut self, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            let step = tokio::select! {
                _ = &mut shutdown => return,
                s = self.sync_once() => s,
            };
            let delay = self.next_delay(&step);
            tokio::select! {
                _ = &mut shutdown => return,
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }
}

// ------------------------------------------------------------- mTLS transport

#[cfg(unix)]
pub use mtls::MtlsRegistryTransport;

#[cfg(unix)]
mod mtls {
    use super::*;
    use crate::bootstrap::{split_host_port, Bootstrap};
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full, Limited};
    use hyper_util::rt::TokioIo;
    use std::path::PathBuf;

    /// Per-attempt bound: connect, handshake, request and body together.
    const TIMEOUT: Duration = Duration::from_secs(20);

    /// The same client pattern as the config fetch (`config_sync::MtlsFetcher`):
    /// one fresh mTLS connection per request (`Connection: close`), CA bundle
    /// and proxy identity read on every call.
    pub struct MtlsRegistryTransport {
        host: String,
        port: u16,
        authority: String,
        metadata_path: String,
        inventory_path: String,
        ca_file: PathBuf,
        cert_file: PathBuf,
        key_file: PathBuf,
        timeout: Duration,
    }

    impl MtlsRegistryTransport {
        pub fn from_bootstrap(b: &Bootstrap) -> Option<MtlsRegistryTransport> {
            let rest = b.control_plane_url.strip_prefix("https://")?;
            let (authority, prefix) = match rest.find('/') {
                Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
                None => (rest, ""),
            };
            let (host, port) = split_host_port(authority).ok()?;
            let host = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(&host)
                .to_string();
            Some(MtlsRegistryTransport {
                authority: authority.to_ascii_lowercase(),
                host,
                port: port.unwrap_or(443),
                metadata_path: format!("{prefix}/v1/proxy-metadata"),
                inventory_path: format!("{prefix}/v1/proxy-inventory"),
                ca_file: b.ca_file.clone(),
                cert_file: b.client_cert_file.clone(),
                key_file: b.client_key_file.clone(),
                timeout: TIMEOUT,
            })
        }

        async fn exchange(&self, path: &str, payload: Vec<u8>) -> Option<(u16, Vec<u8>)> {
            let connector =
                crate::tls::control_plane_connector(&self.ca_file, &self.cert_file, &self.key_file)
                    .ok()?;
            let name = crate::tls::server_name(&self.host)?;
            let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
                .await
                .ok()?;
            let _ = tcp.set_nodelay(true);
            let tls = connector.connect(name, tcp).await.ok()?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .ok()?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = http::Request::builder()
                .method(http::Method::POST)
                .uri(path)
                .header(http::header::HOST, self.authority.as_str())
                .header(http::header::ACCEPT, "application/json")
                .header(http::header::CONTENT_TYPE, "application/json")
                .header(http::header::CONNECTION, "close")
                .body(Full::new(Bytes::from(payload)))
                .ok()?;
            let resp = sender.send_request(req).await.ok()?;
            let (parts, body) = resp.into_parts();
            let bytes = Limited::new(body, MAX_REGISTRY_RESPONSE_BYTES)
                .collect()
                .await
                .ok()
                .map(|c| c.to_bytes().to_vec())
                .unwrap_or_default();
            Some((parts.status.as_u16(), bytes))
        }

        fn post(&self, path: &str, body: Vec<u8>) -> PostFuture<'_> {
            let path = path.to_string();
            Box::pin(async move {
                match tokio::time::timeout(self.timeout, self.exchange(&path, body)).await {
                    Ok(Some((status, body))) => Some(StatusReply { status, body }),
                    _ => None,
                }
            })
        }
    }

    impl RegistryTransport for MtlsRegistryTransport {
        fn post_metadata(&self, body: Vec<u8>) -> PostFuture<'_> {
            self.post(&self.metadata_path, body)
        }
        fn post_inventory(&self, body: Vec<u8>) -> PostFuture<'_> {
            self.post(&self.inventory_path, body)
        }
    }
}

/// Windows: the control-plane client is unix-only until the Windows proxy
/// service is verified; every request gets no answer.
#[cfg(not(unix))]
pub struct MtlsRegistryTransport;

#[cfg(not(unix))]
impl MtlsRegistryTransport {
    pub fn from_bootstrap(_: &crate::bootstrap::Bootstrap) -> Option<MtlsRegistryTransport> {
        Some(MtlsRegistryTransport)
    }
}

#[cfg(not(unix))]
impl RegistryTransport for MtlsRegistryTransport {
    fn post_metadata(&self, _: Vec<u8>) -> PostFuture<'_> {
        Box::pin(async { None })
    }
    fn post_inventory(&self, _: Vec<u8>) -> PostFuture<'_> {
        Box::pin(async { None })
    }
}

/// Uniform in `[d/2, d]`.
fn jittered(d: Duration) -> Duration {
    let r = (uuid::Uuid::new_v4().as_u128() & 0xffff) as u32;
    d / 2 + d.mul_f64(f64::from(r) / 131_072.0)
}
