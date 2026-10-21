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

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sigil_proxy_api::registry::{
    Canon, ObservationSource, RegistryEntry, RegistryProtocolVersion, UploadRequest,
};
use sigil_proxy_api::status::{ConflictDetector, RegistryConflictGap};
use sigil_proxy_api::{
    ErrorCode, Fingerprint, GapReport, Id, KeyId, MetadataRef, PositiveI64, SchemaVersion,
    Timestamp, Uuid, Validate,
};

use crate::jcs;
use crate::registry_store::{
    EntryCheck, EntryRecord, EntryState, RegistryError, RegistryStore, StoredReport,
};
use crate::status_report::{GapQueue, PostFuture, StatusReply};

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
    pub fn report_conflict(
        &self,
        metadata_ref: &str,
        detected_by: ConflictDetector,
    ) -> Result<usize, RegistryError> {
        let Some(rec) = self.store.entry(metadata_ref)? else {
            return Ok(0);
        };
        let first = self.store.quarantine(metadata_ref)?;
        if !first {
            return Ok(0); // already handled
        }
        let ids = self
            .handler
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .registry_conflict(metadata_ref, &rec.key_id);
        self.queue_gap(&rec, &ids, detected_by);
        Ok(ids.len())
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
        for chunk in ids.chunks(GAP_EVENT_IDS) {
            let event_ids: Result<Vec<Uuid>, _> =
                chunk.iter().map(|i| Uuid::new(i.clone())).collect();
            let (Ok(event_ids), Ok(detected_at), Ok(gap_id)) = (
                event_ids,
                Timestamp::new(at.clone()),
                Uuid::new(uuid::Uuid::new_v4().to_string()),
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

pub struct RegistryClient<T: RegistryTransport> {
    store: RegistryStore,
    transport: T,
    conflicts: ConflictReporter,
    params: RegistryParams,
    proxy_id: String,
    /// Current entries-per-request cap (halved by 413, 1 while isolating).
    cap: usize,
    isolating: bool,
    failures: u32,
    discarded_reports: u64,
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
            isolating: false,
            failures: 0,
            discarded_reports: 0,
        }
    }

    pub fn conflicts(&self) -> &ConflictReporter {
        &self.conflicts
    }

    /// Reports dropped without being accepted (409, 413, 422 or a quarantined
    /// member). Lets T-13c surface a stalled or lossy sync.
    pub fn discarded_reports(&self) -> u64 {
        self.discarded_reports
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.failures
    }

    /// One request's worth of work.
    pub async fn sync_once(&mut self) -> SyncStep {
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
        let pending = self.store.pending_entries(self.cap)?;
        if !pending.is_empty() {
            return self.upload(pending).await;
        }
        let Some(report) = self.store.pending_reports(1)?.into_iter().next() else {
            return Ok(SyncStep {
                kind: StepKind::Idle,
                progressed: true,
            });
        };
        self.send_report(report).await
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
        for rec in &pending {
            // A stored entry that cannot be rebuilt was damaged: quarantine it.
            let Some(w) = self.wire_entry(rec) else {
                self.conflicts
                    .report_conflict(&rec.metadata_ref, ConflictDetector::LocalHashCheck)?;
                continue;
            };
            let len = serde_json::to_vec(&w)
                .map(|v| v.len())
                .unwrap_or(usize::MAX);
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
                progressed: true,
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
                self.isolating = false;
                self.cap = (self.cap * 2).clamp(1, MAX_UPLOAD_ENTRIES);
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
                    self.isolating = false;
                    true
                } else {
                    // Send singles until the failing entry is found.
                    self.isolating = true;
                    self.cap = 1;
                    true
                }
            }
            UploadOutcome::Invalid { refs } => {
                let named = if refs.is_empty() {
                    sent
                } else {
                    refs.as_slice()
                };
                self.store.bump_attempts(named)?;
                false
            }
            UploadOutcome::TooLarge => {
                self.cap = (sent.len() / 2).max(1);
                self.cap > 1 || sent.len() > 1
            }
            _ => false,
        })
    }

    // ----------------------------------------------------------------- reports

    async fn send_report(&mut self, report: StoredReport) -> Result<SyncStep, RegistryError> {
        let parsed = sigil_proxy_api::parse_inventory_report(&report.body);
        let members: Vec<String> = match &parsed {
            Ok(r) => r
                .members
                .as_ref()
                .map(|m| m.iter().map(|x| x.as_str().to_string()).collect())
                .unwrap_or_default(),
            Err(_) => {
                self.drop_report(&report)?;
                return Ok(SyncStep {
                    kind: StepKind::Dropped,
                    progressed: true,
                });
            }
        };
        let states = self.store.entry_states(&members)?;
        let unusable = members
            .iter()
            .any(|m| matches!(states.get(m), None | Some(EntryState::Quarantined)));
        if unusable {
            self.drop_report(&report)?;
            return Ok(SyncStep {
                kind: StepKind::Dropped,
                progressed: true,
            });
        }
        let reply = self.transport.post_inventory(report.body.clone()).await;
        let outcome = classify_report(reply.as_ref());
        let progressed = match &outcome {
            ReportOutcome::Done => {
                self.store.report_done(&report.report_id)?;
                true
            }
            ReportOutcome::Pending { refs } => {
                self.store.mark_unacked(refs)?;
                // Members not named stay as they are; the upload path runs next.
                !refs.is_empty()
            }
            ReportOutcome::Discard { .. } => {
                self.drop_report(&report)?;
                true
            }
            _ => false,
        };
        Ok(SyncStep {
            kind: StepKind::Report(outcome),
            progressed,
        })
    }

    fn drop_report(&mut self, report: &StoredReport) -> Result<(), RegistryError> {
        self.store.report_done(&report.report_id)?;
        self.discarded_reports += 1;
        Ok(())
    }

    // --------------------------------------------------------------------- run

    /// Delay before the next step: spacing after progress, the poll interval
    /// when idle, else bounded exponential backoff.
    pub fn next_delay(&self, step: &SyncStep) -> Duration {
        if step.kind == StepKind::Idle {
            return self.params.poll;
        }
        if step.progressed {
            return self.params.min_spacing;
        }
        let shift = self.failures.saturating_sub(1).min(16);
        self.params
            .retry
            .saturating_mul(1u32 << shift)
            .min(self.params.max_backoff)
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

        /// Test hook: a different per-attempt bound.
        pub fn with_timeout(mut self, t: Duration) -> Self {
            self.timeout = t;
            self
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
