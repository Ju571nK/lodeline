//! Status report and heartbeat (T-12c2, control-plane.md section 6.2 "Status
//! report", ledger-and-query.md L6b).
//!
//! * [`StatusBuilder`] turns the config sync's [`ConfigView`] plus pending gaps
//!   into a `POST /v1/proxy-status` body and validates it with the shared
//!   `sigil_proxy_api::parse_status` before anything is sent.
//! * [`classify`] reduces the server's answer to a [`ReportOutcome`]; it is pure.
//! * [`GapQueue`] holds gap reports until they are acknowledged. The ledger that
//!   produces gaps (T-11 S4) does not exist yet, so nothing pushes into it in
//!   this slice; the queue is the seam and carries the response rules.
//! * [`run_status_reporter`] sends on a jittered schedule (the heartbeat) and
//!   promptly after the config view changes. It reuses the config client
//!   ([`crate::config_sync::MtlsFetcher`]) through [`StatusTransport`].
//!
//! Response rules (#260), all fail closed:
//! * `503 storage_limit` is server storage, not a central outage: no outage gap
//!   is ever opened for it, and only the refused gap ids are resent.
//! * `422` with items quarantines exactly those gaps; `422` without usable items
//!   quarantines the whole report (every gap in it).
//! * `409` quarantines the named gaps and resends the rest.
//! * `403 disabled` or `retired` is a rejection: it is never retried hot and it
//!   does not change the local config state (the config fetch is the authority).
//! * Anything else (other 5xx, 429, 404, transport failure) is retried with
//!   backoff; no gap is dropped.
//!
//! Nothing here logs a body, a gap, a hash or an address.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use sigil_proxy_api::status::ConfigState;
use sigil_proxy_api::{ErrorCode, GapReport};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::config_sync::ConfigView;

/// Largest answer read from the server. A 200 body lists at most 200 ids.
pub const MAX_STATUS_RESPONSE_BYTES: usize = 64 * 1024;
/// Gaps per report (`proxy-status.schema.json`).
pub const MAX_GAPS_PER_REPORT: usize = 100;
/// Entries the queue holds (pending plus quarantined). A full queue refuses new
/// gaps rather than dropping an unacknowledged one.
pub const MAX_QUEUED_GAPS: usize = 1024;

/// The server's answer, reduced to what the classifier reads.
#[derive(Clone, PartialEq, Eq)]
pub struct StatusReply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The body is not printed.
impl std::fmt::Debug for StatusReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StatusReply({}, {} bytes)", self.status, self.body.len())
    }
}

pub type PostFuture<'a> = Pin<Box<dyn Future<Output = Option<StatusReply>> + Send + 'a>>;

/// `None` means no answer (transport error, timeout, bad TLS material).
pub trait StatusTransport: Send + Sync {
    fn post_status(&self, body: Vec<u8>) -> PostFuture<'_>;
}

// --------------------------------------------------------------------- queue

fn gap_id(g: &GapReport) -> &str {
    match g {
        GapReport::RegistryConflict(x) => x.gap_id.as_str(),
        GapReport::EventQuarantined(x) => x.gap_id.as_str(),
        GapReport::LocalRecordFailed(x) => x.gap_id.as_str(),
        GapReport::SpoolExpired(x) => x.gap_id.as_str(),
        GapReport::UnrecordedCalls(x) => x.gap_id.as_str(),
        GapReport::CentralOutage(x) => x.gap_id.as_str(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GapState {
    Pending,
    /// Kept locally, never resent (a 422 or 409 named it).
    Quarantined,
}

struct Entry {
    gap: GapReport,
    state: GapState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

/// Gap reports awaiting acknowledgement. Cheap to clone (shared).
#[derive(Clone, Default)]
pub struct GapQueue(Arc<Mutex<Vec<Entry>>>);

impl GapQueue {
    pub fn new() -> GapQueue {
        GapQueue::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Entry>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queue a gap. A gap with the id of a queued one replaces it and is pending
    /// again (an open `central_outage` is resent with its `ended_at`).
    pub fn push(&self, gap: GapReport) -> Result<(), QueueFull> {
        let mut q = self.lock();
        let id = gap_id(&gap).to_string();
        if let Some(e) = q.iter_mut().find(|e| gap_id(&e.gap) == id) {
            *e = Entry {
                gap,
                state: GapState::Pending,
            };
            return Ok(());
        }
        if q.len() >= MAX_QUEUED_GAPS {
            return Err(QueueFull);
        }
        q.push(Entry {
            gap,
            state: GapState::Pending,
        });
        Ok(())
    }

    /// Oldest pending gaps, at most one report's worth.
    pub fn pending_batch(&self) -> Vec<GapReport> {
        self.lock()
            .iter()
            .filter(|e| e.state == GapState::Pending)
            .take(MAX_GAPS_PER_REPORT)
            .map(|e| GapReport::clone(&e.gap))
            .collect()
    }

    pub fn pending_ids(&self) -> Vec<String> {
        self.ids(GapState::Pending)
    }

    pub fn quarantined_ids(&self) -> Vec<String> {
        self.ids(GapState::Quarantined)
    }

    fn ids(&self, s: GapState) -> Vec<String> {
        self.lock()
            .iter()
            .filter(|e| e.state == s)
            .map(|e| gap_id(&e.gap).to_string())
            .collect()
    }

    /// Apply a classified answer for a report that carried `sent` (gap ids).
    pub fn settle(&self, outcome: &ReportOutcome) {
        let mut q = self.lock();
        let drop_ids = |q: &mut Vec<Entry>, ids: &[String]| {
            q.retain(|e| !ids.iter().any(|i| i == gap_id(&e.gap)));
        };
        match outcome {
            ReportOutcome::Accepted {
                acknowledged,
                duplicate,
            } => {
                drop_ids(&mut q, acknowledged);
                drop_ids(&mut q, duplicate);
            }
            // Stored gaps are durable on the server; refused ones stay pending.
            ReportOutcome::StorageLimit { stored, .. } => drop_ids(&mut q, stored),
            ReportOutcome::Quarantine { gaps, .. } | ReportOutcome::Conflict { gaps } => {
                for e in q.iter_mut() {
                    if gaps.iter().any(|i| i == gap_id(&e.gap)) {
                        e.state = GapState::Quarantined;
                    }
                }
            }
            ReportOutcome::Rejected
            | ReportOutcome::Unreachable
            | ReportOutcome::Unavailable
            | ReportOutcome::Retry => {}
        }
    }
}

// ------------------------------------------------------------------ outcomes

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportOutcome {
    /// 200: the listed ids are durable.
    Accepted {
        acknowledged: Vec<String>,
        duplicate: Vec<String>,
    },
    /// 503 `storage_limit`: server storage, not an outage. `refused` stay
    /// pending; `stored` (the rest of a report whose refusal named items) are
    /// durable because the server commits them before answering.
    StorageLimit {
        refused: Vec<String>,
        stored: Vec<String>,
    },
    /// 422. `whole_report` when no usable item named a gap.
    Quarantine {
        gaps: Vec<String>,
        whole_report: bool,
    },
    /// 409: the named gaps conflict with stored ones.
    Conflict { gaps: Vec<String> },
    /// 403 `disabled` or `retired`.
    Rejected,
    /// No answer at all.
    Unreachable,
    /// 5xx that is not `storage_limit`.
    Unavailable,
    /// Any other answer (429, 404, 413, 401, an unreadable 200, ...).
    Retry,
}

impl ReportOutcome {
    /// Whether this answer may count toward a `central_outage` gap. A refusal for
    /// server storage does not: the server is up and answering. (Nothing opens an
    /// outage gap yet; the ingest path of T-11 S4 owns that.)
    pub fn signals_central_outage(&self) -> bool {
        matches!(
            self,
            ReportOutcome::Unreachable | ReportOutcome::Unavailable
        )
    }
}

fn error_code(body: &[u8]) -> Option<sigil_proxy_api::ApiError> {
    sigil_proxy_api::parse_api_error(body).ok()
}

/// Reduce an answer to an outcome. `sent` are the gap ids in the report, in order
/// (the `index` of a 422 item refers to this order). Pure.
pub fn classify(reply: Option<&StatusReply>, sent: &[String]) -> ReportOutcome {
    let Some(r) = reply else {
        return ReportOutcome::Unreachable;
    };
    let in_sent = |id: &str| sent.iter().any(|s| s == id);
    match r.status {
        200 => match sigil_proxy_api::parse_status_response(&r.body) {
            Ok(ok) => ReportOutcome::Accepted {
                acknowledged: ok
                    .acknowledged_gap_ids
                    .iter()
                    .map(|u| u.as_str().to_string())
                    .filter(|i| in_sent(i))
                    .collect(),
                duplicate: ok
                    .duplicate_gap_ids
                    .iter()
                    .map(|u| u.as_str().to_string())
                    .filter(|i| in_sent(i))
                    .collect(),
            },
            Err(_) => ReportOutcome::Retry,
        },
        403 => match error_code(&r.body).map(|e| e.error.code) {
            Some(ErrorCode::Disabled | ErrorCode::Retired) => ReportOutcome::Rejected,
            _ => ReportOutcome::Retry,
        },
        409 => {
            let gaps: Vec<String> = error_code(&r.body)
                .and_then(|e| e.error.items)
                .unwrap_or_default()
                .iter()
                .filter_map(|i| i.gap_id.as_ref().map(|g| g.as_str().to_string()))
                .filter(|g| in_sent(g))
                .collect();
            if gaps.is_empty() {
                ReportOutcome::Retry
            } else {
                ReportOutcome::Conflict { gaps }
            }
        }
        422 => {
            let items = error_code(&r.body)
                .and_then(|e| e.error.items)
                .unwrap_or_default();
            let mut gaps: Vec<String> = Vec::new();
            for it in &items {
                if let Some(id) = sent.get(it.index as usize) {
                    if !gaps.contains(id) {
                        gaps.push(id.clone());
                    }
                }
            }
            // Fail closed: items that name nothing in this report quarantine all
            // of it rather than letting the same invalid report be resent.
            if gaps.is_empty() {
                ReportOutcome::Quarantine {
                    gaps: sent.to_vec(),
                    whole_report: true,
                }
            } else {
                ReportOutcome::Quarantine {
                    gaps,
                    whole_report: false,
                }
            }
        }
        503 => {
            let err = error_code(&r.body);
            let storage_limit = err
                .as_ref()
                .is_some_and(|e| e.error.code.as_str() == "storage_limit");
            if !storage_limit {
                return ReportOutcome::Unavailable;
            }
            let refused: Vec<String> = err
                .and_then(|e| e.error.items)
                .unwrap_or_default()
                .iter()
                .filter_map(|i| i.gap_id.as_ref().map(|g| g.as_str().to_string()))
                .filter(|g| in_sent(g))
                .collect();
            if refused.is_empty() {
                // Nothing named: every gap stays pending (resent, idempotent).
                ReportOutcome::StorageLimit {
                    refused: sent.to_vec(),
                    stored: Vec::new(),
                }
            } else {
                let stored = sent
                    .iter()
                    .filter(|s| !refused.contains(s))
                    .cloned()
                    .collect();
                ReportOutcome::StorageLimit { refused, stored }
            }
        }
        s if (500..600).contains(&s) => ReportOutcome::Unavailable,
        _ => ReportOutcome::Retry,
    }
}

// ------------------------------------------------------------------- builder

/// The report could not be built or did not validate. No detail: the cause could
/// echo a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildError;

pub struct StatusBuilder {
    proxy_id: String,
    epoch_id: String,
    last_sequence: i64,
}

fn rfc3339(t: time::OffsetDateTime) -> String {
    t.replace_nanosecond(0)
        .unwrap_or(t)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

impl StatusBuilder {
    pub fn new(proxy_id: &str, epoch_id: &str) -> StatusBuilder {
        StatusBuilder {
            proxy_id: proxy_id.to_string(),
            epoch_id: epoch_id.to_string(),
            last_sequence: 0,
        }
    }

    /// `status_sequence` is monotonic per epoch and the epoch survives restarts
    /// (state_dir), so it is seeded from the wall clock in milliseconds: a
    /// restarted proxy continues above its earlier reports without a persisted
    /// counter. A clock stepped far back makes the server ignore snapshots (not
    /// gaps) until it catches up; conservative reading of the contract.
    fn next_sequence(&mut self, now: time::OffsetDateTime) -> i64 {
        let ms = i64::try_from(now.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX);
        let seq = ms.max(self.last_sequence.saturating_add(1)).max(1);
        self.last_sequence = seq;
        seq
    }

    /// Build and validate one report body.
    pub fn build(
        &mut self,
        view: &ConfigView,
        gaps: &[GapReport],
        now: time::OffsetDateTime,
    ) -> Result<Vec<u8>, BuildError> {
        let mut config = json!({
            "state": view.state,
            "applied_revision": view.applied_revision,
            "observed_desired_revision": view.observed_revision,
            "expires_at": view.expires_at,
        });
        let c = config.as_object_mut().ok_or(BuildError)?;
        if let Some(e) = view.last_update_error {
            c.insert("last_update_error".into(), json!(e));
        }
        if let Some(v) = view.max_offline_retry_age_seconds {
            c.insert("max_offline_retry_age_seconds".into(), json!(v));
        }
        if let Some(v) = view.event_retention_seconds {
            c.insert("event_retention_seconds".into(), json!(v));
        }
        if let Some(h) = &view.config_hash {
            c.insert("config_hash".into(), json!(h));
        }
        let gaps: Vec<Value> = gaps
            .iter()
            .map(|g| serde_json::to_value(g).map_err(|_| BuildError))
            .collect::<Result<_, _>>()?;
        // Spool, registry, central and routes have no producer until the ledger
        // (T-11 S4) and the route health (T-12b) exist. Reported as empty and
        // healthy, which is true: there is no spool, no registry entry, no ingest
        // attempt and no route health to report yet.
        let body = json!({
            "schema_version": 1,
            "report_id": uuid::Uuid::new_v4().to_string(),
            "proxy_id": self.proxy_id,
            "epoch_id": self.epoch_id,
            "status_sequence": self.next_sequence(now),
            "sent_at": rfc3339(now),
            "config": config,
            "spool": {"state": "ok", "depth_events": 0, "unsent_events": 0, "bytes": 0,
                "capacity_bytes": 1, "oldest_unsent_age_seconds": null,
                "quarantined_events": 0},
            "registry": {"pending_entries": 0, "sync_stalled": false},
            "central": {"last_ingest_ack_at": null, "consecutive_failures": 0},
            "routes": [],
            "counters": {"auth_failures": [], "unmatched_cancels": []},
            "gaps": gaps,
            "last_assigned_sequence": 0,
        });
        let bytes = serde_json::to_vec(&body).map_err(|_| BuildError)?;
        // The shared parser is the contract check; a body it refuses is never sent.
        sigil_proxy_api::parse_status(&bytes).map_err(|_| BuildError)?;
        Ok(bytes)
    }
}

// -------------------------------------------------------------------- pacing

#[derive(Debug, Clone, Copy)]
pub struct ReporterParams {
    /// Interval between reports when all is well (the heartbeat), jittered.
    pub heartbeat: Duration,
    /// First retry delay after a failure; doubles up to `max_backoff`.
    pub retry: Duration,
    pub max_backoff: Duration,
    /// Least spacing between two reports, also for change-triggered ones.
    pub min_spacing: Duration,
}

impl Default for ReporterParams {
    /// Proposed values (unmeasured), like the config poll of section 6.3.
    fn default() -> Self {
        ReporterParams {
            heartbeat: Duration::from_secs(30),
            retry: Duration::from_secs(5),
            max_backoff: Duration::from_secs(300),
            min_spacing: Duration::from_secs(1),
        }
    }
}

/// Everything the reporter owns across sends.
pub struct Reporter {
    builder: StatusBuilder,
    gaps: GapQueue,
    params: ReporterParams,
    failures: u32,
}

impl Reporter {
    pub fn new(proxy_id: &str, epoch_id: &str, gaps: GapQueue, params: ReporterParams) -> Reporter {
        Reporter {
            builder: StatusBuilder::new(proxy_id, epoch_id),
            gaps,
            params,
            failures: 0,
        }
    }

    /// Build, send and settle one report. `None` when nothing was sent (disabled
    /// locally, or the report did not validate).
    pub async fn send_once<T: StatusTransport + ?Sized>(
        &mut self,
        transport: &T,
        view: &ConfigView,
    ) -> Option<ReportOutcome> {
        // A disabled proxy's report is rejected by the server (section 6.2), so
        // `disabled` stays local and nothing is sent; the config fetch learns of
        // a re-enable.
        if view.state == ConfigState::Disabled {
            return None;
        }
        let batch = self.gaps.pending_batch();
        let sent: Vec<String> = batch.iter().map(|g| gap_id(g).to_string()).collect();
        let Ok(body) = self
            .builder
            .build(view, &batch, time::OffsetDateTime::now_utc())
        else {
            tracing::error!("status report did not validate; not sent");
            return None;
        };
        let reply = transport.post_status(body).await;
        let outcome = classify(reply.as_ref(), &sent);
        self.gaps.settle(&outcome);
        tracing::info!(outcome = outcome_label(&outcome), "status report");
        Some(outcome)
    }

    /// Delay before the next report, and whether a config change may bring it
    /// forward (only after a healthy answer: never hot after a rejection, a
    /// storage refusal or a failure).
    fn next_delay(&mut self, outcome: Option<&ReportOutcome>) -> (Duration, bool) {
        let p = self.params;
        let backoff = |f: &mut u32| {
            *f = f.saturating_add(1);
            let shift = (*f - 1).min(16);
            p.retry
                .saturating_mul(1u32 << shift)
                .min(p.max_backoff)
                .max(p.retry)
        };
        let (d, early) = match outcome {
            // Not sent (disabled locally or invalid): wait a heartbeat.
            None => (p.heartbeat, true),
            Some(ReportOutcome::Accepted { .. }) => {
                self.failures = 0;
                (p.heartbeat, true)
            }
            Some(ReportOutcome::StorageLimit { .. }) => {
                self.failures = 0;
                (p.heartbeat, false)
            }
            Some(ReportOutcome::Rejected) => (p.max_backoff, false),
            Some(ReportOutcome::Quarantine {
                whole_report: false,
                ..
            })
            | Some(ReportOutcome::Conflict { .. }) => {
                // The rest of the gaps go out again soon.
                self.failures = 0;
                (p.retry, false)
            }
            Some(
                ReportOutcome::Quarantine { .. }
                | ReportOutcome::Unreachable
                | ReportOutcome::Unavailable
                | ReportOutcome::Retry,
            ) => (backoff(&mut self.failures), false),
        };
        (crate::config_sync::jitter(d), early)
    }
}

fn outcome_label(o: &ReportOutcome) -> &'static str {
    match o {
        ReportOutcome::Accepted { .. } => "accepted",
        ReportOutcome::StorageLimit { .. } => "storage_limit",
        ReportOutcome::Quarantine {
            whole_report: true, ..
        } => "quarantined_whole_report",
        ReportOutcome::Quarantine { .. } => "quarantined_gaps",
        ReportOutcome::Conflict { .. } => "conflict",
        ReportOutcome::Rejected => "rejected",
        ReportOutcome::Unreachable => "unreachable",
        ReportOutcome::Unavailable => "unavailable",
        ReportOutcome::Retry => "retry",
    }
}

/// Send reports until `shutdown` completes: a heartbeat every `heartbeat` (with
/// jitter), earlier when the config view changes (an apply result, expiry, a
/// disable), never closer than `min_spacing`, and backed off after a failure.
pub async fn run_status_reporter<T: StatusTransport + ?Sized>(
    transport: &T,
    mut reporter: Reporter,
    mut view_rx: watch::Receiver<ConfigView>,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    let params = reporter.params;
    // The first report waits for the first config attempt (a view change) or one
    // heartbeat, so it does not report a state about to change.
    let mut next = Instant::now() + crate::config_sync::jitter(params.heartbeat);
    let mut last_sent: Option<Instant> = None;
    let mut early_ok = true;
    let mut watching = true;
    loop {
        loop {
            tokio::select! {
                _ = &mut shutdown => return,
                _ = tokio::time::sleep_until(next) => break,
                changed = async {
                    if watching {
                        view_rx.changed().await.is_ok()
                    } else {
                        std::future::pending::<bool>().await
                    }
                } => {
                    if !changed {
                        watching = false;
                    } else if early_ok {
                        let floor = last_sent.map_or_else(Instant::now, |t| t + params.min_spacing);
                        next = next.min(floor.max(Instant::now()));
                    }
                }
            }
        }
        let view = view_rx.borrow_and_update().clone();
        let outcome = tokio::select! {
            _ = &mut shutdown => return,
            o = reporter.send_once(transport, &view) => o,
        };
        let now = Instant::now();
        last_sent = Some(now);
        let (delay, early) = reporter.next_delay(outcome.as_ref());
        early_ok = early;
        next = now + delay.max(params.min_spacing);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_proxy_api::status::LastUpdateError;
    use std::collections::VecDeque;

    fn uid(n: u32) -> String {
        format!("00000000-0000-4000-8000-{n:012x}")
    }

    fn quarantine_gap(n: u32) -> GapReport {
        serde_json::from_value(json!({
            "kind": "event_quarantined", "gap_id": uid(n),
            "detected_at": "2026-10-11T00:00:00Z", "event_ids": [uid(900)],
            "code": "semantic_invalid"}))
        .unwrap()
    }

    fn outage_gap(n: u32, ended: Value) -> GapReport {
        serde_json::from_value(json!({
            "kind": "central_outage", "gap_id": uid(n),
            "detected_at": "2026-10-11T00:00:00Z",
            "started_at": "2026-10-11T00:00:00Z", "ended_at": ended}))
        .unwrap()
    }

    fn view(state: ConfigState) -> ConfigView {
        let valid = state == ConfigState::Valid;
        ConfigView {
            state,
            last_update_error: None,
            applied_revision: valid.then_some(7),
            config_hash: valid.then(|| "a".repeat(64)),
            observed_revision: valid.then_some(7),
            expires_at: valid.then(|| "2026-10-11T00:05:00Z".to_string()),
            max_offline_retry_age_seconds: valid.then_some(2_592_000),
            event_retention_seconds: valid.then_some(7_776_000),
        }
    }

    fn reply(status: u16, body: Value) -> Option<StatusReply> {
        Some(StatusReply {
            status,
            body: serde_json::to_vec(&body).unwrap(),
        })
    }

    fn err(code: &str, items: Value) -> Value {
        json!({"error": {"code": code, "message": "fixed", "items": items}})
    }

    fn ids(v: &[u32]) -> Vec<String> {
        v.iter().map(|n| uid(*n)).collect()
    }

    // ---- builder

    #[test]
    fn builds_a_valid_report_from_the_config_view() {
        let mut b = StatusBuilder::new("px-1", &uid(5));
        let now = time::OffsetDateTime::now_utc();
        let mut v = view(ConfigState::Valid);
        v.last_update_error = Some(LastUpdateError::FetchFailed);
        let bytes = b.build(&v, &[quarantine_gap(1)], now).unwrap();
        let st = sigil_proxy_api::parse_status(&bytes).unwrap();
        assert_eq!(st.proxy_id.as_str(), "px-1");
        assert_eq!(st.config.state, ConfigState::Valid);
        assert_eq!(st.config.applied_revision.unwrap().get(), 7);
        assert_eq!(
            st.config.last_update_error,
            Some(LastUpdateError::FetchFailed)
        );
        assert_eq!(st.config.config_hash.unwrap().as_str(), "a".repeat(64));
        assert_eq!(st.gaps.len(), 1);
        // none/expired also validate, with nulls
        for s in [ConfigState::None, ConfigState::Expired] {
            b.build(&view(s), &[], now).unwrap();
        }
    }

    #[test]
    fn sequence_is_strictly_increasing_even_within_one_millisecond() {
        let mut b = StatusBuilder::new("px-1", &uid(5));
        let now = time::OffsetDateTime::now_utc();
        let a =
            sigil_proxy_api::parse_status(&b.build(&view(ConfigState::None), &[], now).unwrap())
                .unwrap();
        let c =
            sigil_proxy_api::parse_status(&b.build(&view(ConfigState::None), &[], now).unwrap())
                .unwrap();
        assert!(c.status_sequence.get() > a.status_sequence.get());
        assert_ne!(a.report_id, c.report_id);
    }

    /// A view the schema forbids (valid without R/E or hash) is never sent.
    #[test]
    fn invalid_view_does_not_build() {
        let mut b = StatusBuilder::new("px-1", &uid(5));
        let mut v = view(ConfigState::Valid);
        v.config_hash = None;
        let now = time::OffsetDateTime::now_utc();
        assert_eq!(b.build(&v, &[], now), Err(BuildError));
        let mut v = view(ConfigState::Valid);
        v.event_retention_seconds = None;
        assert_eq!(b.build(&v, &[], now), Err(BuildError));
        // a malformed proxy id never reaches the wire
        let mut b = StatusBuilder::new("bad id!", &uid(5));
        assert_eq!(b.build(&view(ConfigState::None), &[], now), Err(BuildError));
    }

    // ---- classify

    #[test]
    fn ok_acknowledges_only_sent_ids() {
        let sent = ids(&[1, 2]);
        let o = classify(
            reply(
                200,
                json!({"state_applied": true, "acknowledged_gap_ids": [uid(1), uid(99)],
                    "duplicate_gap_ids": [uid(2)]}),
            )
            .as_ref(),
            &sent,
        );
        assert_eq!(
            o,
            ReportOutcome::Accepted {
                acknowledged: ids(&[1]),
                duplicate: ids(&[2])
            }
        );
        assert_eq!(
            classify(reply(200, json!({"nope": 1})).as_ref(), &sent),
            ReportOutcome::Retry
        );
    }

    #[test]
    fn storage_limit_is_not_an_outage_and_resends_only_refused() {
        let sent = ids(&[1, 2, 3]);
        let o = classify(
            reply(
                503,
                err(
                    "storage_limit",
                    json!([{"index": 1, "gap_id": uid(2), "code": "storage_limit"}]),
                ),
            )
            .as_ref(),
            &sent,
        );
        assert_eq!(
            o,
            ReportOutcome::StorageLimit {
                refused: ids(&[2]),
                stored: ids(&[1, 3])
            }
        );
        assert!(!o.signals_central_outage());
        // no usable items: nothing is assumed stored
        let o = classify(reply(503, err("storage_limit", json!([]))).as_ref(), &sent);
        assert_eq!(
            o,
            ReportOutcome::StorageLimit {
                refused: sent.clone(),
                stored: vec![]
            }
        );
        // any other 503 and a missing answer may be an outage
        for r in [
            reply(503, err("storage_unavailable", json!([]))),
            reply(503, json!("x")),
            reply(500, json!({})),
        ] {
            assert!(classify(r.as_ref(), &sent).signals_central_outage());
        }
        assert!(classify(None, &sent).signals_central_outage());
    }

    #[test]
    fn unprocessable_quarantines_items_or_the_whole_report() {
        let sent = ids(&[1, 2, 3]);
        let o = classify(
            reply(
                422,
                err(
                    "semantic_invalid",
                    json!([{"index": 2, "code": "semantic_invalid"}]),
                ),
            )
            .as_ref(),
            &sent,
        );
        assert_eq!(
            o,
            ReportOutcome::Quarantine {
                gaps: ids(&[3]),
                whole_report: false
            }
        );
        for r in [
            reply(422, err("semantic_invalid", json!([]))),
            reply(
                422,
                json!({"error": {"code": "semantic_invalid", "message": "x"}}),
            ),
            // an index outside the report names nothing
            reply(
                422,
                err(
                    "semantic_invalid",
                    json!([{"index": 9, "code": "semantic_invalid"}]),
                ),
            ),
            reply(422, json!("garbage")),
        ] {
            assert_eq!(
                classify(r.as_ref(), &sent),
                ReportOutcome::Quarantine {
                    gaps: sent.clone(),
                    whole_report: true
                }
            );
        }
    }

    #[test]
    fn conflict_disabled_and_the_rest() {
        let sent = ids(&[1, 2]);
        assert_eq!(
            classify(
                reply(
                    409,
                    err(
                        "conflict",
                        json!([{"index": 0, "gap_id": uid(1), "code": "conflict"}])
                    )
                )
                .as_ref(),
                &sent
            ),
            ReportOutcome::Conflict { gaps: ids(&[1]) }
        );
        for c in ["disabled", "retired"] {
            assert_eq!(
                classify(reply(403, err(c, json!([]))).as_ref(), &sent),
                ReportOutcome::Rejected
            );
        }
        assert_eq!(
            classify(reply(403, err("forbidden", json!([]))).as_ref(), &sent),
            ReportOutcome::Retry
        );
        for s in [401, 404, 413, 429, 302] {
            assert_eq!(
                classify(reply(s, json!({})).as_ref(), &sent),
                ReportOutcome::Retry
            );
        }
    }

    // ---- queue

    #[test]
    fn queue_settles_per_outcome() {
        let q = GapQueue::new();
        for n in 1..=4 {
            q.push(quarantine_gap(n)).unwrap();
        }
        q.settle(&ReportOutcome::StorageLimit {
            refused: ids(&[2]),
            stored: ids(&[1]),
        });
        assert_eq!(q.pending_ids(), ids(&[2, 3, 4]));
        q.settle(&ReportOutcome::Quarantine {
            gaps: ids(&[3]),
            whole_report: false,
        });
        assert_eq!(q.pending_ids(), ids(&[2, 4]));
        assert_eq!(q.quarantined_ids(), ids(&[3]));
        // quarantined gaps are not in the next batch
        assert_eq!(q.pending_batch().len(), 2);
        q.settle(&ReportOutcome::Accepted {
            acknowledged: ids(&[2]),
            duplicate: ids(&[4]),
        });
        assert!(q.pending_ids().is_empty());
        // failures drop nothing
        q.push(quarantine_gap(5)).unwrap();
        for o in [
            ReportOutcome::Unreachable,
            ReportOutcome::Unavailable,
            ReportOutcome::Retry,
            ReportOutcome::Rejected,
        ] {
            q.settle(&o);
        }
        assert_eq!(q.pending_ids(), ids(&[5]));
    }

    #[test]
    fn open_outage_is_replaced_by_its_close_and_resent() {
        let q = GapQueue::new();
        q.push(outage_gap(1, Value::Null)).unwrap();
        q.settle(&ReportOutcome::Accepted {
            acknowledged: ids(&[1]),
            duplicate: vec![],
        });
        q.push(outage_gap(1, json!("2026-10-11T00:10:00Z")))
            .unwrap();
        assert_eq!(q.pending_ids(), ids(&[1]));
        // the same id never queues twice
        q.push(outage_gap(1, json!("2026-10-11T00:10:00Z")))
            .unwrap();
        assert_eq!(q.pending_batch().len(), 1);
    }

    #[test]
    fn full_queue_refuses_instead_of_dropping() {
        let q = GapQueue::new();
        for n in 0..MAX_QUEUED_GAPS as u32 {
            q.push(quarantine_gap(n)).unwrap();
        }
        assert_eq!(q.push(quarantine_gap(99_999)), Err(QueueFull));
        assert_eq!(q.pending_batch().len(), MAX_GAPS_PER_REPORT);
    }

    // ---- reporter loop (paused clock, fake transport)

    struct Fake {
        replies: Mutex<VecDeque<Option<StatusReply>>>,
        sent: Mutex<Vec<(Instant, Vec<u8>)>>,
    }

    impl Fake {
        fn new(replies: Vec<Option<StatusReply>>) -> Arc<Fake> {
            Arc::new(Fake {
                replies: Mutex::new(replies.into()),
                sent: Mutex::default(),
            })
        }
        fn count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
    }

    impl StatusTransport for Arc<Fake> {
        fn post_status(&self, body: Vec<u8>) -> PostFuture<'_> {
            self.sent.lock().unwrap().push((Instant::now(), body));
            let r = self.replies.lock().unwrap().pop_front().flatten();
            Box::pin(async move { r })
        }
    }

    fn params() -> ReporterParams {
        ReporterParams::default()
    }

    async fn settle_time() {
        // Let spawned work run under the paused clock.
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_repeats_with_jitter_and_stops_on_shutdown() {
        let fake = Fake::new(vec![]);
        let (tx, rx) = watch::channel(view(ConfigState::None));
        let (stop_tx, stop_rx) = watch::channel(false);
        let f2 = fake.clone();
        let task = tokio::spawn(async move {
            let mut stop_rx = stop_rx;
            run_status_reporter(
                &f2,
                Reporter::new("px-1", &uid(5), GapQueue::new(), params()),
                rx,
                async move {
                    let _ = stop_rx.wait_for(|v| *v).await;
                },
            )
            .await;
        });
        settle_time().await;
        assert_eq!(fake.count(), 0, "first report waits for a heartbeat");
        tokio::time::sleep(Duration::from_secs(23)).await;
        assert_eq!(fake.count(), 0, "heartbeat jitter is at least 24 s");
        tokio::time::sleep(Duration::from_secs(14)).await;
        assert!(fake.count() >= 1);
        // unreachable server: backoff from 5 s, never faster than min spacing
        tokio::time::sleep(Duration::from_secs(60)).await;
        let n = fake.count();
        assert!((2..=8).contains(&n), "{n}");
        let times: Vec<Instant> = fake.sent.lock().unwrap().iter().map(|s| s.0).collect();
        assert!(times
            .windows(2)
            .all(|w| w[1] - w[0] >= Duration::from_secs(1)));
        drop(tx);
        let _ = stop_tx.send(true);
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn config_change_is_reported_promptly_after_a_healthy_answer() {
        let ok = reply(
            200,
            json!({"state_applied": true, "acknowledged_gap_ids": [], "duplicate_gap_ids": []}),
        );
        let fake = Fake::new(vec![ok.clone(), ok.clone(), ok]);
        let (tx, rx) = watch::channel(view(ConfigState::None));
        let (stop_tx, stop_rx) = watch::channel(false);
        let f2 = fake.clone();
        let task = tokio::spawn(async move {
            let mut stop_rx = stop_rx;
            run_status_reporter(
                &f2,
                Reporter::new("px-1", &uid(5), GapQueue::new(), params()),
                rx,
                async move {
                    let _ = stop_rx.wait_for(|v| *v).await;
                },
            )
            .await;
        });
        // The first apply result moves the first report forward.
        tx.send(view(ConfigState::Valid)).unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(fake.count(), 1);
        let first = sigil_proxy_api::parse_status(&fake.sent.lock().unwrap()[0].1).unwrap();
        assert_eq!(first.config.state, ConfigState::Valid);
        // A later change goes out within about a second, not a heartbeat later.
        let mut v = view(ConfigState::Valid);
        v.last_update_error = Some(LastUpdateError::StaleRevision);
        tx.send(v).unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(fake.count(), 2);
        let second = sigil_proxy_api::parse_status(&fake.sent.lock().unwrap()[1].1).unwrap();
        assert_eq!(
            second.config.last_update_error,
            Some(LastUpdateError::StaleRevision)
        );
        assert!(second.status_sequence.get() > first.status_sequence.get());
        let _ = stop_tx.send(true);
        task.await.unwrap();
    }

    /// A rejection backs off to the maximum; a config change does not make it hot.
    #[tokio::test(start_paused = true)]
    async fn rejection_is_not_retried_hot() {
        let rej = reply(403, err("disabled", json!([])));
        let fake = Fake::new(vec![rej.clone(), rej.clone(), rej]);
        let (tx, rx) = watch::channel(view(ConfigState::None));
        let (stop_tx, stop_rx) = watch::channel(false);
        let f2 = fake.clone();
        let task = tokio::spawn(async move {
            let mut stop_rx = stop_rx;
            run_status_reporter(
                &f2,
                Reporter::new("px-1", &uid(5), GapQueue::new(), params()),
                rx,
                async move {
                    let _ = stop_rx.wait_for(|v| *v).await;
                },
            )
            .await;
        });
        tx.send(view(ConfigState::Valid)).unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(fake.count(), 1);
        let mut v = view(ConfigState::Valid);
        v.last_update_error = Some(LastUpdateError::FetchFailed);
        tx.send(v).unwrap();
        tokio::time::sleep(Duration::from_secs(200)).await;
        assert_eq!(fake.count(), 1, "no retry within the maximum backoff");
        tokio::time::sleep(Duration::from_secs(200)).await;
        assert_eq!(fake.count(), 2);
        let _ = stop_tx.send(true);
        task.await.unwrap();
    }

    /// Locally disabled: nothing is sent, and the local state is not touched by
    /// the (never-made) report.
    #[tokio::test(start_paused = true)]
    async fn locally_disabled_sends_nothing() {
        let fake = Fake::new(vec![]);
        let mut r = Reporter::new("px-1", &uid(5), GapQueue::new(), params());
        assert!(r
            .send_once(&fake, &view(ConfigState::Disabled))
            .await
            .is_none());
        assert_eq!(fake.count(), 0);
        assert!(r.send_once(&fake, &view(ConfigState::None)).await.is_some());
        assert_eq!(fake.count(), 1);
    }

    /// End to end through the reporter: storage_limit keeps only refused gaps and
    /// the next report carries only them.
    #[tokio::test(start_paused = true)]
    async fn storage_limit_then_resend_only_refused() {
        let q = GapQueue::new();
        for n in 1..=3 {
            q.push(quarantine_gap(n)).unwrap();
        }
        let fake = Fake::new(vec![
            reply(
                503,
                err(
                    "storage_limit",
                    json!([{"index": 2, "gap_id": uid(3), "code": "storage_limit"}]),
                ),
            ),
            reply(
                200,
                json!({"state_applied": true, "acknowledged_gap_ids": [uid(3)], "duplicate_gap_ids": []}),
            ),
        ]);
        let mut r = Reporter::new("px-1", &uid(5), q.clone(), params());
        let v = view(ConfigState::None);
        let o = r.send_once(&fake, &v).await.unwrap();
        assert!(matches!(o, ReportOutcome::StorageLimit { .. }));
        assert_eq!(q.pending_ids(), ids(&[3]));
        let o = r.send_once(&fake, &v).await.unwrap();
        assert!(matches!(o, ReportOutcome::Accepted { .. }));
        assert!(q.pending_ids().is_empty());
        let sent = fake.sent.lock().unwrap();
        let first = sigil_proxy_api::parse_status(&sent[0].1).unwrap();
        let second = sigil_proxy_api::parse_status(&sent[1].1).unwrap();
        assert_eq!(first.gaps.len(), 3);
        assert_eq!(second.gaps.len(), 1);
        // no central_outage gap was opened by the refusal
        assert!(second
            .gaps
            .iter()
            .all(|g| !matches!(g, GapReport::CentralOutage(_))));
    }

    #[test]
    fn debug_of_a_reply_hides_the_body() {
        let r = StatusReply {
            status: 200,
            body: b"SECRET-BODY".to_vec(),
        };
        assert!(!format!("{r:?}").contains("SECRET"));
    }
}
