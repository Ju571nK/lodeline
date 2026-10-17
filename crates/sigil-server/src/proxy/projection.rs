//! T-11 S5 slice A — the invocation projection (pure function) and the plain
//! Rust shapes the ledger read API returns.
//!
//! Spec: ledger-and-query.md L2 (projection), L3 (filters, keyset order), L4.
//! PX-006/010/011/012/016, AC-05/06/12.
//!
//! [`project`] is a pure function of the *set* of accepted events of one
//! invocation: arrival order, resends (an equal `event_id` collapses) and the
//! order of the input slice never change the result. Contradictions between
//! events are flagged, never rejected or repaired (L2 P-1..P-7, C-1..C-3).
//! `decision` is reserved and always `None` in P1.
//!
//! Nothing here carries arguments, results, tool names, session ids or tokens
//! (PX-010): only closed vocabularies, identifiers and counts.
//!
//! `epoch_superseded` is **not** a function of the invocation's own events (it
//! depends on a later epoch announcement), so [`project`] always yields `false`
//! and the ledger fills it at read time from the `epochs` table. Storing it
//! would leave the stored value stale the moment a newer epoch arrives.

use serde::Serialize;
use sigil_proxy_api::event::{
    CompletionReason, DeliveryState, Method, Outcome, ProtocolVersion, Tool,
};
use sigil_proxy_api::{EventPayload, InvocationCompleted, InvocationStarted, ProxyEvent};
use std::collections::BTreeMap;

/// One accepted event as the projection sees it.
#[derive(Clone, Debug)]
pub struct ProjectionInput {
    pub event: ProxyEvent,
    /// Ledger commit counter of the event row.
    pub created_seq: i64,
    /// Server clock (unix seconds) at acceptance.
    pub received_at: i64,
}

/// Fixed flag codes (L2). Declared in alphabetical order so the derived `Ord`
/// equals the sorted wire order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flag {
    CompletionContradictsStart,
    DuplicateCompletion,
    DuplicateStart,
    /// The invocation has more than [`MAX_PROJECTION_EVENTS`] events; only the
    /// first ones (by `created_seq`) were considered.
    EventLimit,
    StartBindingConflict,
}

impl Flag {
    pub fn as_str(self) -> &'static str {
        match self {
            Flag::CompletionContradictsStart => "completion_contradicts_start",
            Flag::DuplicateCompletion => "duplicate_completion",
            Flag::DuplicateStart => "duplicate_start",
            Flag::EventLimit => "event_limit",
            Flag::StartBindingConflict => "start_binding_conflict",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Flag::CompletionContradictsStart,
            Flag::DuplicateCompletion,
            Flag::DuplicateStart,
            Flag::EventLimit,
            Flag::StartBindingConflict,
        ]
        .into_iter()
        .find(|f| f.as_str() == s)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Lifecycle {
    Started,
    Completed,
    CompletionWithoutStart,
    CancelWithoutStart,
    IntegrityConflict,
}

impl Lifecycle {
    pub fn as_str(self) -> &'static str {
        match self {
            Lifecycle::Started => "started",
            Lifecycle::Completed => "completed",
            Lifecycle::CompletionWithoutStart => "completion_without_start",
            Lifecycle::CancelWithoutStart => "cancel_without_start",
            Lifecycle::IntegrityConflict => "integrity_conflict",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Lifecycle::Started,
            Lifecycle::Completed,
            Lifecycle::CompletionWithoutStart,
            Lifecycle::CancelWithoutStart,
            Lifecycle::IntegrityConflict,
        ]
        .into_iter()
        .find(|l| l.as_str() == s)
    }
}

/// Tool binding of a start. Never a name (PX-010).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolInfo {
    Identified { metadata_ref: String },
    MetadataUnavailable { reason: String },
    Unavailable { reason: String },
}

/// Actor of the start. `credential_owner_id` is a permission owner, not an
/// executor (README N3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorInfo {
    pub actor_id: String,
    pub actor_kind: String,
    pub authentication_method: String,
    pub evidence_source: String,
    pub credential_owner_id: Option<String>,
}

/// The stored/returned invocation record (L2 fields plus `created_seq`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Projection {
    pub proxy_id: String,
    pub invocation_id: String,
    /// Commit counter of the invocation's first accepted event; the immutable
    /// keyset order key of the list (L3).
    pub created_seq: i64,
    pub lifecycle: Lifecycle,
    /// Set only when `lifecycle == Completed`.
    pub outcome: Option<String>,
    pub delivery_state: Option<String>,
    pub reason: Option<String>,
    /// What a completion claimed under `integrity_conflict` or
    /// `completion_without_start`. Uncorroborated; never matched by filters.
    pub reported_outcome: Option<String>,
    pub reported_delivery_state: Option<String>,
    pub reported_reason: Option<String>,
    pub duration_ms: Option<i64>,
    pub response_bytes: Option<i64>,
    pub method: Option<String>,
    pub protocol_version: Option<String>,
    pub upstream_id: Option<String>,
    pub route_revision: Option<i64>,
    pub actor: Option<ActorInfo>,
    pub tool: Option<ToolInfo>,
    pub cancel_observed: bool,
    /// Reserved (P1 has no decision event). Always `None`.
    pub decision: Option<String>,
    /// Proxy clock, unverified: verbatim text and parsed unix seconds.
    pub started_at: Option<String>,
    pub started_at_s: Option<i64>,
    pub completed_at: Option<String>,
    pub completed_at_s: Option<i64>,
    pub first_received_at: i64,
    pub last_received_at: i64,
    pub start_epoch_id: Option<String>,
    /// Filled by the ledger read path; `project` yields `false` (see module doc).
    pub epoch_superseded: bool,
    /// Sorted, fixed codes.
    pub flags: Vec<Flag>,
    pub event_count: i64,
}

fn wire<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

/// Unix seconds of an RFC 3339 timestamp, `None` if it does not parse.
pub fn timestamp_secs(s: &str) -> Option<i64> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

/// C-1 and C-2 for one `(start, completion)` pair. C-3 holds by construction
/// (a reference is only ever copied from an `identified` tool).
fn contradicts(start: &InvocationStarted, c: &InvocationCompleted) -> bool {
    if matches!(start.tool, Some(Tool::Unavailable(_)))
        && !(matches!(c.outcome, Outcome::ProtocolError | Outcome::Denied)
            && c.delivery_state == DeliveryState::NotSent)
    {
        return true;
    }
    match c.reason {
        Some(
            CompletionReason::UpstreamCapabilityUnsupported
            | CompletionReason::UpstreamVersionUnsupported
            | CompletionReason::UpstreamInitializeUnreadable,
        ) => start.method != Method::Initialize,
        Some(CompletionReason::ModernRequestUnsupported) => {
            !(start.method == Method::Unknown && start.protocol_version == ProtocolVersion::Unknown)
        }
        Some(CompletionReason::TaskAugmentationUnsupported) => match c.delivery_state {
            DeliveryState::NotSent => start.method != Method::Unknown,
            DeliveryState::Sent => start.method != Method::ToolsCall,
            DeliveryState::Unknown => false,
        },
        _ => false,
    }
}

type Entry<'a, T> = (&'a ProjectionInput, &'a T);

/// Representative of a group: the lowest `(occurred_at, event_id)`. A pure
/// function of the set, so it does not depend on arrival order.
fn rep<'a, T>(items: &[Entry<'a, T>]) -> Option<Entry<'a, T>> {
    items.iter().copied().min_by(|a, b| {
        let ka = (a.0.event.occurred_at.as_str(), a.0.event.event_id.as_str());
        let kb = (b.0.event.occurred_at.as_str(), b.0.event.event_id.as_str());
        ka.cmp(&kb)
    })
}

/// The L2 projection of one invocation's accepted events. `None` for an empty
/// input. All events are assumed to share `(proxy_id, invocation_id)`.
pub fn project(events: &[ProjectionInput]) -> Option<Projection> {
    project_limited(events, false)
}

/// Upper bound of events one projection is computed from (cost bound for the
/// per-batch recompute; a producer repeating one `invocation_id` must not make
/// every later batch more expensive). The ledger feeds the first
/// `MAX_PROJECTION_EVENTS` events by `created_seq` and sets `truncated`, which
/// adds the `event_limit` flag. Initial test value (D-04).
///
/// **Beyond the cap the result depends on arrival order**: which events are the
/// "first" ones is decided by `created_seq`. Within the cap it never does.
pub const MAX_PROJECTION_EVENTS: usize = 256;

/// Distinct payloads by content hash (SHA-256 of the payload JSON), so the
/// start x completion comparison runs over distinct contents only.
fn distinct<'a, T: Serialize>(items: &[Entry<'a, T>]) -> Vec<&'a T> {
    use sha2::{Digest, Sha256};
    let mut by_hash: BTreeMap<[u8; 32], &'a T> = BTreeMap::new();
    for (_, t) in items {
        let h: [u8; 32] = Sha256::digest(serde_json::to_vec(t).unwrap_or_default()).into();
        by_hash.entry(h).or_insert(t);
    }
    by_hash.into_values().collect()
}

/// [`project`] with the `truncated` marker set by the caller when more than
/// [`MAX_PROJECTION_EVENTS`] events exist and `events` holds only the first ones.
pub fn project_limited(events: &[ProjectionInput], truncated: bool) -> Option<Projection> {
    // Collapse repeats of the same event_id (resend); keep the lowest created_seq.
    let mut by_id: BTreeMap<&str, &ProjectionInput> = BTreeMap::new();
    for e in events {
        by_id
            .entry(e.event.event_id.as_str())
            .and_modify(|cur| {
                if e.created_seq < cur.created_seq {
                    *cur = e;
                }
            })
            .or_insert(e);
    }
    let all: Vec<&ProjectionInput> = by_id.values().copied().collect();
    let first = *all.first()?;

    let mut starts: Vec<Entry<'_, InvocationStarted>> = Vec::new();
    let mut completions: Vec<Entry<'_, InvocationCompleted>> = Vec::new();
    let mut cancel_observed = false;
    for e in &all {
        match &e.event.payload {
            EventPayload::Started(s) => starts.push((e, s)),
            EventPayload::Completed(c) => completions.push((e, c)),
            EventPayload::CancelRequested(_) => cancel_observed = true,
        }
    }

    let mut flags = std::collections::BTreeSet::new();
    if truncated {
        flags.insert(Flag::EventLimit);
    }
    let mut conflict = false;
    let distinct_starts = distinct(&starts);
    let distinct_completions = distinct(&completions);
    if starts.len() > 1 {
        if distinct_starts.len() == 1 {
            flags.insert(Flag::DuplicateStart);
        } else {
            flags.insert(Flag::StartBindingConflict);
            conflict = true;
        }
    }
    if completions.len() > 1 {
        flags.insert(Flag::DuplicateCompletion);
        if distinct_completions.len() > 1 {
            conflict = true;
        }
    }
    if distinct_starts
        .iter()
        .any(|s| distinct_completions.iter().any(|c| contradicts(s, c)))
    {
        flags.insert(Flag::CompletionContradictsStart);
        conflict = true;
    }

    let start = rep(&starts);
    let completion = rep(&completions);
    let lifecycle = if conflict {
        Lifecycle::IntegrityConflict
    } else {
        match (start.is_some(), completion.is_some()) {
            (true, true) => Lifecycle::Completed,
            (true, false) => Lifecycle::Started,
            (false, true) => Lifecycle::CompletionWithoutStart,
            (false, false) => Lifecycle::CancelWithoutStart,
        }
    };

    let (mut outcome, mut delivery_state, mut reason) = (None, None, None);
    let (mut r_outcome, mut r_delivery, mut r_reason) = (None, None, None);
    if let Some((_, c)) = completion {
        let o = Some(wire(&c.outcome));
        let d = Some(wire(&c.delivery_state));
        let r = c.reason.as_ref().map(wire);
        if lifecycle == Lifecycle::Completed {
            (outcome, delivery_state, reason) = (o, d, r);
        } else {
            (r_outcome, r_delivery, r_reason) = (o, d, r);
        }
    }

    let (mut method, mut protocol_version, mut upstream_id, mut route_revision) =
        (None, None, None, None);
    let (mut actor, mut tool) = (None, None);
    let (mut started_at, mut started_at_s, mut start_epoch_id) = (None, None, None);
    if let Some((e, s)) = start {
        method = Some(wire(&s.method));
        protocol_version = Some(wire(&s.protocol_version));
        upstream_id = Some(s.upstream_id.as_str().to_string());
        route_revision = Some(s.route_revision.get());
        actor = Some(ActorInfo {
            actor_id: s.actor.actor_id.as_str().to_string(),
            actor_kind: wire(&s.actor.actor_kind),
            authentication_method: wire(&s.actor.authentication_method),
            evidence_source: wire(&s.actor.evidence_source),
            credential_owner_id: s
                .actor
                .credential_owner_id
                .as_ref()
                .map(|i| i.as_str().to_string()),
        });
        tool = s.tool.as_ref().map(|t| match t {
            Tool::Identified(i) => ToolInfo::Identified {
                metadata_ref: i.metadata_ref.as_str().to_string(),
            },
            Tool::MetadataUnavailable(m) => ToolInfo::MetadataUnavailable {
                reason: wire(&m.reason),
            },
            Tool::Unavailable(u) => ToolInfo::Unavailable {
                reason: wire(&u.reason),
            },
        });
        started_at = Some(e.event.occurred_at.as_str().to_string());
        started_at_s = timestamp_secs(e.event.occurred_at.as_str());
        start_epoch_id = Some(e.event.epoch_id.as_str().to_string());
    }
    let (mut completed_at, mut completed_at_s, mut duration_ms, mut response_bytes) =
        (None, None, None, None);
    if let Some((e, c)) = completion {
        completed_at = Some(e.event.occurred_at.as_str().to_string());
        completed_at_s = timestamp_secs(e.event.occurred_at.as_str());
        duration_ms = Some(c.duration_ms.get());
        response_bytes = Some(c.response_bytes.get());
    }

    Some(Projection {
        proxy_id: first.event.proxy_id.as_str().to_string(),
        invocation_id: first.event.payload.invocation_id().as_str().to_string(),
        created_seq: all.iter().map(|e| e.created_seq).min().unwrap_or(0),
        lifecycle,
        outcome,
        delivery_state,
        reason,
        reported_outcome: r_outcome,
        reported_delivery_state: r_delivery,
        reported_reason: r_reason,
        duration_ms,
        response_bytes,
        method,
        protocol_version,
        upstream_id,
        route_revision,
        actor,
        tool,
        cancel_observed,
        decision: None,
        started_at,
        started_at_s,
        completed_at,
        completed_at_s,
        first_received_at: all.iter().map(|e| e.received_at).min().unwrap_or(0),
        last_received_at: all.iter().map(|e| e.received_at).max().unwrap_or(0),
        start_epoch_id,
        epoch_superseded: false,
        flags: flags.into_iter().collect(),
        event_count: all.len() as i64,
    })
}

// ---------------------------------------------------------------------------
// Read API shapes (plain Rust; the query slice builds the HTTP DTOs).
// ---------------------------------------------------------------------------

/// Which clock `from`/`to` filter (L3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TimeBasis {
    /// Server `first_received_at` (default).
    #[default]
    Received,
    /// Proxy `started_at`, else `completed_at` (unverified).
    Occurred,
}

/// L3 invocation list filters, combined with AND. `from`/`to` are unix seconds,
/// half-open `[from, to)`. `outcome` matches only `lifecycle = completed`
/// records (the stored `outcome` is `NULL` otherwise).
#[derive(Clone, Debug, Default)]
pub struct InvocationFilter {
    /// Caller's `proxy.read` range, bound as `proxy_id IN (...)`. `None` = no
    /// restriction; `Some(empty)` = no rows. Combines (AND) with `proxy_id`.
    pub allowed_proxies: Option<Vec<String>>,
    pub proxy_id: Option<String>,
    pub upstream_id: Option<String>,
    pub actor_id: Option<String>,
    pub method: Option<String>,
    pub outcome: Option<String>,
    pub lifecycle: Option<Lifecycle>,
    pub tool_ref: Option<String>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub time_basis: TimeBasis,
}

/// Hard cap of `list_invocations` (L3).
pub const MAX_LIST_LIMIT: usize = 500;
/// Events returned by `get_invocation` (L3).
pub const MAX_DETAIL_EVENTS: usize = 32;
/// Gaps returned by `gaps_page` (L3).
pub const MAX_GAP_PAGE: usize = 50;

/// One page, newest first. `next_key` is the `created_seq` to pass as
/// `after_key` for the next page; `None` on the last page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationPage {
    pub items: Vec<Projection>,
    pub next_key: Option<i64>,
}

/// Envelope identifiers of one constituent event. Never payload content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventIdentity {
    pub created_seq: i64,
    pub event_type: String,
    pub event_id: String,
    pub epoch_id: String,
    pub sequence: i64,
    pub occurred_at: String,
    pub received_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationDetail {
    pub invocation: Projection,
    /// At most [`MAX_DETAIL_EVENTS`], ordered by `created_seq`.
    pub events: Vec<EventIdentity>,
    pub events_total: i64,
    pub events_truncated: bool,
}

/// Newest-first server-derived gaps plus the total.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GapPage {
    pub items: Vec<crate::proxy::ledger::GapRecord>,
    pub total: i64,
}

/// Result of [`crate::proxy::ledger::Ledger::note_last_assigned`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailGapChange {
    /// `last_assigned_sequence` is not above the highest stored sequence, or an
    /// open tail gap already covers it.
    Unchanged,
    Created,
    Extended,
}
