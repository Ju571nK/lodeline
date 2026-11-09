//! The proxy read bodies, `GET /v1/proxies`, `GET /v1/proxies/{id}`, `GET /v1/proxy-invocations`
//! and `GET /v1/proxy-invocations/{id}`, as `lodeline-server`'s `proxy::query` sends them
//! (ledger-and-query.md L2 to L4), and a proxy's inventory views,
//! `GET /v1/proxies/{id}/{inventory-snapshots,drift,rebaseline-markers}`, as its
//! `proxy::inventory_query` sends them (registry.md R5, R7b).
//!
//! No Go console read these, so they keep the server's shape instead of Go's: a field the server
//! sends as `null` stays `null`, a field it leaves out stays out, and an enum value this build
//! does not know reads as `unknown`, so a newer server does not fail the page. The SPA renders
//! every string here as text. Status fields describe the proxy's last report, not live state.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::Raw;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Connected,
    Disconnected,
    NeverConnected,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigState {
    None,
    Valid,
    Expired,
    Disabled,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpoolState {
    Ok,
    Degraded,
    Full,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteState {
    Supported,
    Degraded,
    Unsupported,
    Disabled,
    #[serde(other)]
    Unknown,
}

/// Only a `sequence_gap` closes, and a closed gap stays listed (L4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapState {
    Open,
    Closed,
    #[serde(other)]
    Unknown,
}

/// `GET /v1/proxies`. `next_cursor` is opaque and bound to the endpoint and its filters.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProxiesPage {
    pub items: Vec<ProxySummary>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProxySummary {
    pub proxy_id: String,
    pub display_name: String,
    pub connection_state: ConnectionState,
    pub last_seen: Option<String>,
    pub desired_revision: Option<u64>,
    pub applied_revision: Option<i64>,
    pub config_in_sync: bool,
    pub config_state: ConfigState,
    pub config_expires_at: Option<String>,
    /// `null` until the proxy has sent a status report.
    pub spool: Option<Spool>,
    pub open_gap_count: i64,
    /// When the server applied the report the status fields come from.
    pub status_as_of: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Spool {
    pub state: SpoolState,
    pub depth_events: i64,
    pub unsent_events: i64,
    pub bytes: i64,
    pub capacity_bytes: i64,
    pub oldest_unsent_age_seconds: Option<i64>,
    pub quarantined_events: i64,
    /// `null` for a proxy that predates the field.
    pub quarantined_bytes: Option<i64>,
    pub as_of: Option<String>,
}

/// `GET /v1/proxies/{id}`. The server's `outages` and `counters` blocks are not read.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProxyDetail {
    #[serde(flatten)]
    pub summary: ProxySummary,
    pub registry: Option<Registry>,
    pub routes: Vec<RouteHealth>,
    pub central: Option<Central>,
    /// Open first, then newest first, at most 50; `audit_gaps_total` counts them all.
    pub audit_gaps: Vec<AuditGap>,
    pub audit_gaps_total: i64,
    /// Inventory gaps dropped at the per-proxy cap. Above zero, the gap list is incomplete.
    pub audit_gaps_dropped: i64,
    pub open_gap_counts: BTreeMap<String, i64>,
}

/// The three counters are left out by proxies that predate them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Registry {
    pub pending_entries: i64,
    pub sync_stalled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined_entries: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poisoned_entries: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discarded_reports: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Central {
    pub last_ingest_ack_at: Option<String>,
    pub consecutive_failures: i64,
    /// Sent only when true. While true the proxy reports its spool `degraded` even when storage
    /// is fine (L5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_stopped: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RouteHealth {
    pub upstream_id: String,
    pub state: RouteState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One L4 gap. `details` holds identifiers and counts only, by kind, and passes through as the
/// server wrote it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditGap {
    pub gap_id: String,
    pub kind: String,
    pub source: String,
    pub detected_at: String,
    pub state: GapState,
    pub details: Raw,
}

/// L2 `lifecycle`. Only `completed` carries a corroborated outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Started,
    Completed,
    CompletionWithoutStart,
    CancelWithoutStart,
    IntegrityConflict,
    #[serde(other)]
    Unknown,
}

/// A completion's outcome. `unknown` is also a value that proxies report, so a value this build
/// does not know reads as that same `unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    ToolError,
    ProtocolError,
    Timeout,
    Denied,
    #[serde(other)]
    Unknown,
}

/// `GET /v1/proxy-invocations`, newest first. `next_cursor` is opaque and bound to the filters.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvocationsPage {
    pub items: Vec<InvocationSummary>,
    pub next_cursor: Option<String>,
}

/// One invocation as the server projects it from its events (L2). The server's reserved
/// `decision` is not read.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvocationSummary {
    pub invocation_id: String,
    pub proxy_id: String,
    pub lifecycle: Lifecycle,
    /// Set only when `lifecycle` is `completed`.
    pub outcome: Option<Outcome>,
    pub delivery_state: Option<String>,
    pub reason: Option<String>,
    /// What a completion claimed under `completion_without_start` or `integrity_conflict`. The
    /// proxy reported it and nothing corroborates it, so it is never a headline value.
    pub reported_outcome: Option<Outcome>,
    pub reported_delivery_state: Option<String>,
    pub reported_reason: Option<String>,
    pub duration_ms: Option<i64>,
    pub response_bytes: Option<i64>,
    pub method: Option<String>,
    pub protocol_version: Option<String>,
    pub upstream_id: Option<String>,
    pub route_revision: Option<i64>,
    pub actor: Option<Actor>,
    pub tool: Option<Tool>,
    pub cancel_observed: bool,
    /// Proxy clock, unverified.
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    /// Server clock.
    pub first_received_at: String,
    pub last_received_at: String,
    pub start_epoch_id: Option<String>,
    pub epoch_superseded: bool,
    pub flags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Actor {
    pub actor_id: String,
    pub actor_kind: String,
    pub authentication_method: String,
    pub evidence_source: String,
    /// Who owns the credential's permissions, not who ran the call.
    pub credential_owner_id: Option<String>,
}

/// The start's tool binding: a metadata reference or why there is none, never a tool name.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Tool {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `GET /v1/proxy-invocations/{id}`: the summary plus the first 32 event envelopes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvocationDetail {
    #[serde(flatten)]
    pub invocation: InvocationSummary,
    pub events_total: i64,
    /// True when more events exist than `events` lists.
    pub events_truncated: bool,
    pub events: Vec<InvocationEvent>,
}

/// Envelope identifiers only; the server never returns a payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvocationEvent {
    pub event_type: String,
    pub event_id: String,
    pub epoch_id: String,
    pub sequence: i64,
    /// Proxy clock, unverified.
    pub occurred_at: String,
    pub received_at: String,
}

/// One of a proxy's three inventory read views.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InventoryView {
    Snapshots,
    Drift,
    Markers,
}

impl InventoryView {
    /// The path segment under `/v1/proxies/{id}/`, which the console's route uses too.
    pub fn segment(self) -> &'static str {
        match self {
            Self::Snapshots => "inventory-snapshots",
            Self::Drift => "drift",
            Self::Markers => "rebaseline-markers",
        }
    }
}

/// The chain an inventory row belongs to. A different credential scope or protocol version is a
/// separate chain, never compared with this one (R5 rule 4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InventoryScope {
    pub proxy_id: String,
    pub upstream_id: String,
    pub credential_scope_id: String,
    pub protocol_version: String,
    pub observation_source: String,
}

/// R7b `comparison_state`. Only `compared` has drift records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonState {
    /// An initial or a restated baseline.
    Baseline,
    Compared,
    Rebaseline,
    /// The previous snapshot has not arrived; no drift is shown yet.
    PendingPrevious,
    /// The deferred checks failed; no drift.
    Inconsistent,
    #[serde(other)]
    Unknown,
}

/// A complete observation of an upstream's tool list. An incomplete one is never a snapshot: the
/// server lists it as an `inventory_incomplete` gap on the proxy detail.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InventorySnapshot {
    pub inventory_id: String,
    #[serde(flatten)]
    pub scope: InventoryScope,
    pub canon: String,
    pub key_id: String,
    pub member_count: i64,
    /// Proxy clock, as the report wrote it.
    pub observed_at: String,
    pub received_at: String,
    pub is_latest: bool,
    pub is_first_baseline: bool,
    pub comparison_state: ComparisonState,
    /// Set only while `pending_previous`.
    pub awaiting_inventory_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftChange {
    Added,
    Removed,
    Changed,
    #[serde(other)]
    Unknown,
}

/// One change between two snapshots of a chain, by metadata reference. It records what the proxy
/// observed; nothing reviewed or approved it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DriftRecord {
    pub drift_id: String,
    pub inventory_id: String,
    pub previous_inventory_id: String,
    #[serde(flatten)]
    pub scope: InventoryScope,
    pub change: DriftChange,
    pub metadata_ref: String,
    /// Sent only for `changed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_metadata_ref: Option<String>,
    pub detected_at: String,
}

/// Why a chain's comparison domain restarted (R5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkerCause {
    DeclaredKeyRotation,
    DeclaredCanonChange,
    EpochChangeDetected,
    KeyChangeUndeclared,
    BaselineRestated,
    #[serde(other)]
    Unknown,
}

/// A baseline reset inside a chain. It never creates drift records.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RebaselineMarker {
    pub marker_id: String,
    #[serde(flatten)]
    pub scope: InventoryScope,
    pub inventory_id: String,
    pub previous_inventory_id: Option<String>,
    pub from_key_id: String,
    pub to_key_id: String,
    pub from_canon: String,
    pub to_canon: String,
    pub cause: MarkerCause,
    pub links_present: bool,
    pub drift_computed: bool,
    pub detected_at: String,
}

/// An inventory view, newest commit first. `next_cursor` is opaque and bound to the view, the
/// proxy and the filters.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InventoryPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}
