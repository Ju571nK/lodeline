//! The proxy read bodies, `GET /v1/proxies` and `GET /v1/proxies/{id}`, as `lodeline-server`'s
//! `proxy::query` sends them (ledger-and-query.md L3 and L4).
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
    /// Newest first, at most 50; `audit_gaps_total` counts them all.
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
