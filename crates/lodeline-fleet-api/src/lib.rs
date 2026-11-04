//! Wire types for the `lodeline-server` read API (`/v1/*`).
//!
//! `lodeline-server` and `lodeline-manager` (in `apps/manager`) both depend on
//! this crate, so a change to a response shape fails to compile in the same
//! commit on whichever side disagrees.
//!
//! A deployed server and manager can still run different versions, so every
//! type accepts unknown fields when deserializing, and fields added after the
//! first release are `Option`. Events, AI guard reasons and scopes stay raw
//! JSON: they are open sets that grow with `lodeline-core`, and a typed copy
//! would drop the payload of a kind it does not know.
//!
//! Struct fields are declared in alphabetical order. The routes used to build
//! their bodies with `serde_json::json!`, whose maps sort keys, so this order
//! keeps the bytes on the wire unchanged. Timestamps are RFC 3339 strings.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Every error response: `{"error": {"code", "message"}}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

impl ErrorBody {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            error: ErrorDetail {
                code: code.into(),
                message: message.into(),
            },
        }
    }
}

/// `GET /v1/healthz`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Healthz {
    pub status: String,
    pub ts: String,
}

/// `GET /v1/meta`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Meta {
    pub alerts_definition_default: AlertsDefinition,
    /// `null` when no audit chain exists.
    pub audit_head: Option<AuditHead>,
    /// Absent before v0.9.0, which reported `license` instead.
    pub fleet: Option<FleetSize>,
    pub schema_version: u32,
    pub server_version: String,
    pub ts: String,
}

/// The server's recommended alert set. Consumers tolerate kinds they do not
/// recognize.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AlertsDefinition {
    pub additional_kinds: Vec<String>,
    pub ai_guard_buckets: Vec<String>,
    pub evidence_kinds: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditHead {
    pub hash: String,
    /// `ed25519:<base64>`, present only when the server holds the key that
    /// signed the head. Otherwise `pubkey_id` names the key to verify with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    pub pubkey_id: String,
    pub seq: u64,
    pub sig: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FleetSize {
    pub active_host_count: u32,
    pub active_window_days: u32,
}

/// `GET /v1/policy/meta`. Each field is copied from the policy bundle on disk
/// without validation: whatever JSON the bundle holds under that key, or
/// `null` when the key is missing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyMeta {
    pub policy_version: Value,
    pub signed_at: Value,
    pub signing_pubkey_id: Value,
    pub valid_until: Value,
}

/// `GET /v1/fleet/hosts`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostsPage {
    pub hosts: Vec<HostListItem>,
    pub next_cursor: Option<String>,
    pub total_estimated: u64,
}

/// One row of `GET /v1/fleet/hosts`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostListItem {
    pub agent_version: String,
    /// `null` until the host reports an AI guard assessment.
    pub current_risk: Option<CurrentRisk>,
    pub host_id: String,
    pub hostname: Option<String>,
    pub last_seen_ts: Option<String>,
    pub open_event_counts_24h: EventCounts,
    /// `healthy`, `stale` or `disconnected`.
    pub status: String,
}

/// `GET /v1/fleet/hosts/{host_id}`: the list row plus the detail blocks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostDetail {
    pub agent_health: AgentHealth,
    pub agent_version: String,
    pub ai_guard: AiGuard,
    pub current_risk: Option<CurrentRisk>,
    pub host_id: String,
    /// `null` until the host reports a host meta snapshot.
    pub host_meta: Option<HostMeta>,
    pub hostname: Option<String>,
    pub last_seen_ts: Option<String>,
    pub open_event_counts_24h: EventCounts,
    pub policy_state: PolicyState,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventCounts {
    pub info: u32,
    pub warn: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CurrentRisk {
    /// Keyed by the tool's wire name, such as `claude_code`.
    pub by_tool: BTreeMap<String, ToolRisk>,
    pub max_bucket: String,
    pub max_score: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolRisk {
    pub assessed_ts: String,
    pub bucket: String,
    pub score: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentHealth {
    pub hash_p99_ms_latest: Option<u32>,
    pub jsonl_above_soft_floor_latest: Option<bool>,
    pub last_heartbeat_ts: Option<String>,
    pub recent_channel_stalls_24h: u32,
    pub recent_sender_lag_critical_24h: u32,
    pub recent_watcher_degraded_24h: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AiGuard {
    /// Keyed by the tool's wire name, such as `claude_code`.
    pub by_tool: BTreeMap<String, AiGuardAssessment>,
}

/// The riskiest current reading for one tool.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AiGuardAssessment {
    pub assessed_ts: String,
    pub bucket: String,
    /// Absent when the agent did not report controls, which older agents do
    /// not; an empty list means it looked and found none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controls: Option<Vec<AiGuardControl>>,
    pub is_reattestation: bool,
    pub reasons: Vec<Value>,
    pub scope: Value,
    pub score: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AiGuardControl {
    pub id: String,
    pub setting: String,
    pub source_path: String,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostMeta {
    pub architecture: Option<String>,
    pub default_gateway_v4: Option<String>,
    pub default_gateway_v6: Option<String>,
    pub dns_servers: Vec<String>,
    pub hostname: Option<String>,
    pub interfaces: Vec<NetworkInterface>,
    pub kernel_version: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub mac: Option<String>,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyState {
    pub last_applied_policy_version: i64,
    pub last_policy_reload_ts: Option<String>,
    pub policy_expired_active: bool,
}

/// `GET /v1/fleet/risk` and `GET /v1/fleet/compliance`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RowsPage<T> {
    pub next_cursor: Option<String>,
    pub rows: Vec<T>,
}

/// One host in `GET /v1/fleet/risk`, described by its riskiest tool.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RiskRow {
    pub assessed_ts: String,
    pub bucket: String,
    pub host_id: String,
    pub hostname: Option<String>,
    pub open_alert_count_24h: u32,
    pub reasons_count: u64,
    pub score: f64,
    pub top_tool: String,
}

/// One host in `GET /v1/fleet/compliance`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComplianceRow {
    pub host_id: String,
    pub hostname: Option<String>,
    pub last_applied_policy_version: i64,
    pub last_policy_reload_ts: Option<String>,
    pub policy_expired_active: bool,
    /// `null` when the server has no readable policy bundle.
    pub server_current_policy_version: Option<i64>,
    pub signature_failures_24h: u32,
    pub version_drift: i64,
}

/// `GET /v1/events`. Each event is the stored JSON, unchanged.
/// `GET /v1/events/{event_id}` returns one such event on its own.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventsPage {
    pub events: Vec<Value>,
    pub next_cursor: Option<String>,
}

/// Query of `GET /v1/fleet/hosts`. List filters are comma-separated.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HostsQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub status: Option<String>,
    pub bucket: Option<String>,
    pub sort: Option<String>,
}

/// Query of `GET /v1/fleet/risk`. `tool` is comma-separated.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RiskQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub tool: Option<String>,
    pub min_bucket: Option<String>,
}

/// Query of `GET /v1/fleet/compliance`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ComplianceQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

/// Query of `GET /v1/events`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EventsQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    // Comma-separated, like the other multi-value filters below. A
    // `Vec<String>` can't be deserialized by axum's serde_urlencoded `Query`
    // extractor (it reports "expected a sequence" even for a single value),
    // which is what broke the MCP `query_events` tool (#73).
    pub host_id: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub evidence_kind: Option<String>,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub min_ai_guard_bucket: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decoding_ignores_unknown_fields_and_accepts_missing_additive_ones() {
        // A 0.8 server: `license` instead of `fleet`, and a head whose key
        // the server does not hold.
        let meta: Meta = serde_json::from_value(json!({
            "alerts_definition_default": {"additional_kinds": [], "ai_guard_buckets": [],
                "evidence_kinds": [], "future_list": [1]},
            "audit_head": {"hash": "h", "pubkey_id": "k", "seq": 1, "sig": "s"},
            "license": {"state": "ok"},
            "schema_version": 1, "server_version": "0.8.0", "ts": "2026-01-01T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(meta.fleet, None);
        assert_eq!(meta.audit_head.unwrap().pubkey, None);

        let a: AiGuardAssessment = serde_json::from_value(json!({
            "assessed_ts": "2026-01-01T00:00:00Z", "bucket": "low", "is_reattestation": false,
            "reasons": [{"kind": "a_future_reason", "detail": 1}],
            "scope": {"kind": "a_future_scope"}, "score": 0.5, "a_future_field": true
        }))
        .unwrap();
        assert_eq!(a.controls, None);
        assert_eq!(
            a.reasons[0]["detail"], 1,
            "unknown reason kinds keep their payload"
        );
    }
}
