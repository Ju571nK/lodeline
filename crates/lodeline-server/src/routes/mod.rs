//! Route handlers for the read API.

pub mod artifacts;
pub mod enroll;
pub mod events;
pub mod fleet_compliance;
pub mod fleet_hosts;
pub mod fleet_risk;
pub mod healthz;
pub mod meta;
pub mod policy_meta;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use lodeline_fleet_api::{ErrorBody, RiskSource};

/// An error response in the read API's shape, `{"error": {"code", "message"}}`.
pub(crate) fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(ErrorBody::new(code, message))).into_response()
}

/// The serde wire string of a unit enum variant, such as `claude_code` for
/// `AiTool::ClaudeCode` or `critical` for `AiGuardBucket::Critical`.
pub(crate) fn wire_str<T: serde::Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        other => unreachable!("not a unit enum variant: {other:?}"),
    }
}

/// RFC 3339, the timestamp form of every read API body.
pub(crate) fn rfc3339(ts: time::OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// The `source` object of a tool's reading in `current_risk`, `ai_guard` and
/// `/v1/fleet/risk`.
pub(crate) fn risk_source(e: &crate::fleet_index::RiskEntry) -> RiskSource {
    RiskSource {
        rule_pack_id: e.rule_pack_id.clone(),
        scope: serde_json::to_value(&e.scope).expect("scope serializes"),
        tool_label: e.tool_label.clone(),
        user: e.user.clone(),
    }
}
