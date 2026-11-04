//! GET /v1/policy/meta — lightweight policy metadata (no full envelope).
//! Reads policy_bundle_path and extracts version + signing fields without
//! re-validating the signature. Auth: bearer.
use super::error_response;
use crate::app::SharedState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use lodeline_fleet_api::PolicyMeta;
use serde_json::Value;

pub async fn get_policy_meta(State(state): State<SharedState>) -> impl IntoResponse {
    let bytes = match std::fs::read(&state.policy_bundle_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "no policy bundle on disk",
            );
        }
        Err(e) => {
            tracing::error!(error = ?e, "read policy bundle failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "bundle read failed",
            );
        }
    };
    let v: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "bundle parse failed",
            );
        }
    };
    let field = |k: &str| v.get(k).cloned().unwrap_or(Value::Null);
    Json(PolicyMeta {
        policy_version: field("policy_version"),
        signed_at: field("signed_at"),
        signing_pubkey_id: field("signing_pubkey_id"),
        valid_until: field("valid_until"),
    })
    .into_response()
}
