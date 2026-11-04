//! GET /v1/meta — server build info + alerts default + fleet size + audit head.
//! Bearer auth.
use crate::app::SharedState;
use axum::{extract::State, response::IntoResponse, Json};
use lodeline_core::event::SCHEMA_VERSION;
use lodeline_fleet_api as api;
use time::{Duration, OffsetDateTime};

/// Canonical alert definition surfaced by `GET /v1/meta`. Extracted so the
/// counter side (`fleet_index_update::is_alert_evidence`) can be tested for
/// drift against it — see the sync test (issue #52).
pub(crate) fn alerts_definition_default() -> api::AlertsDefinition {
    let strings = |s: &[&str]| s.iter().map(|k| k.to_string()).collect();
    api::AlertsDefinition {
        evidence_kinds: strings(&["ai_guard_risk_assessed"]),
        ai_guard_buckets: strings(&["high", "critical"]),
        additional_kinds: strings(&[
            "ai_guard_toggle_drift",
            "policy_signature_invalid",
            "tls_failure",
            "host_id_fingerprint_drift",
            "agent_dying",
            "sender_lag_critical",
        ]),
    }
}

pub async fn get_meta(State(state): State<SharedState>) -> impl IntoResponse {
    let now = OffsetDateTime::now_utc();
    let window = Duration::days(state.active_window_days as i64);
    let active = state.fleet_index.active_host_count(now, window);

    let audit_head = state.audit_head.lock().unwrap().clone().map(|h| {
        let lodeline_core::audit::AuditHead {
            seq,
            hash,
            sig,
            pubkey_id,
        } = h;
        // `pubkey` must be the key that signed the head. The chain is
        // frozen, so it may have been signed by a key other than the one
        // this server holds now (regenerated key, chain moved between
        // installs). Report `pubkey` only when the ids match; otherwise
        // leave it out and let `pubkey_id` name the key to verify with
        // (#237).
        let pubkey = state
            .audit_key
            .as_ref()
            .filter(|k| k.pubkey_id == pubkey_id)
            .map(|k| format!("ed25519:{}", k.pubkey_b64));
        api::AuditHead {
            hash,
            pubkey,
            pubkey_id,
            seq,
            sig,
        }
    });

    Json(api::Meta {
        alerts_definition_default: alerts_definition_default(),
        audit_head,
        fleet: Some(api::FleetSize {
            active_host_count: active,
            active_window_days: state.active_window_days,
        }),
        schema_version: SCHEMA_VERSION,
        server_version: env!("CARGO_PKG_VERSION").into(),
        ts: super::rfc3339(now),
    })
}
