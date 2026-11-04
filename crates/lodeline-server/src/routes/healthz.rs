//! GET /v1/healthz — liveness probe. No auth.
use axum::{response::IntoResponse, Json};
use lodeline_fleet_api::Healthz;
use time::OffsetDateTime;

pub async fn get_healthz() -> impl IntoResponse {
    Json(Healthz {
        status: "ok".into(),
        ts: super::rfc3339(OffsetDateTime::now_utc()),
    })
}
