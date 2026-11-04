//! GET /v1/events — list (paged JSONL scan)
//! GET /v1/events/{event_id} — single event lookup via UUIDv7 timestamp

use super::error_response;
use crate::app::SharedState;
use crate::jsonl_scan::{find_by_id, scan, ScanFilters};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use lodeline_fleet_api::{EventsPage, EventsQuery};
use uuid::Uuid;

fn parse_rfc3339(s: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}

fn comma_split(s: &Option<String>) -> Option<Vec<String>> {
    s.as_ref()
        .map(|v| v.split(',').map(|p| p.trim().to_string()).collect())
}

pub async fn get_events(
    State(state): State<SharedState>,
    Query(q): Query<EventsQuery>,
) -> impl IntoResponse {
    let cursor = match q.cursor.as_deref() {
        None => None,
        Some(c) => match Uuid::parse_str(c) {
            Ok(u) => Some(u),
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_query",
                    "cursor must be a UUID",
                )
            }
        },
    };
    let since = match q.since.as_deref().map(parse_rfc3339) {
        Some(None) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                "since must be RFC 3339",
            )
        }
        x => x.flatten(),
    };
    let until = match q.until.as_deref().map(parse_rfc3339) {
        Some(None) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                "until must be RFC 3339",
            )
        }
        x => x.flatten(),
    };
    let limit = q.limit.unwrap_or(100).clamp(1, 1000) as usize;

    let filters = ScanFilters {
        cursor,
        host_ids: comma_split(&q.host_id),
        since,
        until,
        evidence_kinds: comma_split(&q.evidence_kind),
        severity: comma_split(&q.severity),
        source: comma_split(&q.source),
        min_ai_guard_bucket: q.min_ai_guard_bucket.clone(),
        limit,
    };
    let r = match scan(&state.events_out_dir, &filters) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, "scan failed");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal", "scan failed");
        }
    };
    Json(EventsPage {
        events: r.events,
        next_cursor: r.next_cursor.map(|u| u.to_string()),
    })
    .into_response()
}

pub async fn get_event_by_id(
    State(state): State<SharedState>,
    Path(event_id): Path<String>,
) -> impl IntoResponse {
    let uid = match Uuid::parse_str(&event_id) {
        Ok(u) => u,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                "event_id must be a UUID",
            )
        }
    };
    match find_by_id(&state.events_out_dir, uid) {
        Ok(Some(v)) => Json(v).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "not_found", "event_id not found"),
        Err(e) => {
            tracing::error!(error = ?e, "find_by_id failed");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "lookup failed",
            )
        }
    }
}
