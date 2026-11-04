//! The `/api/v1` handlers, by area.

pub mod fleet;
pub mod triage;

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Go's `httputil.WriteJSON` with status 200. Go writes the status and `Content-Type` before it
/// encodes, so a body it cannot encode leaves an empty 200.
pub fn write_json<T: Serialize + ?Sized>(body: &T) -> Response {
    let body = serde_json::to_string(body)
        .map(|s| s + "\n")
        .unwrap_or_default();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}
