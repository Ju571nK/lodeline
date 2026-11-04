//! The `/api/v1/triage/*` handlers (Go's `internal/api/v1/triage.go`). The actor and note
//! author are the session subject, exactly as the session check passed it on.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Extension;

use crate::api::{field, go_object, read_body, set, write_json, TRIAGE_BODY_LIMIT};
use crate::auth::{go_fold, Subject};
use crate::server::{error_response, AppState};
use crate::triage::{self, Error, Store, Upsert};

pub async fn upsert(
    State(s): State<AppState>,
    Extension(Subject(actor)): Extension<Subject>,
    req: Request,
) -> Response {
    let body = match read_body(req, TRIAGE_BODY_LIMIT).await {
        Ok(body) => body.and_then(|b| upsert_body(&b)),
        Err(e) => return e.into_response(),
    };
    let Some(body) = body else {
        return malformed();
    };
    if body.host_id.is_empty() || body.event_id.is_empty() {
        return invalid("host_id and event_id are required");
    }
    if !body.status.is_empty() && !triage::STATUSES.contains(&body.status.as_str()) {
        return invalid("status must be one of: open, acknowledged, investigating, resolved");
    }
    let input = Upsert { actor, ..body };
    blocking(s.triage, move |t| t.upsert(input, triage::now)).await
}

pub async fn note(
    State(s): State<AppState>,
    Extension(Subject(author)): Extension<Subject>,
    req: Request,
) -> Response {
    let body = match read_body(req, TRIAGE_BODY_LIMIT).await {
        Ok(body) => body.and_then(|b| note_body(&b)),
        Err(e) => return e.into_response(),
    };
    let Some(body) = body else {
        return malformed();
    };
    if body.host_id.is_empty() || body.event_id.is_empty() || body.body.is_empty() {
        return invalid("host_id, event_id, body are required");
    }
    blocking(s.triage, move |t| {
        t.append_note(
            &body.host_id,
            &body.event_id,
            &author,
            &body.body,
            triage::now,
        )
    })
    .await
}

pub async fn get(State(s): State<AppState>, uri: Uri) -> Response {
    let (host_id, event_id) = path_params(uri.path());
    if host_id.is_empty() || event_id.is_empty() {
        return invalid("host_id and event_id required");
    }
    blocking(s.triage, move |t| t.get(&host_id, &event_id)).await
}

/// Runs a store call off the async runtime and writes its answer as Go's `mapTriageErr` does.
async fn blocking<T, F>(store: Arc<Store>, f: F) -> Response
where
    T: serde::Serialize + Send + 'static,
    F: FnOnce(&Store) -> Result<T, Error> + Send + 'static,
{
    let result = tokio::task::spawn_blocking(move || f(&store))
        .await
        .expect("triage store call panicked");
    match result {
        Ok(v) => write_json(&v),
        Err(Error::NotFound) => {
            error_response(StatusCode::NOT_FOUND, "not_found", "triage row not found")
        }
        Err(e @ (Error::InvalidStatus(_) | Error::MissingFields(_))) => invalid(&e.to_string()),
        Err(e @ Error::Db(_)) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &e.to_string(),
        ),
    }
}

fn invalid(msg: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, "invalid_query", msg)
}

fn malformed() -> Response {
    invalid("malformed JSON body")
}

#[derive(Default)]
struct NoteBody {
    host_id: String,
    event_id: String,
    body: String,
}

fn upsert_body(raw: &[u8]) -> Option<Upsert> {
    let mut b = Upsert::default();
    for (key, value) in go_object(raw)? {
        match go_fold(&key).as_str() {
            "host_id" => set(&mut b.host_id, &value)?,
            "event_id" => set(&mut b.event_id, &value)?,
            "status" => set(&mut b.status, &value)?,
            // A null pointer field is set to nil; null on any other field changes nothing.
            "assignee" => b.assignee = field(&value)?,
            "clear_assignee" => set(&mut b.clear_assignee, &value)?,
            // json.RawMessage keeps any value, `null` included, as its text.
            "evidence_snapshot" => b.evidence_snapshot = Some(value.get().to_owned()),
            _ => {}
        }
    }
    Some(b)
}

fn note_body(raw: &[u8]) -> Option<NoteBody> {
    let mut b = NoteBody::default();
    for (key, value) in go_object(raw)? {
        match go_fold(&key).as_str() {
            "host_id" => set(&mut b.host_id, &value)?,
            "event_id" => set(&mut b.event_id, &value)?,
            "body" => set(&mut b.body, &value)?,
            _ => {}
        }
    }
    Some(b)
}

/// `{host_id}` and `{event_id}`, the last two path segments, decoded as chi gives them.
fn path_params(raw: &str) -> (String, String) {
    let path = crate::api::fleet::route_path(raw);
    let mut segments = path.rsplit('/');
    let event_id = segments.next().unwrap_or_default().to_owned();
    let host_id = segments.next().unwrap_or_default().to_owned();
    (host_id, event_id)
}

#[cfg(test)]
mod tests;
