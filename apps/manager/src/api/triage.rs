//! The `/api/v1/triage/*` handlers (Go's `internal/api/v1/triage.go`). The actor and note
//! author are the session subject, exactly as the session check passed it on.

use std::pin::Pin;
use std::sync::Arc;

use axum::body::HttpBody;
use axum::extract::{Request, State};
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use axum::Extension;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;

use crate::api::write_json;
use crate::auth::{go_fold, Members, Subject};
use crate::server::{error_response, AppState};
use crate::triage::{self, Error, Store, Upsert};

pub async fn upsert(
    State(s): State<AppState>,
    Extension(Subject(actor)): Extension<Subject>,
    req: Request,
) -> Response {
    let Some(body) = read_body(req).await.and_then(|b| upsert_body(&b)) else {
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
    let Some(body) = read_body(req).await.and_then(|b| note_body(&b)) else {
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

/// Go's `maxNestingDepth`: a body may nest arrays and objects 10000 deep, and no deeper.
const MAX_DEPTH: usize = 10_000;

/// The body a frame at a time up to the end of its first JSON value, as Go's decoder reads it,
/// with no size limit. `None` when a read fails before the value ends or the value nests deeper
/// than Go allows.
async fn read_body(req: Request) -> Option<Vec<u8>> {
    let mut body = req.into_body();
    let (mut buf, mut scan) = (Vec::new(), Scan::default());
    while !scan.feed(&buf)? {
        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        let Some(frame) = frame else { break };
        if let Ok(data) = frame.ok()?.into_data() {
            buf.extend_from_slice(&data);
        }
    }
    Some(buf)
}

/// How much of a body's first JSON value has been read.
#[derive(Default)]
struct Scan {
    scanned: usize,
    first: Option<usize>,
    depth: usize,
    in_string: bool,
    escaped: bool,
}

impl Scan {
    /// Scans the bytes added since the last call: `true` once `buf` holds all that `go_object`
    /// reads, `None` once the value nests deeper than Go allows.
    fn feed(&mut self, buf: &[u8]) -> Option<bool> {
        for (i, &b) in buf.iter().enumerate().skip(self.scanned) {
            self.scanned = i + 1;
            if self.in_string {
                match (self.escaped, b) {
                    (true, _) => self.escaped = false,
                    (false, b'\\') => self.escaped = true,
                    (false, b'"') => self.in_string = false,
                    _ => {}
                }
                continue;
            }
            if self.first.is_none() && !json_space(b) {
                self.first = Some(i);
            }
            match (self.first, b) {
                // Not an object: four bytes tell `null` from a value Go rejects.
                (Some(f), _) if buf[f] != b'{' => return Some(buf.len() >= f + 4),
                (_, b'"') => self.in_string = true,
                (_, b'{' | b'[') => {
                    self.depth += 1;
                    if self.depth > MAX_DEPTH {
                        return None;
                    }
                }
                (_, b'}' | b']') => {
                    self.depth -= 1;
                    if self.depth == 0 {
                        return Some(true);
                    }
                }
                _ => {}
            }
        }
        Some(false)
    }
}

fn json_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
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

fn field<T: DeserializeOwned>(value: &RawValue) -> Option<Option<T>> {
    serde_json::from_str(value.get()).ok()
}

/// Sets `slot` unless the value is `null`; `None` when the value has the wrong type.
fn set<T: DeserializeOwned>(slot: &mut T, value: &RawValue) -> Option<()> {
    if let Some(v) = field(value)? {
        *slot = v;
    }
    Some(())
}

/// The first JSON value of a body as Go's `json.Decoder` reads it into a struct: the members
/// of an object in order, repeats kept so the last one wins; no members for `null`; `None` for
/// any other value or a syntax error. Bytes after the first value are not read.
///
/// shortcut: invalid UTF-8 and lone surrogate escapes fail here; Go reads them as U+FFFD. Fix
/// when a client sends them.
fn go_object(raw: &[u8]) -> Option<Vec<(String, Box<RawValue>)>> {
    // Go's scanner ends a top-level literal at its last letter, whatever follows.
    let start = raw
        .iter()
        .position(|&b| !json_space(b))
        .unwrap_or(raw.len());
    if raw[start..].starts_with(b"null") {
        return Some(Vec::new());
    }
    let mut values =
        serde_json::Deserializer::from_slice(raw).into_iter::<Members<Box<RawValue>>>();
    values.next()?.ok().map(|m| m.0)
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
