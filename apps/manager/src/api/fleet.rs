//! The `/api/v1/fleet/*` handlers (Go's `internal/api/v1/fleet.go`): thin relays of the fleet
//! client, with Go's query parsing and error mapping. The SPA never sees `lodeline-server` URLs.

use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use serde::Serialize;

use crate::api::{write_json, Query};
use crate::fleet::{
    self, ComplianceParams, Event, EventsParams, FleetError, GoTime, HostsParams, Reply, Request,
    RiskParams,
};
use crate::server::{error_response, AppState};
use crate::{config, triage};

pub async fn meta(State(s): State<AppState>) -> Response {
    relay(s.fleet.get(Request::Meta).await)
}

/// Not retried: the connection indicator must show a down upstream at once.
pub async fn healthz(State(s): State<AppState>) -> Response {
    relay(s.fleet.get(Request::Healthz).await)
}

pub async fn events(State(s): State<AppState>, uri: Uri) -> Response {
    match events_params(&Query::parse(uri.query())) {
        Ok(p) => joined(&s, retried(&s, Request::Events(p)).await).await,
        Err(msg) => invalid_query(msg),
    }
}

pub async fn event(State(s): State<AppState>, uri: Uri) -> Response {
    let id = last_segment(&route_path(uri.path()));
    joined(&s, retried(&s, Request::EventById(id)).await).await
}

pub async fn risk(State(s): State<AppState>, uri: Uri) -> Response {
    let q = Query::parse(uri.query());
    match q.limit() {
        Ok(limit) => {
            let p = RiskParams {
                cursor: q.get("cursor").into(),
                limit,
                tool: split_comma(q.get("tool")),
                min_bucket: q.get("min_bucket").into(),
            };
            relay(retried(&s, Request::Risk(p)).await)
        }
        Err(msg) => invalid_query(msg),
    }
}

pub async fn compliance(State(s): State<AppState>, uri: Uri) -> Response {
    let q = Query::parse(uri.query());
    match q.limit() {
        Ok(limit) => {
            let p = ComplianceParams {
                cursor: q.get("cursor").into(),
                limit,
            };
            relay(retried(&s, Request::Compliance(p)).await)
        }
        Err(msg) => invalid_query(msg),
    }
}

pub async fn hosts(State(s): State<AppState>, uri: Uri) -> Response {
    let q = Query::parse(uri.query());
    match q.limit() {
        Ok(limit) => {
            let p = HostsParams {
                cursor: q.get("cursor").into(),
                limit,
                status: split_comma(q.get("status")),
                bucket: split_comma(q.get("bucket")),
                sort: q.get("sort").into(),
            };
            relay(retried(&s, Request::Hosts(p)).await)
        }
        Err(msg) => invalid_query(msg),
    }
}

pub async fn host(State(s): State<AppState>, uri: Uri) -> Response {
    let id = last_segment(&route_path(uri.path()));
    relay(retried(&s, Request::HostById(id)).await)
}

async fn retried(s: &AppState, req: Request) -> Reply {
    fleet::retry(fleet::DEFAULT_RETRY, || s.fleet.get(req.clone())).await
}

/// An event as the alerts queue reads it: the event plus its triage view, `null` when nobody
/// has triaged it.
#[derive(Serialize)]
struct WithTriage<'a> {
    #[serde(flatten)]
    event: &'a Event,
    triage: Option<triage::View>,
}

#[derive(Serialize)]
struct Page<'a> {
    events: Vec<WithTriage<'a>>,
    next_cursor: &'a Option<String>,
}

/// Go's per-event triage lookup in the events and event-by-ID handlers.
async fn joined(s: &AppState, reply: Reply) -> Response {
    let (events, next_cursor) = match reply.as_deref() {
        Ok(fleet::Response::Events(page)) => (
            page.events.iter().flatten().collect(),
            Some(&page.next_cursor),
        ),
        Ok(fleet::Response::Event(e)) => (vec![e], None),
        _ => return relay(reply),
    };
    let keys: Vec<_> = events
        .iter()
        .map(|e| (e.host_id.clone(), e.event_id.clone()))
        .collect();
    let store = s.triage.clone();
    let views = tokio::task::spawn_blocking(move || store.views(&keys))
        .await
        .expect("triage lookup panicked");
    let rows: Vec<WithTriage> = events
        .into_iter()
        .zip(views)
        .map(|(event, triage)| WithTriage { event, triage })
        .collect();
    match next_cursor {
        Some(next_cursor) => write_json(&Page {
            events: rows,
            next_cursor,
        }),
        None => write_json(&rows[0]),
    }
}

fn relay(reply: Reply) -> Response {
    match reply.as_deref() {
        Err(e) => map_err(e),
        Ok(body) => write_json(body),
    }
}

/// Go's `mapFleetErr`. Upstream details are logged, never sent: a transport error names the
/// server URL, and an error body is the server's text.
fn map_err(e: &FleetError) -> Response {
    match e {
        FleetError::NotFound => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "event or host not found",
        ),
        FleetError::ReadApiDisabled => error_response(
            StatusCode::BAD_GATEWAY,
            "read_api_disabled",
            "lodeline-server has the read API disabled \u{2014} set LODELINE_SERVER_READ_TOKEN there",
        ),
        FleetError::Unauthorized => error_response(
            StatusCode::BAD_GATEWAY,
            "upstream_unauthorized",
            "lodeline-server rejected our token \u{2014} check LODELINE_SERVER_READ_TOKEN",
        ),
        FleetError::ServiceUnavailable { .. } => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "lodeline-server is rebuilding its index, retry shortly",
        ),
        FleetError::Api { code, .. } => {
            eprintln!("fleet: upstream request failed: {e}");
            error_response(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                &format!("lodeline-server returned an error ({code})"),
            )
        }
        FleetError::Transport(_) => {
            eprintln!("fleet: upstream request failed: {e}");
            error_response(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "request to lodeline-server failed",
            )
        }
    }
}

fn invalid_query(msg: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, "invalid_query", msg)
}

fn events_params(q: &Query) -> Result<EventsParams, &'static str> {
    let time = |key, msg| match q.get(key) {
        "" => Ok(GoTime::default()),
        v => GoTime::parse(v).ok_or(msg),
    };
    let mut p = EventsParams {
        cursor: q.get("cursor").into(),
        limit: q.limit()?,
        host_ids: split_comma(q.get("host_id")),
        since: time("since", "since must be RFC3339")?,
        until: time("until", "until must be RFC3339")?,
        evidence_kinds: split_comma(q.get("evidence_kind")),
        severity: split_comma(q.get("severity")),
        source: split_comma(q.get("source")),
        min_ai_guard_bucket: q.get("min_ai_guard_bucket").into(),
    };
    // `host_id` is the one repeatable filter: `?host_id=a&host_id=b,c` names all three.
    let hosts: Vec<&str> = q.all("host_id").collect();
    if hosts.len() > 1 {
        p.host_ids = hosts.into_iter().flat_map(split_comma).collect();
    }
    Ok(p)
}

fn split_comma(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// The path as chi routes it: decoded, unless the path's escaping differs from Go's own, in
/// which case Go keeps the raw path and chi matches on it, escapes included.
///
/// shortcut: a decoded path that is not UTF-8 is read lossily, where Go keeps the bytes.
pub fn route_path(raw: &str) -> String {
    let decoded = String::from_utf8_lossy(&config::unescape(raw).unwrap_or_default()).into_owned();
    if fleet::escape_path(&decoded) == raw {
        decoded
    } else {
        raw.to_owned()
    }
}

fn last_segment(path: &str) -> String {
    path.rsplit('/').next().unwrap_or_default().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_and_path_params_read_as_go_does() {
        let q = Query::parse(Some(
            "limit=%2B3&a;b=1&x=%zz&severity=+warn+,,high&host_id=a",
        ));
        assert_eq!(q.limit(), Ok(3));
        assert_eq!(q.get("x"), "");
        assert_eq!(split_comma(q.get("severity")), ["warn", "high"]);
        assert_eq!(
            Query::parse(Some("limit=+3")).limit(),
            Err("limit must be an integer")
        );
        for (raw, want) in [
            ("/api/v1/fleet/events/a%20b", "a b"),
            ("/api/v1/fleet/events/a%2Bb", "a%2Bb"),
            ("/api/v1/fleet/events/a%2Fb", "a%2Fb"),
            ("/api/v1/fleet/events/%41bc", "%41bc"),
            ("/api/v1/fleet/events/abc", "abc"),
            ("/api/v1/fleet/events/%2A", "*"),
            ("/api/v1/fleet/events/a*b%20c", "a*b%20c"),
        ] {
            assert_eq!(last_segment(&route_path(raw)), want, "{raw}");
        }
    }
}
