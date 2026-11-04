//! Go's `internal/fleet/http_test.go`, retry tests included, against a local stub server.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::IntoResponse;
use serde_json::{json, Value};

use super::*;
use crate::fleet::{
    retry, ActiveHosts, EventsParams, GoTime, HostsParams, Meta, RetryPolicy, RiskParams,
    DEFAULT_RETRY,
};

const TOKEN: &str = "test-bearer-secret";

#[derive(Clone, Debug)]
struct Seen {
    path: String,
    query: String,
    auth: Option<String>,
    accept: Option<String>,
}

struct Answer {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: String,
    delay: Duration,
}

fn json_answer(status: u16, body: Value) -> Answer {
    Answer {
        status,
        headers: vec![("content-type", "application/json".into())],
        body: body.to_string(),
        delay: Duration::ZERO,
    }
}

fn with_header(mut a: Answer, name: &'static str, value: &str) -> Answer {
    a.headers.push((name, value.into()));
    a
}

type Calls = Arc<Mutex<Vec<Seen>>>;

/// A server that answers call `n` (from 0) with `answer(n)` and records every request.
async fn stub(answer: impl Fn(usize) -> Answer + Send + Sync + 'static) -> (HttpClient, Calls) {
    let calls: Calls = Arc::default();
    let seen = calls.clone();
    let answer = Arc::new(answer);
    let app = axum::Router::new().fallback(move |uri: Uri, headers: HeaderMap| {
        let (seen, answer) = (seen.clone(), answer.clone());
        async move {
            let header = |n: &str| headers.get(n).map(|v| v.to_str().unwrap().to_owned());
            let n = {
                let mut seen = seen.lock().unwrap();
                seen.push(Seen {
                    path: uri.path().into(),
                    query: uri.query().unwrap_or_default().into(),
                    auth: header("authorization"),
                    accept: header("accept"),
                });
                seen.len() - 1
            };
            let a = answer(n);
            tokio::time::sleep(a.delay).await;
            let mut res = (StatusCode::from_u16(a.status).unwrap(), a.body).into_response();
            for (k, v) in a.headers {
                res.headers_mut().insert(k, v.parse().unwrap());
            }
            res
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = HttpClient::new(&url, TOKEN, None, Duration::from_secs(2)).unwrap();
    (client, calls)
}

fn meta_body(extra: Value) -> Value {
    let mut b = json!({
        "server_version": "0.9.0", "schema_version": 1, "ts": "2026-10-09T12:00:00Z",
        "alerts_definition_default": {"evidence_kinds": ["ai_guard_risk_assessed"],
            "ai_guard_buckets": ["high", "critical"], "additional_kinds": []}
    });
    b.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    b
}

fn error_body(code: &str) -> Value {
    json!({"error": {"code": code, "message": "nope"}})
}

fn meta(reply: Reply) -> Meta {
    match &*reply.unwrap() {
        Response::Meta(m) => m.clone(),
        other => panic!("not meta: {other:?}"),
    }
}

#[tokio::test]
async fn healthz_sends_no_authorization() {
    let (c, calls) =
        stub(|_| json_answer(200, json!({"status": "ok", "ts": "2026-05-19T12:00:00Z"}))).await;
    let Response::Healthz(h) = &*c.get(Request::Healthz).await.unwrap() else {
        panic!("not healthz")
    };
    assert_eq!(h.status, "ok");
    let seen = calls.lock().unwrap()[0].clone();
    assert_eq!(seen.auth, None, "healthz must not send Authorization");
    assert_eq!(seen.path, "/v1/healthz");
    assert_eq!(seen.accept.as_deref(), Some("application/json"));
}

#[tokio::test]
async fn meta_sends_bearer() {
    let (c, calls) = stub(|_| json_answer(200, meta_body(json!({})))).await;
    assert_eq!(meta(c.get(Request::Meta).await).server_version, "0.9.0");
    let auth = calls.lock().unwrap()[0].auth.clone();
    assert_eq!(auth.as_deref(), Some("Bearer test-bearer-secret"));
}

#[tokio::test]
async fn meta_fleet_block() {
    let body = meta_body(json!({"fleet": {"active_host_count": 42, "active_window_days": 7}}));
    let (c, _) = stub(move |_| json_answer(200, body.clone())).await;
    let fleet = meta(c.get(Request::Meta).await).fleet;
    assert_eq!(
        fleet,
        Some(ActiveHosts {
            active_host_count: 42,
            active_window_days: 7
        })
    );
}

/// lodeline-server 0.8 reports the host count inside `license`.
#[tokio::test]
async fn meta_legacy_license_maps_to_fleet() {
    let body = meta_body(json!({"license": {
        "state": "ok", "licensed": false, "expired": false, "effective_max_hosts": 200,
        "current_host_count": 12, "active_window_days": 30, "customer_id": null, "license_id": null
    }}));
    let (c, _) = stub(move |_| json_answer(200, body.clone())).await;
    let m = meta(c.get(Request::Meta).await);
    assert_eq!(
        m.fleet,
        Some(ActiveHosts {
            active_host_count: 12,
            active_window_days: 30
        })
    );
    let out = serde_json::to_string(&m).unwrap();
    assert!(
        !out.contains("\"license\""),
        "the legacy object is not re-emitted: {out}"
    );
}

#[tokio::test]
async fn meta_fleet_wins_over_legacy_license() {
    let body = meta_body(json!({
        "fleet": {"active_host_count": 3, "active_window_days": 7},
        "license": {"current_host_count": 99, "active_window_days": 30}
    }));
    let (c, _) = stub(move |_| json_answer(200, body.clone())).await;
    let fleet = meta(c.get(Request::Meta).await).fleet.unwrap();
    assert_eq!(fleet.active_host_count, 3);
}

#[tokio::test]
async fn meta_without_fleet_or_license() {
    let (c, _) = stub(|_| json_answer(200, meta_body(json!({})))).await;
    assert_eq!(meta(c.get(Request::Meta).await).fleet, None);
}

#[tokio::test]
async fn events_query_params() {
    let (c, calls) = stub(|_| json_answer(200, json!({"events": [], "next_cursor": null}))).await;
    let p = EventsParams {
        cursor: "abc".into(),
        limit: 200,
        host_ids: vec!["a".into(), "b".into()],
        since: GoTime::parse("2026-05-19T08:00:00Z").unwrap(),
        evidence_kinds: vec!["foo".into(), "bar".into()],
        severity: vec!["warn".into()],
        source: vec!["file_system".into()],
        min_ai_guard_bucket: "high".into(),
        ..Default::default()
    };
    c.get(Request::Events(p)).await.unwrap();
    // One comma-joined host_id: the server reads it as a single value it splits.
    assert_eq!(
        calls.lock().unwrap()[0].query,
        "cursor=abc&evidence_kind=foo%2Cbar&host_id=a%2Cb&limit=200&min_ai_guard_bucket=high\
         &severity=warn&since=2026-05-19T08%3A00%3A00Z&source=file_system"
    );
}

#[tokio::test]
async fn event_by_id_decodes() {
    let body = r#"{
        "schema_version": 1,
        "event_id": "019e0cea-42f1-7ef3-9a6a-1721e98ee2ba",
        "ts": "2026-05-19T12:33:55Z",
        "host_id": "5a7c3e91-aaaa-bbbb-cccc-dddddddddddd",
        "agent_version": "0.4.0",
        "severity": "warn",
        "source": {"kind":"file_system"},
        "subject": {"kind":"path","value":"/etc/passwd"},
        "evidence": {"kind":"ai_guard_risk_assessed","tool":"claude_code","scope":{"kind":"user_global"},"score":7.2,"bucket":"critical","reasons":[],"is_reattestation":false},
        "target_id": null
    }"#;
    let (c, calls) = stub(move |_| Answer {
        body: body.into(),
        ..json_answer(200, Value::Null)
    })
    .await;
    let id = "019e0cea-42f1-7ef3-9a6a-1721e98ee2ba";
    let Response::Event(e) = &*c.get(Request::EventById(id.into())).await.unwrap() else {
        panic!("not an event")
    };
    assert_eq!(e.severity, "warn");
    assert_eq!(e.evidence_kind(), "ai_guard_risk_assessed");
    assert_eq!(e.evidence["tool"], "claude_code");
    assert_eq!(e.evidence["bucket"], "critical");
    assert!(calls.lock().unwrap()[0].path.ends_with(id));
}

#[tokio::test]
async fn status_401_is_unauthorized() {
    let (c, _) = stub(|_| json_answer(401, error_body("unauthorized"))).await;
    assert_eq!(
        c.get(Request::Meta).await.unwrap_err(),
        FleetError::Unauthorized
    );
}

#[tokio::test]
async fn status_404_on_meta_is_read_api_disabled() {
    let (c, _) = stub(|_| json_answer(404, Value::Null)).await;
    assert_eq!(
        c.get(Request::Meta).await.unwrap_err(),
        FleetError::ReadApiDisabled
    );
}

#[tokio::test]
async fn status_404_on_event_by_id_is_not_found() {
    let (c, _) = stub(|_| json_answer(404, Value::Null)).await;
    let err = c
        .get(Request::EventById("missing".into()))
        .await
        .unwrap_err();
    assert_eq!(err, FleetError::NotFound, "an ID lookup 404 is not found");
}

#[tokio::test]
async fn status_404_on_host_by_id_is_not_found() {
    let (c, _) = stub(|_| json_answer(404, Value::Null)).await;
    let err = c
        .get(Request::HostById("missing".into()))
        .await
        .unwrap_err();
    assert_eq!(err, FleetError::NotFound);
}

#[tokio::test]
async fn status_503_parses_retry_after() {
    let (c, _) = stub(|_| {
        with_header(
            json_answer(503, error_body("service_unavailable")),
            "retry-after",
            "7",
        )
    })
    .await;
    assert_eq!(
        c.get(Request::Meta).await.unwrap_err(),
        FleetError::ServiceUnavailable {
            retry_after: Duration::from_secs(7)
        }
    );
}

#[tokio::test]
async fn status_503_without_retry_after_waits_5s() {
    for value in [None, Some("soon"), Some("-1")] {
        let (c, _) = stub(move |_| {
            let a = json_answer(503, error_body("service_unavailable"));
            match value {
                Some(v) => with_header(a, "retry-after", v),
                None => a,
            }
        })
        .await;
        assert_eq!(
            c.get(Request::Meta).await.unwrap_err(),
            FleetError::ServiceUnavailable {
                retry_after: Duration::from_secs(5)
            },
            "{value:?}"
        );
    }
}

#[tokio::test]
async fn status_400_is_an_api_error_with_the_upstream_code() {
    let (c, _) = stub(|_| json_answer(400, error_body("invalid_query"))).await;
    let p = EventsParams {
        cursor: "garbage".into(),
        ..Default::default()
    };
    let FleetError::Api { status, code, .. } = c.get(Request::Events(p)).await.unwrap_err() else {
        panic!("not an API error")
    };
    assert_eq!((status, code.as_str()), (400, "invalid_query"));

    let (c, _) = stub(|_| Answer {
        body: " panic at the server \n".into(),
        ..json_answer(500, Value::Null)
    })
    .await;
    assert_eq!(
        c.get(Request::Meta).await.unwrap_err(),
        FleetError::Api {
            status: 500,
            code: "unknown".into(),
            message: "panic at the server".into()
        }
    );
}

const FAST: RetryPolicy = RetryPolicy {
    max_attempts: 3,
    max_delay: Duration::from_millis(10),
};

#[tokio::test]
async fn retry_succeeds_after_a_503() {
    let (c, calls) = stub(|n| match n {
        0 => with_header(
            json_answer(503, error_body("service_unavailable")),
            "retry-after",
            "0",
        ),
        _ => json_answer(200, meta_body(json!({}))),
    })
    .await;
    let m = meta(retry(FAST, || c.get(Request::Meta)).await);
    assert_eq!(m.server_version, "0.9.0");
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn retry_does_not_retry_401() {
    let (c, calls) = stub(|_| json_answer(401, error_body("unauthorized"))).await;
    let err = retry(DEFAULT_RETRY, || c.get(Request::Meta))
        .await
        .unwrap_err();
    assert_eq!(err, FleetError::Unauthorized);
    assert_eq!(calls.lock().unwrap().len(), 1, "401 is a config error");
}

#[tokio::test]
async fn retry_does_not_retry_404() {
    let (c, calls) = stub(|_| json_answer(404, Value::Null)).await;
    let err = retry(DEFAULT_RETRY, || c.get(Request::Meta))
        .await
        .unwrap_err();
    assert_eq!(err, FleetError::ReadApiDisabled);
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn retry_exhausts_its_attempts() {
    let (c, calls) = stub(|_| {
        with_header(
            json_answer(503, error_body("service_unavailable")),
            "retry-after",
            "0",
        )
    })
    .await;
    let err = retry(FAST, || c.get(Request::Meta)).await.unwrap_err();
    assert!(err.is_retryable(), "{err}");
    assert_eq!(calls.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn retry_stops_when_the_caller_goes_away() {
    let (c, _) = stub(|_| {
        with_header(
            json_answer(503, error_body("service_unavailable")),
            "retry-after",
            "60",
        )
    })
    .await;
    let policy = RetryPolicy {
        max_attempts: 5,
        max_delay: Duration::from_millis(50),
    };
    let started = Instant::now();
    let res = tokio::time::timeout(
        Duration::from_millis(20),
        retry(policy, || c.get(Request::Meta)),
    )
    .await;
    assert!(res.is_err(), "dropped at the caller's deadline");
    assert!(started.elapsed() < Duration::from_millis(500));
}

/// Go's `net/http` reports a client timeout as `context.DeadlineExceeded`, which Go's retry
/// checks before anything else, so a timeout fails after one attempt.
#[tokio::test]
async fn a_timeout_is_a_transport_error_and_is_not_retried() {
    let (c, calls) = stub(|_| Answer {
        delay: Duration::from_secs(3),
        ..json_answer(200, meta_body(json!({})))
    })
    .await;
    let started = Instant::now();
    let err = retry(DEFAULT_RETRY, || c.get(Request::Meta))
        .await
        .unwrap_err();
    assert!(matches!(err, FleetError::Transport(_)), "{err}");
    assert!(
        started.elapsed() < Duration::from_millis(2900),
        "the 2 s timeout ended it"
    );
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_refused_connection_or_a_bad_body_is_a_transport_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let c = HttpClient::new(&url, TOKEN, None, Duration::from_secs(2)).unwrap();
    assert!(matches!(
        c.get(Request::Meta).await.unwrap_err(),
        FleetError::Transport(_)
    ));

    for body in ["", "{\"events\": [", "{\"events\": \"no\"}"] {
        let (c, _) = stub(move |_| Answer {
            body: body.into(),
            ..json_answer(200, Value::Null)
        })
        .await;
        let err = c
            .get(Request::Events(EventsParams::default()))
            .await
            .unwrap_err();
        assert!(matches!(err, FleetError::Transport(_)), "{body:?}: {err}");
    }
}

#[tokio::test]
async fn ids_are_path_escaped() {
    let (c, calls) = stub(|_| json_answer(404, Value::Null)).await;
    for id in ["a b", "a/b", "a+b", "%41"] {
        let _ = c.get(Request::HostById(id.into())).await;
    }
    let paths: Vec<String> = calls
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.path.clone())
        .collect();
    assert_eq!(
        paths,
        [
            "/v1/fleet/hosts/a%20b",
            "/v1/fleet/hosts/a%2Fb",
            "/v1/fleet/hosts/a+b",
            "/v1/fleet/hosts/%2541"
        ]
    );
}

#[tokio::test]
async fn hosts_query_builds_its_filters() {
    let (c, calls) = stub(|_| {
        json_answer(
            200,
            json!({"hosts": [], "next_cursor": null, "total_estimated": 0}),
        )
    })
    .await;
    let p = HostsParams {
        limit: 50,
        status: vec!["healthy".into(), "stale".into()],
        bucket: vec!["high".into(), "critical".into()],
        sort: "risk".into(),
        ..Default::default()
    };
    c.get(Request::Hosts(p)).await.unwrap();
    assert_eq!(
        calls.lock().unwrap()[0].query,
        "bucket=high%2Ccritical&limit=50&sort=risk&status=healthy%2Cstale"
    );
}

#[tokio::test]
async fn risk_query_builds_its_filters() {
    let (c, calls) = stub(|_| json_answer(200, json!({"rows": [], "next_cursor": null}))).await;
    let p = RiskParams {
        limit: 25,
        tool: vec!["claude_code".into(), "codex".into()],
        min_bucket: "high".into(),
        ..Default::default()
    };
    c.get(Request::Risk(p)).await.unwrap();
    assert_eq!(
        calls.lock().unwrap()[0].query,
        "limit=25&min_bucket=high&tool=claude_code%2Ccodex"
    );
}
