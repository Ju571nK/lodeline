//! Go's triage cases from `internal/api/v1/handlers_test.go`, and its body decoding rules.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request};
use axum::Router;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::{json, Value};
use tower::ServiceExt;

use super::*;
use crate::auth::Signer;
use crate::fleet;
use crate::server::router;

const SECRET: &str = "0123456789abcdefghijklmnopqrstuv";

fn app() -> Router {
    router(AppState {
        signer: Arc::new(Signer::new(SECRET.as_bytes())),
        fleet: Arc::new(fleet::Mock::new(1_779_192_000)),
        triage: Arc::new(Store::open(":memory:").unwrap()),
    })
}

fn cookie(subject: &str) -> String {
    let claims = json!({"iss": "lodeline-manager", "sub": subject, "exp": 4_000_000_000_i64});
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap();
    format!("lodeline_session={token}")
}

async fn call(app: &Router, method: Method, uri: &str, body: Option<Value>) -> (u16, Value) {
    call_as(app, "admin", method, uri, body).await
}

async fn call_as(
    app: &Router,
    subject: &str,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "console.example")
        .header(header::COOKIE, cookie(subject))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status().as_u16();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn events_join_triage() {
    let app = app();
    let (code, page) = call(&app, Method::GET, "/api/v1/fleet/events?limit=1", None).await;
    assert_eq!(code, 200);
    let ev = &page["events"][0];
    assert_eq!(ev["triage"], Value::Null, "no triage row yet");

    let upsert = json!({
        "host_id": ev["host_id"], "event_id": ev["event_id"],
        "status": "acknowledged", "evidence_snapshot": {"snap": "ok"},
    });
    let (code, _) = call(&app, Method::POST, "/api/v1/triage/upsert", Some(upsert)).await;
    assert_eq!(code, 200);

    let (_, page) = call(&app, Method::GET, "/api/v1/fleet/events?limit=1", None).await;
    let triage = &page["events"][0]["triage"];
    assert_eq!(triage["status"], "acknowledged");
    assert_eq!(triage["assignee"], Value::Null);
    let path = format!("/api/v1/fleet/events/{}", ev["event_id"].as_str().unwrap());
    let (_, event) = call(&app, Method::GET, &path, None).await;
    assert_eq!(&event["triage"], triage);
    // Go encodes this time as a plain time.Time, with trailing fraction zeros dropped.
    let at = triage["updated_at"].as_str().unwrap();
    assert!(at.ends_with('Z') && !at.contains("0Z"), "{at}");
}

#[tokio::test]
async fn upsert_requires_auth() {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/triage/upsert")
        .header(header::HOST, "console.example")
        .body(Body::from(
            r#"{"host_id":"h1","event_id":"e1","status":"open","evidence_snapshot":{"x":1}}"#,
        ))
        .unwrap();
    assert_eq!(app().oneshot(req).await.unwrap().status(), 401);
}

#[tokio::test]
async fn state_machine_allows_every_transition() {
    let app = app();
    let steps = [
        "open",
        "acknowledged",
        "investigating",
        "resolved",
        "investigating",
        "open",
    ];
    for (i, status) in steps.into_iter().enumerate() {
        let mut body = json!({"host_id": "h1", "event_id": "e1", "status": status});
        if i == 0 {
            body["evidence_snapshot"] = json!({"first": true});
        }
        let (code, res) = call(&app, Method::POST, "/api/v1/triage/upsert", Some(body)).await;
        assert_eq!(code, 200, "step {i} to {status}: {res}");
    }
    let (code, got) = call(&app, Method::GET, "/api/v1/triage/h1/e1", None).await;
    assert_eq!(code, 200);
    assert_eq!(got["row"]["status"], "open");
    assert_eq!(got["log"].as_array().unwrap().len(), 6);
}

#[tokio::test]
async fn note_and_get() {
    let app = app();
    let upsert =
        json!({"host_id": "h2", "event_id": "e2", "status": "open", "evidence_snapshot": {"x": 2}});
    let (code, _) = call(&app, Method::POST, "/api/v1/triage/upsert", Some(upsert)).await;
    assert_eq!(code, 200);
    let note = json!({"host_id": "h2", "event_id": "e2", "body": "first note"});
    let (code, note) = call(&app, Method::POST, "/api/v1/triage/note", Some(note)).await;
    assert_eq!(code, 200);
    assert_eq!(note["author"], "admin", "author comes from the session");
    assert_eq!(note["body"], "first note");
    let (code, got) = call(&app, Method::GET, "/api/v1/triage/h2/e2", None).await;
    assert_eq!(code, 200);
    assert_eq!(got["notes"].as_array().unwrap().len(), 1);
    assert_eq!(got["notes"][0]["body"], "first note");
}

#[tokio::test]
async fn rejects_bad_status() {
    let body = json!({"host_id": "h3", "event_id": "e3", "status": "bogus", "evidence_snapshot": {"x": 3}});
    let (code, res) = call(&app(), Method::POST, "/api/v1/triage/upsert", Some(body)).await;
    assert_eq!(code, 400);
    assert_eq!(res["error"]["code"], "invalid_query");
}

/// The actor and author are the session subject as is, so an OIDC subject (`oidc:` and a
/// hash) and a local username both stay the same strings across the upgrade.
#[tokio::test]
async fn actor_and_author_are_the_session_subject() {
    let app = app();
    let subject = "oidc:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
    let upsert = json!({"host_id": "h", "event_id": "e", "evidence_snapshot": {}});
    call_as(
        &app,
        subject,
        Method::POST,
        "/api/v1/triage/upsert",
        Some(upsert),
    )
    .await;
    let note = json!({"host_id": "h", "event_id": "e", "body": "b"});
    call_as(
        &app,
        "admin <&>",
        Method::POST,
        "/api/v1/triage/note",
        Some(note),
    )
    .await;
    let (_, got) = call(&app, Method::GET, "/api/v1/triage/h/e", None).await;
    assert_eq!(got["log"][0]["actor"], subject);
    assert_eq!(got["notes"][0]["author"], "admin <&>");
}

#[test]
fn bodies_decode_as_go_decodes_them() {
    let upsert = |raw: &str| upsert_body(raw.as_bytes());
    let note = |raw: &str| note_body(raw.as_bytes()).map(|b| (b.host_id, b.event_id, b.body));

    // Only the first value is read, and keys match without regard to case, the last one winning.
    let b = upsert(r#"{"HOST_ID":"a","Event_Id":"b","host_id":"c"} trailing {"#).unwrap();
    assert_eq!((b.host_id.as_str(), b.event_id.as_str()), ("c", "b"));
    // U+017F folds to `s`, as in Go.
    assert_eq!(
        upsert("{\"\u{17f}tatus\":\"open\"}").unwrap().status,
        "open"
    );
    // null keeps a string or bool as it was, resets a pointer, and is a snapshot of its own.
    let b = upsert(r#"{"host_id":"a","host_id":null,"assignee":"x","assignee":null,"clear_assignee":true,"clear_assignee":null,"evidence_snapshot":null}"#).unwrap();
    assert_eq!(b.host_id, "a");
    assert_eq!(b.assignee, None);
    assert!(b.clear_assignee);
    assert_eq!(b.evidence_snapshot.as_deref(), Some("null"));
    // The snapshot keeps its text; unknown keys are ignored.
    let b = upsert(r#"{"evidence_snapshot": { "n" : 1.0 },"author":"x"}"#).unwrap();
    assert_eq!(b.evidence_snapshot.as_deref(), Some(r#"{ "n" : 1.0 }"#));
    // A top-level null reads as an empty struct, whatever follows its last letter.
    for raw in ["null", " \n null", "nullx", "null {"] {
        assert_eq!(note(raw), Some(Default::default()), "{raw}");
    }
    for raw in [
        "",
        "  ",
        "nul",
        "[]",
        "5",
        "\"x\"",
        "true",
        "{\"host_id\":",
        "{\"body\":7}",
        "{\"host_id\":[]}",
        "{\"clear_assignee\":\"yes\"}",
        "{\"assignee\":1}",
        "\u{feff}{}",
    ] {
        assert!(upsert(raw).is_none() || note(raw).is_none(), "{raw:?}");
    }
    assert!(upsert("{\"clear_assignee\":\"yes\"}").is_none());
    assert!(note("{\"body\":7}").is_none());
}

#[test]
fn path_params_read_as_chi_gives_them() {
    for (raw, want) in [
        ("/api/v1/triage/h/e", ("h", "e")),
        ("/api/v1/triage//e", ("", "e")),
        ("/api/v1/triage/h%20x/e", ("h x", "e")),
        ("/api/v1/triage/h/e%2Fx", ("h", "e%2Fx")),
    ] {
        let (h, e) = path_params(raw);
        assert_eq!((h.as_str(), e.as_str()), want, "{raw}");
    }
}
