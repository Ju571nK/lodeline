//! Go's triage cases from `internal/api/v1/handlers_test.go`, and its body decoding rules.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request};
use axum::Router;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::{json, Value};
use tower::ServiceExt;

use super::*;
use crate::api::BodyError;
use crate::fleet;
use crate::server::router;

const SECRET: &str = "0123456789abcdefghijklmnopqrstuv";

fn app() -> Router {
    router(AppState::for_tests(
        SECRET,
        Arc::new(fleet::Mock::new(1_779_192_000)),
    ))
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

fn error(code: &str, message: &str) -> Value {
    json!({"error": {"code": code, "message": message}})
}

#[tokio::test]
async fn rejects_bad_status() {
    let body = json!({"host_id": "h3", "event_id": "e3", "status": "bogus", "evidence_snapshot": {"x": 3}});
    let (code, res) = call(&app(), Method::POST, "/api/v1/triage/upsert", Some(body)).await;
    assert_eq!(code, 400);
    assert_eq!(
        res,
        error(
            "invalid_query",
            "status must be one of: open, acknowledged, investigating, resolved"
        )
    );
}

/// Go's messages and the order its handlers check in: decode, required ids, status, then the
/// store's own checks.
#[tokio::test]
async fn errors_answer_as_go_does() {
    let app = app();
    let upsert = "/api/v1/triage/upsert";
    let note = "/api/v1/triage/note";
    let required = "host_id and event_id are required";
    let bad_status = "status must be one of: open, acknowledged, investigating, resolved";
    let cases = [
        (
            upsert,
            json!([]),
            400,
            "invalid_query",
            "malformed JSON body",
        ),
        (
            upsert,
            json!({"host_id": "h", "status": "bogus"}),
            400,
            "invalid_query",
            required,
        ),
        (
            upsert,
            json!({"host_id": "h", "event_id": "e", "status": "bogus"}),
            400,
            "invalid_query",
            bad_status,
        ),
        (
            upsert,
            json!({"host_id": "h", "event_id": "e"}),
            400,
            "invalid_query",
            "triage: missing required fields: EvidenceSnapshot required on insert",
        ),
        (
            note,
            json!({"host_id": 1}),
            400,
            "invalid_query",
            "malformed JSON body",
        ),
        (
            note,
            json!({"host_id": "h", "event_id": "e"}),
            400,
            "invalid_query",
            "host_id, event_id, body are required",
        ),
        (
            note,
            json!({"host_id": "h", "event_id": "e", "body": "b"}),
            404,
            "not_found",
            "triage row not found",
        ),
    ];
    for (path, body, status, code, message) in cases {
        let (got, res) = call(&app, Method::POST, path, Some(body.clone())).await;
        assert_eq!((got, res), (status, error(code, message)), "{path} {body}");
    }
    for (path, status, code, message) in [
        (
            "/api/v1/triage/h/e",
            404,
            "not_found",
            "triage row not found",
        ),
        (
            "/api/v1/triage//e",
            400,
            "invalid_query",
            "host_id and event_id required",
        ),
    ] {
        let (got, res) = call(&app, Method::GET, path, None).await;
        assert_eq!((got, res), (status, error(code, message)), "{path}");
    }
}

/// Go reads the clock once its transaction holds the connection, so times follow commit
/// order: each list's times rise with its ids, and the row keeps the newest upsert's time.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn times_follow_commit_order() {
    let app = app();
    let insert = json!({"host_id": "h", "event_id": "e", "evidence_snapshot": {}});
    call(&app, Method::POST, "/api/v1/triage/upsert", Some(insert)).await;
    let workers: Vec<_> = (0..32)
        .map(|w| {
            let app = app.clone();
            tokio::spawn(async move {
                let mut newest = String::new();
                for i in 0..40 {
                    let status = ["open", "acknowledged"][(w + i) % 2];
                    let body = json!({"host_id": "h", "event_id": "e", "status": status});
                    let (code, row) =
                        call(&app, Method::POST, "/api/v1/triage/upsert", Some(body)).await;
                    assert_eq!(code, 200, "{row}");
                    newest = newest.max(row["updated_at"].as_str().unwrap().to_owned());
                    let note = json!({"host_id": "h", "event_id": "e", "body": "n"});
                    let (code, res) =
                        call(&app, Method::POST, "/api/v1/triage/note", Some(note)).await;
                    assert_eq!(code, 200, "{res}");
                }
                newest
            })
        })
        .collect();
    let mut newest = String::new();
    for w in workers {
        newest = newest.max(w.await.unwrap());
    }
    let (_, got) = call(&app, Method::GET, "/api/v1/triage/h/e", None).await;
    for (list, field) in [("log", "at"), ("notes", "created_at")] {
        let mut entries: Vec<(i64, &str)> = got[list]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (e["id"].as_i64().unwrap(), e[field].as_str().unwrap()))
            .collect();
        entries.sort();
        let late = entries.windows(2).filter(|w| w[0].1 > w[1].1).count();
        assert_eq!(
            late,
            0,
            "{list}: {late} of {} out of id order",
            entries.len()
        );
    }
    assert_eq!(got["row"]["updated_at"], newest);
    let last_log = got["log"].as_array().unwrap().last().unwrap()["at"]
        .as_str()
        .unwrap();
    assert!(last_log <= newest.as_str(), "{last_log} after {newest}");
}

/// Go's decoder fails a body that nests arrays and objects more than 10000 deep, in any field.
/// Brackets inside strings do not count.
#[tokio::test]
async fn nesting_stops_at_go_depth() {
    let app = app();
    // A level's (open, close), alternating between the two, nested around a `0`.
    let (array, object) = (("[", "]"), (r#"{"a":"#, "}"));
    let string = (r#"["[{\"]}[{","#, "]");
    let shapes = [
        ("array", [array, array]),
        ("object", [object, object]),
        ("mixed", [array, object]),
        ("string", [string, string]),
    ];
    for (shape, pair) in shapes {
        let body = |key: &str, depth: usize| {
            let levels: Vec<_> = (0..depth - 1).map(|i| pair[i % 2]).collect();
            let opens: String = levels.iter().map(|l| l.0).collect();
            let closes: String = levels.iter().rev().map(|l| l.1).collect();
            format!(
                r#"{{"host_id":"h","event_id":"{shape}{key}{depth}","evidence_snapshot":{{}},"{key}":{opens}0{closes}}}"#
            )
        };
        for key in ["evidence_snapshot", "unknown"] {
            for (depth, want) in [(10_000, 200), (10_001, 400)] {
                let req = Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/triage/upsert")
                    .header(header::HOST, "console.example")
                    .header(header::COOKIE, cookie("admin"))
                    .body(Body::from(body(key, depth)))
                    .unwrap();
                let res = app.clone().oneshot(req).await.unwrap();
                let status = res.status().as_u16();
                let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
                    .await
                    .unwrap();
                assert_eq!(status, want, "{shape} {key} at depth {depth}");
                if want == 400 {
                    let res: Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(res, error("invalid_query", "malformed JSON body"));
                }
            }
        }
    }
}

/// A body whose frames come one by one and then fail, as a client that stops sending does.
struct Frames(std::collections::VecDeque<&'static str>);

impl axum::body::HttpBody for Frames {
    type Data = axum::body::Bytes;
    type Error = &'static str;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let frame = self.0.pop_front().ok_or("read after the value");
        std::task::Poll::Ready(Some(frame.map(|f| hyper::body::Frame::data(f.into()))))
    }
}

/// Like Go's decoder, the body is read until its first value is complete and no further: the
/// frame after the value would fail the read. After a top-level `null`, Go waits for one more
/// byte or the end of the body; this read does not.
#[tokio::test]
async fn body_is_read_to_the_end_of_its_first_value() {
    let read = |frames: &[&'static str]| {
        let body = Body::new(Frames(frames.iter().copied().collect()));
        read_body(Request::new(body), TRIAGE_BODY_LIMIT)
    };
    for (frames, want) in [
        (&[r#"{"host_id":"a"}"#][..], r#"{"host_id":"a"}"#),
        (
            &[r#" {"body":"}{"#, r#"\"","x":[{}]} {"#],
            r#" {"body":"}{\"","x":[{}]} {"#,
        ),
        (&["nu", "ll"], "null"),
        // A byte a frame: `null` is whole at its fourth byte, and what follows is not read.
        (&["n", "u", "l", "l"], "null"),
        (&["n", "u", "l", "l", "x", "}"], "null"),
        (&["\u{feff}{}"], "\u{feff}{}"),
    ] {
        let got = read(frames).await.unwrap();
        let text = got.clone().map(String::from_utf8);
        assert_eq!(text, Some(Ok(want.to_owned())), "{frames:?}");
        if want == "null" {
            // Go decodes `null`, trailing bytes or not, into an empty request.
            let b = upsert_body(&got.unwrap()).unwrap();
            assert_eq!((b.host_id.as_str(), b.event_id.as_str()), ("", ""));
        }
    }
    assert_eq!(
        read(&[r#"{"host_id":"a""#]).await.unwrap(),
        None,
        "fails mid-value"
    );
}

/// The limit counts the first value only: bytes after it in the same frame do not count.
#[tokio::test]
async fn the_body_limit_applies_to_the_first_value() {
    let read = |frames: &[&'static str]| {
        let body = Body::new(Frames(frames.iter().copied().collect()));
        read_body(Request::new(body), 16)
    };
    let fits = read(&[r#"{"host_id":"ab"} and more"#]).await.unwrap();
    assert_eq!(fits.as_deref(), Some(&br#"{"host_id":"ab"}"#[..]));
    let fits = read(&[r#"{"host_id":"#, r#""ab"} and more"#])
        .await
        .unwrap();
    assert_eq!(fits.as_deref(), Some(&br#"{"host_id":"ab"}"#[..]));
    for frames in [
        &[r#"{"host_id":"abc"}"#][..],
        &[r#"{"host_id":"ab"#, r#"c"}"#],
    ] {
        assert_eq!(read(frames).await, Err(BodyError::TooLarge), "{frames:?}");
    }
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
    // Which decoder rejects each body: a key only one request type has is ignored by the other.
    for (raw, upsert_rejects, note_rejects) in [
        ("", true, true),
        ("  ", true, true),
        ("\u{c}null", true, true),
        ("nul", true, true),
        ("[]", true, true),
        ("5", true, true),
        ("\"x\"", true, true),
        ("true", true, true),
        ("{\"host_id\":", true, true),
        ("{\"host_id\":[]}", true, true),
        ("{\"body\":7}", false, true),
        ("{\"clear_assignee\":\"yes\"}", true, false),
        ("{\"assignee\":1}", true, false),
        ("\u{feff}{}", true, true),
    ] {
        assert_eq!(upsert(raw).is_none(), upsert_rejects, "upsert {raw:?}");
        assert_eq!(note(raw).is_none(), note_rejects, "note {raw:?}");
    }
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

/// Triage bodies may be up to 4 MiB, room for any event `lodeline-server` accepts (2 MiB a
/// request); a larger one gets 413.
#[tokio::test]
async fn triage_bodies_are_capped_at_4_mib() {
    let app = app();
    let upsert = |len: usize| {
        json!({"host_id": "h", "event_id": "e-big", "status": "open",
               "evidence_snapshot": {"blob": "x".repeat(len)}})
    };
    let (code, _) = call(
        &app,
        Method::POST,
        "/api/v1/triage/upsert",
        Some(upsert(4 << 20)),
    )
    .await;
    assert_eq!(code, 413);
    let (code, _) = call(
        &app,
        Method::POST,
        "/api/v1/triage/upsert",
        Some(upsert(3 << 20)),
    )
    .await;
    assert_eq!(code, 200);
    let note = json!({"host_id": "h", "event_id": "e-big", "body": "n".repeat(4 << 20)});
    let (code, _) = call(&app, Method::POST, "/api/v1/triage/note", Some(note)).await;
    assert_eq!(code, 413);
}
