//! The two routes through the console's router, with an enroller that records what it is asked.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request};
use axum::Router;
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::enroll::{new_host_id, Active, Enroll, Enroller, Template, REQUIRED};
use crate::fleet::BoxFuture;
use crate::server::{router, AppState};
use crate::testutil::{post_files, session_cookie, Reply, ORIGIN, SESSION_SECRET};

use super::*;

#[derive(Debug)]
struct Scripted {
    calls: Mutex<Vec<(String, String)>>,
    reply: Mutex<Result<(), MintError>>,
}

impl Enroller for Scripted {
    fn mint<'a>(
        &'a self,
        host_id: &'a str,
        subject: &'a str,
    ) -> BoxFuture<'a, Result<MintResponse, MintError>> {
        self.calls
            .lock()
            .unwrap()
            .push((host_id.into(), subject.into()));
        let reply = match &*self.reply.lock().unwrap() {
            Ok(()) => Ok(MintResponse {
                expires_at: "2030-01-01T00:00:00Z".into(),
                host_id: host_id.into(),
                token: "scripted-token-SECRETTOKEN".into(),
            }),
            Err(MintError::HostExists) => Err(MintError::HostExists),
            Err(MintError::TokenOutstanding) => Err(MintError::TokenOutstanding),
            Err(MintError::LimitReached) => Err(MintError::LimitReached),
            Err(MintError::Unavailable) => Err(MintError::Unavailable),
            Err(MintError::Refused) => Err(MintError::Refused),
            Err(MintError::Failed) => Err(MintError::Failed),
        };
        Box::pin(async move { reply })
    }
}

fn on(subjects: &[&str]) -> (Router, Arc<Scripted>) {
    let enroller = Arc::new(Scripted {
        calls: Default::default(),
        reply: Mutex::new(Ok(())),
    });
    let active = Active {
        template: Template::mock(),
        enroller: enroller.clone(),
        public_origin: ORIGIN.into(),
        subjects: subjects.iter().map(|s| s.to_string()).collect(),
    };
    let mut st = AppState::for_tests(
        SESSION_SECRET,
        Arc::new(crate::fleet::Mock::new(1_779_192_000)),
    );
    st.enroll = Arc::new(Enroll::On(active));
    (router(st), enroller)
}

fn calls(e: &Scripted) -> usize {
    e.calls.lock().unwrap().len()
}

async fn get_status(app: &Router, who: Option<&str>) -> Reply {
    let mut req = Request::builder()
        .uri("/api/v1/enrollment")
        .header(header::HOST, "console.example.com");
    if let Some(who) = who {
        req = req.header(header::COOKIE, session_cookie(who));
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (parts, body) = res.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Reply {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body,
    }
}

#[tokio::test]
async fn the_origin_rule_refuses_before_any_upstream_call() {
    type Edits<'a> = Vec<(&'a str, Option<&'a str>)>;
    let refused: [(&str, Edits); 13] = [
        ("no origin", vec![("origin", None)]),
        (
            "another host",
            vec![("origin", Some("https://evil.example.com"))],
        ),
        ("null", vec![("origin", Some("null"))]),
        (
            "another port",
            vec![("origin", Some("https://console.example.com:8443"))],
        ),
        (
            "another scheme",
            vec![("origin", Some("http://console.example.com"))],
        ),
        (
            "a path",
            vec![("origin", Some("https://console.example.com/app"))],
        ),
        (
            "a trailing slash",
            vec![("origin", Some("https://console.example.com/"))],
        ),
        (
            "a referer instead",
            vec![
                ("origin", None),
                ("referer", Some("https://console.example.com/enroll")),
            ],
        ),
        ("cross-site", vec![("sec-fetch-site", Some("cross-site"))]),
        ("same-site", vec![("sec-fetch-site", Some("same-site"))]),
        ("none", vec![("sec-fetch-site", Some("none"))]),
        ("text/plain", vec![("content-type", Some("text/plain"))]),
        ("no content type", vec![("content-type", None)]),
    ];
    let (app, enroller) = on(&[]);
    for (what, edits) in refused {
        let r = post_files(&app, Some("alice"), &edits, "{}").await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (403, "origin_not_allowed"),
            "{what}: {}",
            r.text()
        );
    }
    assert_eq!(calls(&enroller), 0);
}

#[tokio::test]
async fn two_origin_headers_are_refused() {
    let (app, enroller) = on(&[]);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/enrollment/files")
        .header(header::HOST, "console.example.com")
        .header(header::COOKIE, session_cookie("alice"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, ORIGIN)
        .header(header::ORIGIN, ORIGIN)
        .body(Body::from("{}"))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(calls(&enroller), 0);
}

#[tokio::test]
async fn the_origin_is_compared_as_a_parsed_origin() {
    let (app, enroller) = on(&[]);
    for (what, origin) in [
        ("exact", "https://console.example.com"),
        ("upper-case host", "https://CONSOLE.Example.COM"),
        (
            "default port spelled out",
            "https://console.example.com:443",
        ),
        ("upper-case scheme", "HTTPS://console.example.com"),
    ] {
        let r = post_files(&app, Some("alice"), &[("origin", Some(origin))], "{}").await;
        assert_eq!(r.status, 200, "{what}: {}", r.text());
    }
    assert_eq!(calls(&enroller), 4);
}

#[tokio::test]
async fn a_content_type_with_parameters_and_any_case_is_json() {
    let (app, _) = on(&[]);
    let r = post_files(
        &app,
        Some("alice"),
        &[("content-type", Some("Application/JSON; charset=utf-8"))],
        "{}",
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
}

#[tokio::test]
async fn no_session_is_401_and_makes_no_call() {
    let (app, enroller) = on(&[]);
    for who in [None] {
        let r = post_files(&app, who, &[], "{}").await;
        assert_eq!((r.status, r.code().as_str()), (401, "unauthorized"));
    }
    assert_eq!(get_status(&app, None).await.status, 401);
    assert_eq!(calls(&enroller), 0);
}

#[tokio::test]
async fn a_subject_outside_the_list_is_refused_and_cannot_enroll() {
    let (app, enroller) = on(&["alice"]);
    let r = post_files(&app, Some("bob"), &[], "{}").await;
    assert_eq!((r.status, r.code().as_str()), (403, "not_an_enroller"));
    assert_eq!(calls(&enroller), 0);
    assert_eq!(
        get_status(&app, Some("bob")).await.json()["can_enroll"],
        false
    );
    assert_eq!(
        get_status(&app, Some("alice")).await.json()["can_enroll"],
        true
    );
    assert_eq!(post_files(&app, Some("alice"), &[], "{}").await.status, 200);
    assert_eq!(calls(&enroller), 1);
    // With no list every signed-in subject may.
    let (open, _) = on(&[]);
    assert_eq!(
        get_status(&open, Some("bob")).await.json()["can_enroll"],
        true
    );
}

#[tokio::test]
async fn off_reports_the_missing_names_and_the_post_is_404() {
    let app = router(AppState::for_tests(
        SESSION_SECRET,
        Arc::new(crate::fleet::Mock::new(1_779_192_000)),
    ));
    let r = get_status(&app, Some("alice")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"enabled": false, "missing": REQUIRED}));
    assert_eq!(r.headers["cache-control"], "no-store");
    let r = post_files(&app, Some("alice"), &[], "{}").await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (404, "enrollment_not_configured")
    );
}

#[tokio::test]
async fn on_reports_what_a_file_made_now_holds_and_no_secret() {
    let (app, _) = on(&[]);
    let r = get_status(&app, Some("alice")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.headers["cache-control"], "no-store");
    let v = r.json();
    let keys: HashSet<_> = v.as_object().unwrap().keys().cloned().collect();
    let want = [
        "enabled",
        "can_enroll",
        "server_url",
        "enroll_url",
        "ca",
        "policy_keys",
    ];
    assert_eq!(keys, want.iter().map(|s| s.to_string()).collect());
    assert_eq!(v["enabled"], true);
    assert_eq!(v["server_url"], "https://lodeline.example.com:8443");
    assert_eq!(v["enroll_url"], "https://lodeline.example.com:8444");
    assert!(v["ca"][0]["subject"]
        .as_str()
        .unwrap()
        .contains("lodeline-mock-ca"));
    assert_eq!(
        v["ca"][0]["sha256"].as_str().unwrap().split(':').count(),
        32
    );
    let key = &v["policy_keys"][0];
    assert_eq!(key["id"], "mock-key-1");
    assert_eq!(key["valid_from"], "2020-01-01T00:00:00Z");
    assert_eq!(key["valid_until"], "2099-01-01T00:00:00Z");
    assert_eq!(key["sha256"].as_str().unwrap().split(':').count(), 32);
    assert!(!r.text().contains("ed25519_pubkey_b64") && !r.text().contains("token"));
}

#[tokio::test]
async fn a_given_host_id_goes_to_the_server_unchanged_and_a_bad_one_never_does() {
    let (app, enroller) = on(&[]);
    let given = "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f";
    let r = post_files(
        &app,
        Some("alice"),
        &[],
        &json!({"host_id": given}).to_string(),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["host_id"], given);
    assert_eq!(
        *enroller.calls.lock().unwrap(),
        [(given.to_owned(), "alice".to_owned())]
    );
    for bad in [
        "3F2C6A1E-8B4D-4C2A-9E7F-1A2B3C4D5E6F",
        "018f9c1a-0000-7000-8000-0000000000aa",
        "3f2c6a1e8b4d4c2a9e7f1a2b3c4d5e6f",
        "",
        "not a uuid",
    ] {
        let r = post_files(
            &app,
            Some("alice"),
            &[],
            &json!({"host_id": bad}).to_string(),
        )
        .await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (422, "invalid_host_id"),
            "{bad:?}"
        );
    }
    assert_eq!(calls(&enroller), 1);
}

#[tokio::test]
async fn the_body_is_empty_object_or_a_host_id_and_nothing_else() {
    let (app, enroller) = on(&[]);
    for bad in [
        r#"{"host_id":"3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f","ttl_seconds":5}"#,
        r#"{"ttl":1}"#,
        r#"{"host_id":5}"#,
        r#"[]"#,
        r#"null"#,
        r#"{"#,
        "",
    ] {
        let r = post_files(&app, Some("alice"), &[], bad).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (400, "invalid_request"),
            "{bad}"
        );
    }
    let big = format!(r#"{{"host_id":"{}"}}"#, "a".repeat(2000));
    assert_eq!(post_files(&app, Some("alice"), &[], &big).await.status, 413);
    assert_eq!(calls(&enroller), 0);
    assert_eq!(
        post_files(&app, Some("alice"), &[], r#"{"host_id":null}"#)
            .await
            .status,
        200
    );
}

#[tokio::test]
async fn a_made_host_id_is_a_canonical_version_4_uuid_and_differs_each_time() {
    let (app, enroller) = on(&[]);
    let mut seen = HashSet::new();
    for _ in 0..200 {
        let r = post_files(&app, Some("alice"), &[], "{}").await;
        assert_eq!(r.status, 200);
        let id = r.headers["x-lodeline-enroll-host-id"]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(r.json()["host_id"], id.as_str());
        assert!(crate::enroll::is_canonical_v4(&id), "{id}");
        assert!(seen.insert(id));
    }
    assert_eq!(calls(&enroller), 200);
    assert_ne!(new_host_id().unwrap(), new_host_id().unwrap());
}

#[tokio::test]
async fn each_failure_of_the_mint_has_its_own_answer_and_text() {
    let (app, enroller) = on(&[]);
    let table = [
        (MintError::HostExists, 409, "host_exists", "enroll-token"),
        (
            MintError::TokenOutstanding,
            409,
            "token_outstanding",
            "wait until it expires",
        ),
        (
            MintError::LimitReached,
            429,
            "enrollment_limit_reached",
            "Try again",
        ),
        (
            MintError::Unavailable,
            502,
            "enroll_unavailable",
            "mint certificate",
        ),
        (MintError::Refused, 502, "enroll_refused", "refused"),
        (MintError::Failed, 502, "enroll_failed", "No file was made"),
    ];
    for (err, status, code, text) in table {
        *enroller.reply.lock().unwrap() = Err(err);
        let r = post_files(&app, Some("alice"), &[], "{}").await;
        assert_eq!((r.status, r.code().as_str()), (status, code));
        assert!(
            r.json()["error"]["message"]
                .as_str()
                .unwrap()
                .contains(text),
            "{code}: {}",
            r.text()
        );
        assert!(!r.text().contains("SECRETTOKEN"));
        assert!(r.headers.get("content-disposition").is_none());
    }
}

#[tokio::test]
async fn the_file_is_the_servers_answer_in_the_readers_format() {
    let (app, _) = on(&[]);
    let r = post_files(&app, Some("alice"), &[], "{}").await;
    assert_eq!(r.status, 200);
    let v: Value = r.json();
    assert_eq!(v["lodeline_enrollment"], 1);
    assert_eq!(v["token"], "scripted-token-SECRETTOKEN");
    assert_eq!(v["expires_at"], "2030-01-01T00:00:00Z");
    assert_eq!(
        r.headers["x-lodeline-enroll-expires-at"],
        "2030-01-01T00:00:00Z"
    );
    assert!(r.text().contains("\n  \"enroll_url\""), "pretty printed");
    assert!(r.body.ends_with(b"}\n"));
}
