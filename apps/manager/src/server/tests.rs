use super::*;
use axum::body::Body;
use jsonwebtoken::{encode, EncodingKey, Header};
use tower::ServiceExt;

const SECRET: &str = "0123456789abcdefghijklmnopqrstuv";

fn app() -> Router {
    router(AppState::for_tests(
        SECRET,
        Arc::new(fleet::Mock::new(1_767_225_600)),
    ))
}

fn session(exp: i64) -> String {
    let claims = serde_json::json!({"iss": "lodeline-manager", "sub": "admin", "exp": exp});
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap();
    format!("lodeline_session={token}")
}

async fn send(method: Method, uri: &str, cookie: Option<&str>) -> (Response, String) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "console.example");
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    call(app(), req.body(Body::empty()).unwrap()).await
}

async fn call(app: Router, req: Request) -> (Response, String) {
    let res = app.oneshot(req).await.unwrap();
    let (parts, body) = res.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    (
        Response::from_parts(parts, Body::empty()),
        String::from_utf8(bytes.to_vec()).unwrap(),
    )
}

fn assert_security_headers(res: &Response, what: &str) {
    let h = res.headers();
    assert_eq!(
        h[header::CONTENT_SECURITY_POLICY],
        CONTENT_SECURITY_POLICY,
        "{what}"
    );
    assert_eq!(h[header::X_FRAME_OPTIONS], "DENY", "{what}");
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff", "{what}");
    assert_eq!(h[header::REFERRER_POLICY], "no-referrer", "{what}");
    assert!(!h.contains_key(header::STRICT_TRANSPORT_SECURITY), "{what}");
}

#[tokio::test]
async fn health_reports_status_version_and_time() {
    let (res, body) = send(Method::GET, "/api/health", None).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "application/json");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    assert!(v["timestamp"].as_str().unwrap().ends_with('Z'));
    assert_security_headers(&res, "health");
}

#[tokio::test]
async fn other_methods_get_chi_405_before_auth() {
    for (method, uri, allow) in [
        (Method::POST, "/api/health", "GET"),
        (Method::HEAD, "/api/health", "GET"),
        (Method::GET, "/api/v1/auth/login", "POST"),
        (Method::POST, "/api/v1/fleet/meta", "GET"),
        (Method::HEAD, "/api/v1/fleet/hosts/h1", "GET"),
    ] {
        let (res, body) = send(method.clone(), uri, None).await;
        assert_eq!(
            res.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {uri}"
        );
        assert_eq!(res.headers()[header::ALLOW], allow, "{method} {uri}");
        assert!(body.is_empty(), "{method} {uri}");
        let length = res.headers().get(header::CONTENT_LENGTH);
        let want = (method != Method::HEAD).then_some("0");
        assert_eq!(length.map(|v| v.to_str().unwrap()), want, "{method} {uri}");
        assert_security_headers(&res, uri);
    }
}

/// What a valid session gets with no body or `Content-Type`: the mock fleet's answer or an empty
/// triage store's.
fn authorized_status(uri: &str) -> u16 {
    match uri {
        "/api/v1/fleet/events/e1" | "/api/v1/fleet/hosts/h1" | "/api/v1/triage/h1/e1" => 404,
        "/api/v1/triage/upsert" | "/api/v1/triage/note" => 415,
        _ => 200,
    }
}

#[tokio::test]
async fn session_routes_answer_401_forms() {
    let future = session(4_000_000_000);
    let expired = session(1_600_000_000);
    for (method, uri) in ROUTES
        .iter()
        .filter(|(_, _, access)| *access == Access::Session)
        .map(|(m, p, _)| {
            (
                m.clone(),
                p.replace("{event_id}", "e1").replace("{host_id}", "h1"),
            )
        })
    {
        for (cookie, status, code) in [
            (None, 401, Some(("unauthorized", "session cookie missing"))),
            (
                Some("lodeline_session="),
                401,
                Some(("unauthorized", "session cookie missing")),
            ),
            (
                Some("lodeline_session=x"),
                401,
                Some(("unauthorized", "invalid session")),
            ),
            (
                Some(expired.as_str()),
                401,
                Some(("session_expired", "session expired, please log in again")),
            ),
            (Some(future.as_str()), authorized_status(&uri), None),
        ] {
            let (res, body) = send(method.clone(), &uri, cookie).await;
            assert_eq!(res.status().as_u16(), status, "{uri} {cookie:?}");
            assert_security_headers(&res, &uri);
            if let Some((code, message)) = code {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(
                    v,
                    serde_json::json!({"error": {"code": code, "message": message}}),
                    "{uri}"
                );
            }
        }
    }
}

#[tokio::test]
async fn unknown_api_paths_get_chi_404_text() {
    for uri in [
        "/api",
        "/api/",
        "/api/x",
        "/api/v1/nope",
        "/api/v1/fleet/meta/",
    ] {
        let (res, body) = send(Method::GET, uri, None).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(
            res.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert_eq!(body, "404 page not found\n", "{uri}");
        assert_security_headers(&res, uri);
    }
    let (res, _) = send(Method::GET, "//api/health", None).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
}

#[tokio::test]
async fn a_bad_percent_escape_is_refused_before_routing() {
    for uri in ["/%zz", "/api/health%2", "/assets/%g0.js"] {
        let (res, body) = send(Method::GET, uri, None).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(body, "400 Bad Request");
        assert!(!res.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    }
}

#[tokio::test]
async fn host_headers_are_checked_before_routing_as_go_does() {
    let cases: [(Version, &[&str], &str); 5] = [
        (
            Version::HTTP_11,
            &[],
            "400 Bad Request: missing required Host header",
        ),
        (Version::HTTP_11, &["a", "b"], "400 Bad Request"),
        (Version::HTTP_10, &["a", "b"], "400 Bad Request"),
        (
            Version::HTTP_11,
            &["a b"],
            "400 Bad Request: malformed Host header",
        ),
        (
            Version::HTTP_10,
            &["a/b"],
            "400 Bad Request: malformed Host header",
        ),
    ];
    for (version, hosts, want) in cases {
        let mut req = Request::builder().uri("/api/health").version(version);
        for host in hosts {
            req = req.header(header::HOST, *host);
        }
        let (res, body) = call(app(), req.body(Body::empty()).unwrap()).await;
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "{version:?} {hosts:?}"
        );
        assert_eq!(body, want, "{version:?} {hosts:?}");
        assert!(!res.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    }
    for (version, host) in [
        (Version::HTTP_10, None),
        (Version::HTTP_11, Some("[::1]:8080")),
    ] {
        let mut req = Request::builder().uri("/api/health").version(version);
        if let Some(host) = host {
            req = req.header(header::HOST, host);
        }
        let (res, _) = call(app(), req.body(Body::empty()).unwrap()).await;
        assert_eq!(res.status(), StatusCode::OK, "{version:?} {host:?}");
    }
}

#[tokio::test]
async fn a_panicking_handler_gets_chi_recoverer_500_with_security_headers() {
    async fn boom() -> Response {
        panic!("handler panicked on purpose")
    }
    let boom = Router::new().route("/boom", axum::routing::get(boom));
    let req = Request::builder()
        .uri("/boom")
        .header(header::HOST, "console.example")
        .body(Body::empty())
        .unwrap();
    let (res, body) = call(with_middleware(boom), req).await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, "");
    assert!(!res.headers().contains_key(header::CONTENT_TYPE));
    assert_security_headers(&res, "panic");
}

/// Every route in the router has a row in the parity table, and the other way round.
#[test]
fn routes_match_the_parity_table() {
    let cases = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/web/tests/parity/cases.ts"
    ))
    .unwrap();
    let block = cases
        .split_once("export const ROUTES = [")
        .and_then(|(_, rest)| rest.split_once("] as const;"))
        .expect("ROUTES in cases.ts")
        .0;
    let table: Vec<&str> = block
        .lines()
        .filter_map(|l| l.trim().strip_prefix('\'')?.strip_suffix("',"))
        .filter(|r| *r != "GET /*")
        .collect();
    let ours: Vec<String> = ROUTES.iter().map(|(m, p, _)| format!("{m} {p}")).collect();
    assert_eq!(ours, table);
}

fn post(uri: &str, content_type: Option<&str>, cookie: Option<&str>, body: Body) -> Request {
    let mut req = Request::post(uri).header(header::HOST, "console.example");
    if let Some(content_type) = content_type {
        req = req.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    req.body(body).unwrap()
}

const UNSUPPORTED: &str = "{\"error\":{\"code\":\"unsupported_media_type\",\"message\":\"Content-Type must be application/json\"}}\n";

/// The body routes read only `application/json`, whatever its case or parameters.
#[tokio::test]
async fn bodies_must_be_application_json() {
    let app = app();
    let cookie = session(4_000_000_000);
    for (uri, body, ok) in [
        (
            "/api/v1/auth/login",
            r#"{"username":"admin","password":"wrong"}"#,
            401,
        ),
        (
            "/api/v1/triage/upsert",
            r#"{"host_id":"h1","event_id":"e1","status":"open","evidence_snapshot":{}}"#,
            200,
        ),
        (
            "/api/v1/triage/note",
            r#"{"host_id":"h1","event_id":"e1","body":"n"}"#,
            200,
        ),
    ] {
        for (content_type, want) in [
            (Some("text/plain"), 415),
            (Some("text/plain;charset=UTF-8"), 415),
            (None, 415),
            (Some("application/x-www-form-urlencoded"), 415),
            (Some("multipart/form-data; boundary=x"), 415),
            (Some("application/vnd.api+json"), 415),
            (Some("application/json; charset=utf-8"), ok),
            (Some("Application/JSON"), ok),
            (Some("application/json"), ok),
        ] {
            let req = post(uri, content_type, Some(&cookie), Body::from(body));
            let (res, text) = call(app.clone(), req).await;
            assert_eq!(res.status(), want, "{uri} {content_type:?}");
            if want == 415 {
                assert_eq!(text, UNSUPPORTED, "{uri} {content_type:?}");
            }
        }
    }
}

/// The type is checked before any of the body is read.
#[tokio::test]
async fn the_type_is_checked_before_the_body_is_read() {
    let cookie = session(4_000_000_000);
    for uri in [
        "/api/v1/auth/login",
        "/api/v1/triage/upsert",
        "/api/v1/triage/note",
    ] {
        let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let body = Body::new(crate::testutil::Trickle {
            prefix: b"{",
            filler: b' ',
            total: 1 << 20,
            stall: true,
            sent: sent.clone(),
        });
        let req = post(uri, Some("text/plain"), Some(&cookie), body);
        let (res, _) = call(app(), req).await;
        assert_eq!(res.status(), 415, "{uri}");
        assert_eq!(sent.load(std::sync::atomic::Ordering::Relaxed), 0, "{uri}");
    }
}

/// A session check still answers first, and a refused login still counts toward the limit.
#[tokio::test]
async fn auth_and_the_login_limit_come_before_the_type_check() {
    for uri in ["/api/v1/triage/upsert", "/api/v1/triage/note"] {
        let (res, _) = call(app(), post(uri, Some("text/plain"), None, Body::from("{}"))).await;
        assert_eq!(res.status(), 401, "{uri}");
    }
    let app = app();
    for _ in 0..10 {
        let req = post(
            "/api/v1/auth/login",
            Some("text/plain"),
            None,
            Body::from("{}"),
        );
        assert_eq!(call(app.clone(), req).await.0.status(), 415);
    }
    let req = post(
        "/api/v1/auth/login",
        Some("application/json"),
        None,
        Body::from("{}"),
    );
    assert_eq!(call(app, req).await.0.status(), 429);
}
