//! Go's auth cases from `internal/api/v1/handlers_test.go` and `oidc_test.go`, with the exact
//! cookie forms Go writes.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{header, Method, Request};
use axum::Router;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::{json, Value};
use tower::ServiceExt;

use super::*;
use crate::auth::oidc::Oidc;
use crate::config::OidcConfig;
use crate::fleet;
use crate::server::router;
use crate::testutil::{authorize_redirect, OidcProvider};

const SECRET: &str = "0123456789abcdefghijklmnopqrstuv";

fn state() -> AppState {
    AppState::for_tests(SECRET, Arc::new(fleet::Mock::new(1_779_192_000)))
}

struct Reply {
    status: u16,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }

    fn cookies(&self) -> Vec<&str> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect()
    }
}

async fn call(app: &Router, method: Method, uri: &str, cookie: Option<&str>, body: &str) -> Reply {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "console.example");
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let (parts, body) = res.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    Reply {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

async fn login(app: &Router, username: &str, password: &str) -> Reply {
    let body = json!({"username": username, "password": password}).to_string();
    call(app, Method::POST, "/api/v1/auth/login", None, &body).await
}

/// The cookie's value and its attributes after the value.
fn split_cookie<'a>(cookie: &'a str, name: &str) -> (&'a str, &'a str) {
    let rest = cookie.strip_prefix(&format!("{name}=")).unwrap();
    rest.split_once(';').unwrap()
}

fn http_date(unix: i64) -> String {
    DateTime::from_timestamp(unix, 0)
        .unwrap()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

#[tokio::test]
async fn a_wrong_password_or_username_gets_the_same_401_after_the_delay() {
    let app = router(state());
    for (username, password) in [
        ("admin", "wrong"),
        ("not-admin", "test-password"),
        ("admin", ""),
        ("", ""),
    ] {
        let started = Instant::now();
        let r = login(&app, username, password).await;
        assert!(started.elapsed() >= LOGIN_FAIL_DELAY, "{username}");
        assert_eq!(r.status, 401, "{username}");
        assert_eq!(
            r.json(),
            json!({"error": {"code": "invalid_credentials", "message": "username or password is wrong"}})
        );
        assert!(r.cookies().is_empty());
    }
}

#[tokio::test]
async fn a_login_sets_the_session_cookie_as_go_does() {
    let app = router(state());
    let before = SystemTime::now();
    let r = login(&app, "admin", "test-password").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let body = r.json();
    assert_eq!(body["username"], "admin");
    let expires_at = GoTime::parse(body["expires_at"].as_str().unwrap()).unwrap();
    assert_eq!(expires_at.offset, 0);
    let ttl = 12 * 3600;
    let since = |t: SystemTime| t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    assert!((since(before) + ttl..=since(SystemTime::now()) + ttl).contains(&expires_at.unix));

    let cookies = r.cookies();
    assert_eq!(cookies.len(), 1);
    let (token, attributes) = split_cookie(cookies[0], COOKIE_NAME);
    assert_eq!(
        attributes,
        format!(
            " Path=/; Expires={}; Max-Age=43200; HttpOnly; SameSite=Lax",
            http_date(expires_at.unix)
        )
    );
    let (subject, exp) = state().signer.verify_with_exp(token).unwrap();
    assert_eq!((subject.as_str(), exp), ("admin", Some(expires_at.unix)));
}

#[tokio::test]
async fn cookies_carry_secure_unless_turned_off() {
    let mut st = state();
    st.auth = Arc::new(AuthConfig {
        admin_username: "admin".into(),
        admin_password_bcrypt: st.auth.admin_password_bcrypt.clone(),
        cookie_secure: true,
    });
    let app = router(st);
    let r = login(&app, "admin", "test-password").await;
    let cookie = r.cookies()[0].to_owned();
    assert!(
        cookie.ends_with("; HttpOnly; Secure; SameSite=Lax"),
        "{cookie}"
    );
    let session = cookie.split(';').next().unwrap();
    let r = call(&app, Method::POST, "/api/v1/auth/logout", Some(session), "").await;
    assert_eq!(
        r.cookies(),
        ["lodeline_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; Secure; SameSite=Lax"]
    );
}

#[tokio::test]
async fn login_bodies_decode_as_go_does() {
    let app = router(state());
    let cases = [
        (r#"{"USERNAME":"admin","Password":"test-password"}"#, 200),
        (
            r#"{"username":"admin","password":"test-password"} trailing"#,
            200,
        ),
        (
            r#"{"username":"admin","password":"test-password","x":1}"#,
            200,
        ),
        ("null", 401),
        ("[]", 400),
        ("", 400),
        (r#"{"username":"admin","password":12345}"#, 400),
        (r#"{"username":"#, 400),
    ];
    for (body, want) in cases {
        let r = call(&app, Method::POST, "/api/v1/auth/login", None, body).await;
        assert_eq!(r.status, want, "{body}");
        if want == 400 {
            assert_eq!(
                r.json(),
                json!({"error": {"code": "invalid_query", "message": "malformed JSON body"}})
            );
        }
    }
}

/// bcrypt and the failure delay run off the async runtime: on a single-threaded runtime, other
/// requests keep being answered while a failing login runs. The limit is half of the shorter
/// of one bcrypt check and the delay, either of which would stall the runtime if run on it.
#[test]
fn a_failing_login_does_not_hold_the_runtime() {
    let s = state();
    let started = Instant::now();
    assert!(!crate::auth::password_matches(
        "wrong",
        &s.auth.admin_password_bcrypt
    ));
    let limit = started.elapsed().min(LOGIN_FAIL_DELAY) / 2;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let app = router(s);
        let failing = tokio::spawn({
            let app = app.clone();
            async move { login(&app, "admin", "wrong").await.status }
        });
        let (mut worst, mut rounds) = (Duration::ZERO, 0);
        while !failing.is_finished() {
            let started = Instant::now();
            tokio::time::sleep(Duration::from_millis(10)).await;
            let health = call(&app, Method::GET, "/api/health", None, "").await;
            assert_eq!(health.status, 200);
            worst = worst.max(started.elapsed());
            rounds += 1;
        }
        assert_eq!(failing.await.unwrap(), 401);
        assert!(rounds >= 10, "{rounds}");
        assert!(worst < limit, "{worst:?} against {limit:?}");
    });
}

/// Go's JSON encoder escapes `<`, `>`, `&`, U+2028 and U+2029 in every body.
#[tokio::test]
async fn bodies_escape_html_characters_as_go_does() {
    let mut s = state();
    let username = "a<&>b\u{2028}\u{2029}";
    s.auth = Arc::new(AuthConfig {
        admin_username: username.into(),
        admin_password_bcrypt: s.auth.admin_password_bcrypt.clone(),
        cookie_secure: false,
    });
    let app = router(s);
    let r = login(&app, username, "test-password").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let want = r#"{"username":"a\u003c\u0026\u003eb\u2028\u2029","expires_at":""#;
    assert!(r.body.starts_with(want), "{}", r.body);
    let session = r.cookies()[0].split(';').next().unwrap().to_owned();
    let r = call(&app, Method::GET, "/api/v1/auth/me", Some(&session), "").await;
    assert!(r.body.starts_with(want), "{}", r.body);
}

#[tokio::test]
async fn me_requires_a_cookie_and_returns_subject_and_expiry() {
    let app = router(state());
    let r = call(&app, Method::GET, "/api/v1/auth/me", None, "").await;
    assert_eq!(r.status, 401);
    assert_eq!(r.json()["error"]["code"], "unauthorized");

    let r = login(&app, "admin", "test-password").await;
    let session = r.cookies()[0].split(';').next().unwrap().to_owned();
    let issued = GoTime::parse(r.json()["expires_at"].as_str().unwrap()).unwrap();
    let r = call(&app, Method::GET, "/api/v1/auth/me", Some(&session), "").await;
    assert_eq!(r.status, 200);
    let me = r.json();
    assert_eq!(me["username"], "admin");
    let exp = GoTime::parse(me["expires_at"].as_str().unwrap()).unwrap();
    // The token keeps whole seconds; Go writes them in the process time zone.
    assert_eq!((exp.unix, exp.nanos), (issued.unix, 0));
    assert_eq!(exp, local_time(issued.unix));
}

fn token(claims: Value) -> String {
    let t = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap();
    format!("lodeline_session={t}")
}

#[tokio::test]
async fn me_writes_a_missing_or_unwritable_expiry_as_go_does() {
    let app = router(state());
    let r = call(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        Some(&token(json!({"iss": "lodeline-manager", "sub": "admin"}))),
        "",
    )
    .await;
    assert_eq!(
        r.json(),
        json!({"username": "admin", "expires_at": "0001-01-01T00:00:00Z"})
    );
    // Past year 9999 Go's encoder fails after the status and Content-Type are out.
    for exp in [300_000_000_000_i64, 9_000_000_000_000_000] {
        let claims = json!({"iss": "lodeline-manager", "sub": "admin", "exp": exp});
        let r = call(
            &app,
            Method::GET,
            "/api/v1/auth/me",
            Some(&token(claims)),
            "",
        )
        .await;
        assert_eq!((r.status, r.body.as_str()), (200, ""), "{exp}");
        assert_eq!(r.headers[header::CONTENT_TYPE], "application/json");
    }
}

#[tokio::test]
async fn logout_writes_go_deletion_cookie() {
    let app = router(state());
    let session =
        token(json!({"iss": "lodeline-manager", "sub": "admin", "exp": 4_000_000_000_i64}));
    let r = call(
        &app,
        Method::POST,
        "/api/v1/auth/logout",
        Some(&session),
        "",
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"status": "ok"}));
    assert_eq!(
        r.cookies(),
        ["lodeline_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; SameSite=Lax"]
    );
    // Stateless, as in Go: the token still verifies after logout.
    let r = call(&app, Method::GET, "/api/v1/auth/me", Some(&session), "").await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn oidc_disabled() {
    let app = router(state());
    let r = call(&app, Method::GET, "/api/v1/auth/methods", None, "").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"local": true, "oidc": false}));
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
    for path in [
        "/api/v1/auth/oidc/start",
        "/api/v1/auth/oidc/callback?code=c&state=s",
    ] {
        let r = call(&app, Method::GET, path, None, "").await;
        assert_eq!((r.status, r.body.as_str()), (404, "404 page not found\n"));
        assert_eq!(r.headers[header::CACHE_CONTROL], "no-store", "{path}");
        assert_eq!(r.headers[header::REFERRER_POLICY], "no-referrer", "{path}");
        assert!(r.cookies().is_empty());
    }
}

async fn oidc_state(p: &OidcProvider) -> (AppState, Arc<Oidc>) {
    let c = OidcConfig {
        issuer: p.url.clone(),
        client_id: "console".into(),
        client_secret: "test-secret".into(),
        redirect_url: "https://console.example/api/v1/auth/oidc/callback".into(),
        allowed_subjects: vec!["employee-1".into()],
    };
    let oidc = Arc::new(Oidc::discover(&c, p.client()).await.unwrap());
    let mut st = state();
    st.oidc = Some(oidc.clone());
    st.auth = Arc::new(AuthConfig {
        admin_username: "admin".into(),
        admin_password_bcrypt: st.auth.admin_password_bcrypt.clone(),
        cookie_secure: true,
    });
    (st, oidc)
}

const CLEAR_BINDING: &str =
    "lodeline_oidc_binding=; Path=/api/v1/auth/oidc; Max-Age=0; HttpOnly; Secure; SameSite=Lax";

fn failed(r: &Reply) {
    assert_eq!(r.status, 303);
    assert_eq!(r.headers[header::LOCATION], "/login?oidc_error=1");
    assert_eq!(r.body, "<a href=\"/login?oidc_error=1\">See Other</a>.\n\n");
    assert_eq!(r.cookies(), [CLEAR_BINDING]);
}

/// Go's `TestOIDCRoutesSessionAndFailure`, with the exact headers and cookies.
#[tokio::test]
async fn oidc_routes_session_and_failure() {
    let p = OidcProvider::start(false).await;
    let (st, _) = oidc_state(&p).await;
    let signer = st.signer.clone();
    let app = router(st);

    let r = call(&app, Method::GET, "/api/v1/auth/methods", None, "").await;
    assert_eq!(r.json(), json!({"local": true, "oidc": true}));

    let start = call(&app, Method::GET, "/api/v1/auth/oidc/start", None, "").await;
    assert_eq!(start.status, 302);
    assert_eq!(start.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(start.headers[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(
        start.headers[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    let location = start.headers[header::LOCATION].to_str().unwrap().to_owned();
    assert!(location.starts_with(&format!("{}/authorize?client_id=console&", p.url)));
    assert_eq!(
        start.body,
        format!(
            "<a href=\"{}\">Found</a>.\n\n",
            location.replace('&', "&amp;")
        )
    );
    let cookies = start.cookies();
    assert_eq!(cookies.len(), 1);
    let (binding, attributes) = split_cookie(cookies[0], BINDING_COOKIE);
    assert_eq!(binding.len(), 43);
    assert_eq!(
        attributes,
        " Path=/api/v1/auth/oidc; Max-Age=300; HttpOnly; Secure; SameSite=Lax"
    );

    let callback = authorize_redirect(&p.client(), &location).await;
    let path = format!("/api/v1/auth/oidc/callback?{}", callback.query().unwrap());
    let binding_cookie = format!("{BINDING_COOKIE}={binding}");

    failed(&call(&app, Method::GET, &path, None, "").await);
    let success = call(&app, Method::GET, &path, Some(&binding_cookie), "").await;
    assert_eq!(success.status, 303);
    assert_eq!(success.headers[header::LOCATION], "/alerts");
    assert_eq!(success.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(success.headers[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(success.body, "<a href=\"/alerts\">See Other</a>.\n\n");
    let cookies = success.cookies();
    assert_eq!(cookies.len(), 2);
    assert_eq!(cookies[0], CLEAR_BINDING);
    let (token, attributes) = split_cookie(cookies[1], COOKIE_NAME);
    let (subject, exp) = signer.verify_with_exp(token).unwrap();
    let exp = exp.unwrap();
    assert_eq!(subject, auth::oidc::identity(&p.url, "employee-1"));
    let max_age: i64 = attributes
        .split("Max-Age=")
        .nth(1)
        .and_then(|s| s.split(';').next())
        .unwrap()
        .parse()
        .unwrap();
    assert!((3590..=3600).contains(&max_age), "{max_age}");
    assert_eq!(
        attributes,
        format!(
            " Path=/; Expires={}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax",
            http_date(exp)
        )
    );

    let session = format!("{COOKIE_NAME}={token}");
    let me = call(&app, Method::GET, "/api/v1/auth/me", Some(&session), "").await;
    assert_eq!(me.status, 200);
    assert_eq!(me.json()["username"], subject);

    failed(&call(&app, Method::GET, &path, Some(&binding_cookie), "").await);
}

/// An `error` from the provider fails the login whatever else the query holds, uses up the
/// attempt, and none of the provider's text reaches the answer.
#[tokio::test]
async fn an_oidc_error_answer_fails_closed() {
    let p = OidcProvider::start(false).await;
    let (st, _) = oidc_state(&p).await;
    let app = router(st);
    let start = call(&app, Method::GET, "/api/v1/auth/oidc/start", None, "").await;
    let location = start.headers[header::LOCATION].to_str().unwrap();
    let (binding, _) = split_cookie(start.cookies()[0], BINDING_COOKIE);
    let binding_cookie = format!("{BINDING_COOKIE}={binding}");
    let callback = authorize_redirect(&p.client(), location).await;
    let path = format!(
        "/api/v1/auth/oidc/callback?error=access_denied&error_description=%3Cb%3Eno%3C%2Fb%3E&{}",
        callback.query().unwrap()
    );
    let r = call(&app, Method::GET, &path, Some(&binding_cookie), "").await;
    failed(&r);
    assert!(!r.body.contains("access_denied") && !r.body.contains("<b>"));
    let path = format!("/api/v1/auth/oidc/callback?{}", callback.query().unwrap());
    failed(&call(&app, Method::GET, &path, Some(&binding_cookie), "").await);
}

#[tokio::test]
async fn oidc_start_answers_503_while_1024_logins_are_pending() {
    let p = OidcProvider::start(false).await;
    let (st, oidc) = oidc_state(&p).await;
    let app = router(st);
    for _ in 0..1024 {
        oidc.begin().unwrap();
    }
    let r = call(&app, Method::GET, "/api/v1/auth/oidc/start", None, "").await;
    assert_eq!(r.status, 503);
    assert_eq!(
        r.json(),
        json!({"error": {"code": "login_unavailable", "message": "Sign-in is busy. Try again shortly."}})
    );
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
    assert!(r.cookies().is_empty());
}
