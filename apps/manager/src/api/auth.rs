//! The `/api/v1/auth/*` handlers (Go's `internal/api/v1/auth.go` and `oidc.go`).
//!
//! The session is a stateless signed cookie: logout clears the browser's copy and does not
//! revoke the token. There is no CSRF token; `SameSite=Lax` keeps the cookie off cross-site
//! subrequests and POSTs, which covers other sites but not other origins of the same site.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Local, Offset, TimeZone, Utc};
use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::api::{go_object, read_body, set, write_json, Query, LOGIN_BODY_LIMIT};
use crate::auth::{self, go_fold, request_cookie, COOKIE_NAME};
use crate::fleet::GoTime;
use crate::server::{error_response, text_response, AppState};

/// The wait on every failed credential check, so a wrong username and a wrong password take
/// the same time.
const LOGIN_FAIL_DELAY: Duration = Duration::from_millis(250);
const BINDING_COOKIE: &str = "lodeline_oidc_binding";
const OIDC_FAILED: &str = "/login?oidc_error=1";

/// The local admin, and whether cookies carry `Secure`.
pub struct AuthConfig {
    pub admin_username: String,
    pub admin_password_bcrypt: String,
    /// False only with `LODELINE_INSECURE_COOKIE=1`.
    pub cookie_secure: bool,
}

#[derive(Serialize)]
struct Session<'a> {
    username: &'a str,
    expires_at: GoTime,
}

#[derive(Default)]
struct LoginBody {
    username: String,
    password: String,
}

/// Go's `handleLogin`. The body is read as Go's decoder reads it, and only as `application/json`.
pub async fn login(State(s): State<AppState>, req: Request) -> Response {
    let body = match read_body(req, LOGIN_BODY_LIMIT).await {
        Ok(body) => body.and_then(|b| login_body(&b)),
        Err(e) => return e.into_response(),
    };
    let Some(body) = body else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "malformed JSON body",
        );
    };
    // Both checks always run, so the time taken does not tell whether the username exists.
    let username_ok: bool = body
        .username
        .as_bytes()
        .ct_eq(s.auth.admin_username.as_bytes())
        .into();
    let hash = s.auth.admin_password_bcrypt.clone();
    let password_ok =
        tokio::task::spawn_blocking(move || auth::password_matches(&body.password, &hash))
            .await
            .unwrap_or(false);
    if !username_ok || !password_ok {
        tokio::time::sleep(LOGIN_FAIL_DELAY).await;
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "username or password is wrong",
        );
    }

    let Some((token, exp)) = s.signer.sign_until(&s.auth.admin_username, None) else {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "failed to issue session",
        );
    };
    let max_age = s.signer.ttl().as_secs() as i64;
    let mut res = write_json(&Session {
        username: &s.auth.admin_username,
        expires_at: go_time(exp),
    });
    let cookie = set_cookie(
        COOKIE_NAME,
        &token,
        "/",
        Some(exp),
        max_age,
        s.auth.cookie_secure,
    );
    res.headers_mut().append(header::SET_COOKIE, cookie);
    res
}

fn login_body(raw: &[u8]) -> Option<LoginBody> {
    let mut b = LoginBody::default();
    for (key, value) in go_object(raw)? {
        match go_fold(&key).as_str() {
            "username" => set(&mut b.username, &value)?,
            "password" => set(&mut b.password, &value)?,
            _ => {}
        }
    }
    Some(b)
}

/// Go's `handleLogout`: a deletion cookie, whether or not the token is still valid elsewhere.
pub async fn logout(State(s): State<AppState>) -> Response {
    let mut res = write_json(&serde_json::json!({"status": "ok"}));
    let cookie = set_cookie(
        COOKIE_NAME,
        "",
        "/",
        Some(UNIX_EPOCH),
        -1,
        s.auth.cookie_secure,
    );
    res.headers_mut().append(header::SET_COOKIE, cookie);
    res
}

/// Go's `handleMe`: the subject and the token's `exp`, in the process time zone as Go writes
/// it, or Go's zero time for a token without one.
pub async fn me(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let unauthorized = |message| error_response(StatusCode::UNAUTHORIZED, "unauthorized", message);
    let Some(token) = request_cookie(&headers, COOKIE_NAME) else {
        return unauthorized("session cookie missing");
    };
    match s.signer.verify_with_exp(token) {
        Ok((subject, exp)) => write_json(&Session {
            username: &subject,
            expires_at: exp.map_or_else(GoTime::default, local_time),
        }),
        Err(_) => unauthorized("invalid session"),
    }
}

pub async fn methods(State(s): State<AppState>) -> Response {
    let mut res = write_json(&serde_json::json!({"local": true, "oidc": s.oidc.is_some()}));
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Go's `handleOIDCStart`: 302 to the provider with a fresh binding cookie, 404 with OIDC off.
pub async fn oidc_start(State(s): State<AppState>) -> Response {
    let res = match &s.oidc {
        None => text_response(StatusCode::NOT_FOUND, "404 page not found\n"),
        Some(oidc) => match oidc.begin() {
            None => error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "login_unavailable",
                "Sign-in is busy. Try again shortly.",
            ),
            Some((location, binding)) => {
                let max_age = auth::oidc::LOGIN_ATTEMPT_TTL.as_secs() as i64;
                let cookie = binding_cookie(&binding, max_age, s.auth.cookie_secure);
                redirect(StatusCode::FOUND, &location, vec![cookie])
            }
        },
    };
    no_store(res)
}

/// Go's `handleOIDCCallback`: always clears the binding cookie, then 303 to `/alerts` with a
/// session, or to the login page on any failure. Provider errors and text are never shown.
pub async fn oidc_callback(State(s): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(oidc) = &s.oidc else {
        return no_store(text_response(StatusCode::NOT_FOUND, "404 page not found\n"));
    };
    let secure = s.auth.cookie_secure;
    let mut cookies = vec![binding_cookie("", -1, secure)];
    let mut target = OIDC_FAILED;
    if let Some(binding) = request_cookie(&headers, BINDING_COOKIE) {
        let q = Query::parse(uri.query());
        let code = if q.get("error").is_empty() {
            q.get("code")
        } else {
            ""
        };
        let session =
            oidc.complete(q.get("state"), binding, code)
                .await
                .and_then(|(subject, exp)| {
                    let deadline = u64::try_from(exp)
                        .ok()
                        .and_then(|secs| UNIX_EPOCH.checked_add(Duration::from_secs(secs)));
                    s.signer.sign_until(&subject, deadline)
                });
        if let Some((token, exp)) = session {
            let left = exp
                .duration_since(SystemTime::now())
                .map_or(0, |d| d.as_secs() as i64);
            cookies.push(set_cookie(
                COOKIE_NAME,
                &token,
                "/",
                Some(exp),
                left.max(1),
                secure,
            ));
            target = "/alerts";
        }
    }
    no_store(redirect(StatusCode::SEE_OTHER, target, cookies))
}

fn binding_cookie(value: &str, max_age: i64, secure: bool) -> HeaderValue {
    set_cookie(
        BINDING_COOKIE,
        value,
        "/api/v1/auth/oidc",
        None,
        max_age,
        secure,
    )
}

/// Go's `http.Cookie.String` for the attributes these cookies use: a negative `max_age` writes
/// `Max-Age=0`, zero writes none.
fn set_cookie(
    name: &str,
    value: &str,
    path: &str,
    expires: Option<SystemTime>,
    max_age: i64,
    secure: bool,
) -> HeaderValue {
    let mut c = format!("{name}={value}; Path={path}");
    if let Some(t) = expires {
        let t = DateTime::<Utc>::from(t);
        c += &t.format("; Expires=%a, %d %b %Y %H:%M:%S GMT").to_string();
    }
    if max_age > 0 {
        c += &format!("; Max-Age={max_age}");
    } else if max_age < 0 {
        c += "; Max-Age=0";
    }
    c += "; HttpOnly";
    if secure {
        c += "; Secure";
    }
    c += "; SameSite=Lax";
    HeaderValue::from_str(&c).expect("cookie text is visible ASCII")
}

/// Go's `http.Redirect` for a GET: the location with non-ASCII bytes escaped, and a short HTML
/// body. The local targets here are already clean paths, which Go leaves as they are.
fn redirect(status: StatusCode, location: &str, cookies: Vec<HeaderValue>) -> Response {
    let body = format!(
        "<a href=\"{}\">{}</a>.\n\n",
        html_escape(location),
        status.canonical_reason().unwrap_or_default()
    );
    let mut res = (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response();
    let mut escaped = String::with_capacity(location.len());
    for b in location.bytes() {
        match b {
            0x80.. => escaped += &format!("%{b:x}"),
            b => escaped.push(char::from(b)),
        }
    }
    // Discovery accepted only URLs that Go's parser takes, which have no control bytes.
    let location = HeaderValue::from_str(&escaped).expect("location is visible ASCII");
    let h = res.headers_mut();
    h.insert(header::LOCATION, location);
    for cookie in cookies {
        h.append(header::SET_COOKIE, cookie);
    }
    res
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

fn no_store(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    res
}

/// The session end as Go's login writes it: UTC with the fraction kept.
fn go_time(t: SystemTime) -> GoTime {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    GoTime {
        unix: d.as_secs() as i64,
        nanos: d.subsec_nanos(),
        offset: 0,
    }
}

/// Go's `time.Unix(exp, 0)`, which is in the process time zone.
fn local_time(exp: i64) -> GoTime {
    let offset = Local
        .timestamp_opt(exp, 0)
        .single()
        .map_or(0, |t| t.offset().fix().local_minus_utc());
    GoTime {
        unix: exp,
        nanos: 0,
        offset,
    }
}

#[cfg(test)]
mod tests;
