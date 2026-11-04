//! The HTTP surface: Go's chi router (`internal/server`, `internal/api/v1/server.go`) with its
//! security headers, access log, 404 and 405 forms, and the SPA catch-all.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::handler::Handler;
use axum::http::{header, HeaderValue, Method, StatusCode, Version};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, MethodRouter};
use axum::Router;
use hyper::body::Frame;
use hyper::ext::ReasonPhrase;
use tower_http::catch_panic::CatchPanicLayer;

use crate::api::auth::AuthConfig;
use crate::api::ratelimit::{self, RateLimiter};
use crate::auth::oidc::Oidc;
use crate::auth::{require_auth, Signer};
use crate::{api, config, fleet, spa, triage};

#[derive(Clone)]
pub struct AppState {
    pub signer: Arc<Signer>,
    pub auth: Arc<AuthConfig>,
    /// `None` when OIDC is not configured.
    pub oidc: Option<Arc<Oidc>>,
    pub fleet: Arc<dyn fleet::Client>,
    pub triage: Arc<triage::Store>,
    /// The login limiter's trusted proxies (`TRUSTED_PROXIES`).
    pub trusted_proxies: Arc<[ipnet::IpNet]>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    Public,
    Session,
}

#[cfg(test)]
impl AppState {
    /// Go's handler test harness: admin `admin` with password `test-password`, a 12 hour
    /// session, cookies without `Secure`, OIDC off and an empty in-memory triage store.
    pub fn for_tests(secret: &str, fleet: Arc<dyn fleet::Client>) -> Self {
        Self {
            signer: Arc::new(
                Signer::new(secret.as_bytes(), Duration::from_secs(12 * 3600)).unwrap(),
            ),
            auth: Arc::new(AuthConfig {
                admin_username: "admin".into(),
                admin_password_bcrypt:
                    "$2a$10$wfv94g2jgl.5WmoEZHXfw.WMQSDL6HzwEq0avcAT1QmtrqBWUf7wu".into(),
                cookie_secure: false,
            }),
            oidc: None,
            fleet,
            triage: Arc::new(triage::Store::open(":memory:").unwrap()),
            trusted_proxies: Arc::new([]),
        }
    }
}

/// Every API route of the Go router, in chi pattern syntax. Session routes sit behind
/// `require_auth`. The parity table must list each one (see the route test).
pub const ROUTES: [(Method, &str, Access); 18] = [
    (Method::GET, "/api/health", Access::Public),
    (Method::POST, "/api/v1/auth/login", Access::Public),
    (Method::GET, "/api/v1/auth/methods", Access::Public),
    (Method::GET, "/api/v1/auth/oidc/start", Access::Public),
    (Method::GET, "/api/v1/auth/oidc/callback", Access::Public),
    (Method::POST, "/api/v1/auth/logout", Access::Session),
    (Method::GET, "/api/v1/auth/me", Access::Session),
    (Method::GET, "/api/v1/fleet/meta", Access::Session),
    (Method::GET, "/api/v1/fleet/healthz", Access::Session),
    (Method::GET, "/api/v1/fleet/events", Access::Session),
    (
        Method::GET,
        "/api/v1/fleet/events/{event_id}",
        Access::Session,
    ),
    (Method::GET, "/api/v1/fleet/risk", Access::Session),
    (Method::GET, "/api/v1/fleet/compliance", Access::Session),
    (Method::GET, "/api/v1/fleet/hosts", Access::Session),
    (
        Method::GET,
        "/api/v1/fleet/hosts/{host_id}",
        Access::Session,
    ),
    (Method::POST, "/api/v1/triage/upsert", Access::Session),
    (Method::POST, "/api/v1/triage/note", Access::Session),
    (
        Method::GET,
        "/api/v1/triage/{host_id}/{event_id}",
        Access::Session,
    ),
];

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'";

pub fn router(state: AppState) -> Router {
    // One limiter per router, shared by login and the two OIDC routes: 10 a minute.
    let limiter = Arc::new(RateLimiter::new(
        10,
        Duration::from_secs(60),
        state.trusted_proxies.clone(),
    ));
    let mut router = Router::new();
    for (method, path, _) in ROUTES {
        let axum_path = path.replace('{', ":").replace('}', "");
        router = router.route(&axum_path, endpoint(method, path, &state, &limiter));
    }
    with_middleware(router.fallback(fallback).with_state(state))
}

/// Go's middleware order: the server's own 400 answers, then the access log, chi's `Recoverer`
/// and the security headers.
fn with_middleware(router: Router) -> Router {
    router
        .layer(CatchPanicLayer::custom(|_| {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }))
        .layer(middleware::map_response(security_headers))
        .layer(middleware::from_fn(access_log))
        .layer(middleware::from_fn(reject_bad_requests))
}

fn endpoint(
    method: Method,
    path: &str,
    state: &AppState,
    limiter: &Arc<RateLimiter>,
) -> MethodRouter<AppState> {
    let auth = middleware::from_fn_with_state(state.signer.clone(), require_auth);
    let limit = middleware::from_fn_with_state(limiter.clone(), ratelimit::limit);
    match path {
        "/api/health" => only(method, health),
        "/api/v1/auth/login" => only(method, api::auth::login.layer(limit)),
        "/api/v1/auth/methods" => only(method, api::auth::methods),
        "/api/v1/auth/oidc/start" => only(method, api::auth::oidc_start.layer(limit)),
        "/api/v1/auth/oidc/callback" => only(method, api::auth::oidc_callback.layer(limit)),
        "/api/v1/auth/logout" => only(method, api::auth::logout.layer(auth)),
        "/api/v1/auth/me" => only(method, api::auth::me.layer(auth)),
        "/api/v1/fleet/meta" => only(method, api::fleet::meta.layer(auth)),
        "/api/v1/fleet/healthz" => only(method, api::fleet::healthz.layer(auth)),
        "/api/v1/fleet/events" => only(method, api::fleet::events.layer(auth)),
        "/api/v1/fleet/events/{event_id}" => only(method, api::fleet::event.layer(auth)),
        "/api/v1/fleet/risk" => only(method, api::fleet::risk.layer(auth)),
        "/api/v1/fleet/compliance" => only(method, api::fleet::compliance.layer(auth)),
        "/api/v1/fleet/hosts" => only(method, api::fleet::hosts.layer(auth)),
        "/api/v1/fleet/hosts/{host_id}" => only(method, api::fleet::host.layer(auth)),
        "/api/v1/triage/upsert" => only(method, api::triage::upsert.layer(auth)),
        "/api/v1/triage/note" => only(method, api::triage::note.layer(auth)),
        "/api/v1/triage/{host_id}/{event_id}" => only(method, api::triage::get.layer(auth)),
        _ => unreachable!("no handler for {path}"),
    }
}

/// Routes one method to `handler` and answers chi's 405 for any other, HEAD included, before
/// any route middleware runs.
fn only<H, T>(method: Method, handler: H) -> MethodRouter<AppState>
where
    H: Handler<T, AppState>,
    T: 'static,
{
    any(move |State(state): State<AppState>, req: Request| {
        let (handler, method) = (handler.clone(), method.clone());
        async move {
            if *req.method() == method {
                handler.call(req, state).await
            } else {
                let allow = HeaderValue::from_str(method.as_str()).expect("method is a token");
                let mut res =
                    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, allow)]).into_response();
                // Go declares no length on an empty answer to HEAD; axum declares one for any
                // body of known size.
                if req.method() == Method::HEAD {
                    *res.body_mut() = Body::new(UnknownLength);
                }
                res
            }
        }
    })
}

/// An empty body that does not state its size.
struct UnknownLength;

impl hyper::body::Body for UnknownLength {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(None)
    }
}

async fn health() -> Response {
    let body = serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    json_response(StatusCode::OK, &body)
}

/// chi sends `/api` and everything under it that no route matches to its 404 text, and every
/// other path to the SPA.
async fn fallback(req: Request) -> Response {
    let path = req.uri().path();
    if path == "/api" || path.starts_with("/api/") {
        return text_response(StatusCode::NOT_FOUND, "404 page not found\n");
    }
    spa::serve(spa::ASSETS, &req)
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response {
    // Go's json.Encoder escapes HTML characters and ends the body with a newline.
    let body = format!("{}\n", triage::go_compact(&body.to_string()));
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// The `{"error":{"code","message"}}` body every API error uses.
pub fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    let body = serde_json::json!({"error": {"code": code, "message": message}});
    json_response(status, &body)
}

pub fn text_response(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    res
}

/// Logs method, path and status. The query string is left out: OIDC callbacks carry codes.
async fn access_log(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let res = next.run(req).await;
    eprintln!(
        "http: method={method} path={path:?} status={}",
        res.status().as_u16()
    );
    res
}

/// Requests Go's HTTP server refuses before any handler runs, so these answers have no security
/// headers and are not logged: a path with a malformed percent escape, more than one `Host`, no
/// `Host` on HTTP/1.1, and a malformed `Host`.
async fn reject_bad_requests(req: Request, next: Next) -> Response {
    let hosts: Vec<_> = req.headers().get_all(header::HOST).iter().collect();
    let host_byte = |b: &u8| b.is_ascii_alphanumeric() || b"!$%&'()*+,-.:;=[]_~".contains(b);
    let reason = if config::unescape(req.uri().path()).is_none() || hosts.len() > 1 {
        "Bad Request"
    } else if hosts.is_empty()
        && req.version() == Version::HTTP_11
        && req.method() != Method::CONNECT
    {
        "Bad Request: missing required Host header"
    } else if hosts
        .first()
        .is_some_and(|h| !h.as_bytes().iter().all(host_byte))
    {
        "Bad Request: malformed Host header"
    } else {
        return next.run(req).await;
    };
    let mut res = (
        StatusCode::BAD_REQUEST,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CONNECTION, "close"),
        ],
        format!("400 {reason}"),
    )
        .into_response();
    // Go puts the whole reason in the status line too.
    res.extensions_mut()
        .insert(ReasonPhrase::from_static(reason.as_bytes()));
    res
}

#[cfg(test)]
mod tests;
