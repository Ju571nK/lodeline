//! Downstream listener and byte relay (T-12 slice A, #258).
//!
//! Request order (first failing step answers; nothing reaches upstream before
//! the last step):
//!
//! 1. path `/mcp/{route_id}` shape            -> 404
//! 2. `Host` check on loopback listeners      -> 403 (DNS rebinding)
//! 3. no applied table / no verifier at all   -> 401
//! 4. unknown route                           -> 404
//! 5. bearer verification on that route       -> 401
//! 6. `Origin` check                          -> 403
//! 7. method (only POST relays)               -> 405
//! 8. admission (total, route, principal)     -> 429 (queue depth 0)
//! 9. bounded request body                    -> 413
//! 10. resolve + destination check, connect   -> 502 / 504
//! 11. relay; response streamed through the metered body
//!
//! The forwarded request body and the response bytes are never re-encoded
//! (D-01 relay-first). No MCP SDK type is on this path.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use sigil_proxy_api::Id;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::body::{MeteredBody, Permits};
use crate::bootstrap::{is_loopback, is_loopback_host, normalize_origin};
use crate::dest::{resolve_checked, DestError, Resolver};
use crate::headers::{downstream_response_headers, upstream_request_headers};
use crate::lifecycle::{drain, DrainOutcome};
use crate::limits::Limits;
use crate::route::{Route, TableHandle};
use crate::tls;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type RespBody = BoxBody<Bytes, BoxError>;

/// JSON-RPC message for an upstream 401/403 (control-plane.md §5.4).
// OPEN: the fixed text is not defined anywhere in the contract (control-plane
// open question 3). This wording is a placeholder.
pub const UPSTREAM_REJECTED_MESSAGE: &str = "upstream request failed";

/// Idle limit for a client that has connected but not finished its headers.
// OPEN: not in the D-04 table; a fixed value so a stalled client cannot hold a
// connection open forever.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

// OPEN: the route path shape `/mcp/{route_id}` is a candidate (task T-12a).
const ROUTE_PREFIX: &str = "/mcp/";

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Clone, Copy)]
enum HostPolicy {
    /// Loopback listener: `Host` must be a loopback name or literal with this port.
    Loopback {
        port: u16,
    },
    // OPEN: for a non-loopback listener the bootstrap holds no host names, so
    // no Host check is made (control-plane.md §5.3 "Host ... recommended").
    Any,
}

struct Shared {
    limits: Limits,
    table: TableHandle,
    resolver: Arc<dyn Resolver>,
    total: Arc<Semaphore>,
    host: HostPolicy,
    #[cfg(unix)]
    upstream_tls: tls::Connector,
}

pub struct Proxy {
    limits: Limits,
    table: TableHandle,
    resolver: Arc<dyn Resolver>,
}

impl Proxy {
    pub fn new(limits: Limits, table: TableHandle, resolver: Arc<dyn Resolver>) -> Proxy {
        Proxy {
            limits,
            table,
            resolver,
        }
    }

    /// Accept until `shutdown` resolves, then stop accepting and drain
    /// in-flight connections for at most `shutdown_grace_secs`.
    pub async fn serve(
        self,
        listener: TcpListener,
        acceptor: Option<tls::Acceptor>,
        shutdown: impl Future<Output = ()>,
    ) -> io::Result<DrainOutcome> {
        let local = listener.local_addr()?;
        let grace = Duration::from_secs(self.limits.shutdown_grace_secs);
        let shared = Arc::new(Shared {
            total: Arc::new(Semaphore::new(self.limits.max_concurrent_calls as usize)),
            host: if is_loopback(local.ip()) {
                HostPolicy::Loopback { port: local.port() }
            } else {
                HostPolicy::Any
            },
            limits: self.limits,
            table: self.table,
            resolver: self.resolver,
            #[cfg(unix)]
            upstream_tls: tls::upstream_connector(),
        });
        let graceful = GracefulShutdown::new();
        let acceptor = acceptor.map(Arc::new);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = listener.accept() => {
                    let (sock, _) = match accepted {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::warn!(error = %e, "accept failed");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };
                    let _ = sock.set_nodelay(true);
                    let shared = shared.clone();
                    match &acceptor {
                        None => {
                            let conn = graceful.watcher().watch(connection(sock, shared));
                            tokio::spawn(async move { let _ = conn.await; });
                        }
                        Some(a) => {
                            let a = a.clone();
                            // The handshake runs inside the spawned task, so a slow
                            // TLS client cannot stall the accept loop. It is not
                            // tracked by `graceful` until established.
                            // OPEN: handshake time is bounded by HEADER_READ_TIMEOUT only.
                            let watch = graceful.watcher();
                            tokio::spawn(async move {
                                handshake_and_serve(a, sock, shared, watch).await;
                            });
                        }
                    }
                }
            }
        }
        drop(listener);
        Ok(drain(grace, graceful.shutdown()).await)
    }
}

type Watcher = hyper_util::server::graceful::Watcher;

async fn handshake_and_serve(
    a: Arc<tls::Acceptor>,
    sock: TcpStream,
    shared: Arc<Shared>,
    watch: Watcher,
) {
    #[cfg(unix)]
    {
        match tokio::time::timeout(HEADER_READ_TIMEOUT, a.accept(sock)).await {
            Ok(Ok(tls_stream)) => {
                let conn = connection(tls_stream, shared);
                let _ = watch.watch(conn).await;
            }
            _ => tracing::debug!("tls handshake failed"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (a, sock, shared, watch);
    }
}

fn connection<I>(
    io: I,
    shared: Arc<Shared>,
) -> impl hyper_util::server::graceful::GracefulConnection
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let max_buf = (shared.limits.max_header_bytes as usize).max(8192);
    let svc = service_fn(move |req| handle(req, shared.clone()));
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_buf_size(max_buf)
        .serve_connection(TokioIo::new(io), svc)
}

// ---------------------------------------------------------------- responses

fn fixed(status: StatusCode, code: &'static str) -> Response<RespBody> {
    let body = format!("{{\"error\":\"{code}\"}}");
    let mut r = Response::new(boxed_full(Bytes::from(body)));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

fn boxed_full(b: Bytes) -> RespBody {
    Full::new(b).map_err(|never| match never {}).boxed()
}

fn unauthorized() -> Response<RespBody> {
    let mut r = fixed(StatusCode::UNAUTHORIZED, "unauthorized");
    // Bare scheme only: no realm, error or error_description (control-plane §5.1).
    r.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    r
}

// ------------------------------------------------------------------ helpers

fn route_id_from_path(path: &str) -> Option<&str> {
    let id = path.strip_prefix(ROUTE_PREFIX)?;
    Id::new(id).ok()?;
    Some(id)
}

fn host_allowed(policy: HostPolicy, req: &http::request::Parts) -> bool {
    let HostPolicy::Loopback { port } = policy else {
        return true;
    };
    let mut hosts = req.headers.get_all(header::HOST).iter();
    let (Some(h), None) = (hosts.next(), hosts.next()) else {
        return false;
    };
    let Ok(h) = h.to_str() else { return false };
    let Ok((host, p)) = crate::bootstrap::split_host_port(&h.to_ascii_lowercase()) else {
        return false;
    };
    let p = p.unwrap_or(80);
    p == port && is_loopback_host(&host)
}

fn bearer_token(h: &http::HeaderMap) -> Option<&str> {
    let mut it = h.get_all(header::AUTHORIZATION).iter();
    let (Some(v), None) = (it.next(), it.next()) else {
        return None;
    };
    let s = v.to_str().ok()?;
    let (scheme, token) = s.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > 4096
        || token.bytes().any(|b| b <= b' ')
    {
        return None;
    }
    Some(token)
}

fn origin_ok(route: &Route, h: &http::HeaderMap) -> bool {
    let mut it = h.get_all(header::ORIGIN).iter();
    let Some(v) = it.next() else {
        // Absent is allowed: non-browser bearer clients send none
        // (control-plane.md §5.3, "absent-allowed recommended").
        return true;
    };
    if it.next().is_some() {
        return false;
    }
    v.to_str()
        .ok()
        .and_then(|s| normalize_origin(s).ok())
        .is_some_and(|o| route.origin_allowed(&o))
}

fn content_length(h: &http::HeaderMap) -> Option<u64> {
    h.get(header::CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

fn is_sse(h: &http::HeaderMap) -> bool {
    h.get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.trim_start()
                .get(..17)
                .is_some_and(|p| p.eq_ignore_ascii_case("text/event-stream"))
        })
}

/// The request's JSON-RPC `id`, from the parse COPY only (string or number).
fn request_id(body: &[u8]) -> Option<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    match v.get("id")? {
        id @ (serde_json::Value::String(_) | serde_json::Value::Number(_)) => Some(id.clone()),
        _ => None,
    }
}

/// control-plane.md §5.4: HTTP 200 JSON-RPC -32603, fixed message, no data,
/// nothing echoed but the request id. Without an id (a notification or an
/// unparsable body) a JSON-RPC reply is not possible, so a fixed 502 is sent.
// OPEN: the no-id case is not specified by the contract.
fn upstream_auth_rejected(request_body: &[u8]) -> Response<RespBody> {
    match request_id(request_body) {
        Some(id) => {
            let v = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32603, "message": UPSTREAM_REJECTED_MESSAGE},
            });
            let mut r = Response::new(boxed_full(Bytes::from(v.to_string())));
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            r.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            r
        }
        None => fixed(StatusCode::BAD_GATEWAY, "upstream_rejected"),
    }
}

// ------------------------------------------------------------------ handler

async fn handle(
    req: Request<Incoming>,
    shared: Arc<Shared>,
) -> Result<Response<RespBody>, Infallible> {
    Ok(handle_inner(req, &shared).await)
}

async fn handle_inner(req: Request<Incoming>, sh: &Shared) -> Response<RespBody> {
    let (parts, body) = req.into_parts();

    // hyper's buffer cap bounds reads but a single large read can exceed it, so
    // the header block is measured here as well (D-04: 32 KiB -> 431).
    let header_bytes: usize = parts.uri.to_string().len()
        + parts
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len() + 4)
            .sum::<usize>();
    if header_bytes as u64 > sh.limits.max_header_bytes {
        return fixed(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "headers_too_large",
        );
    }

    let Some(route_id) = route_id_from_path(parts.uri.path()) else {
        return fixed(StatusCode::NOT_FOUND, "not_found");
    };
    if !host_allowed(sh.host, &parts) {
        return fixed(StatusCode::FORBIDDEN, "forbidden");
    }
    // Until an applied config has at least one verifier everything is 401, so
    // an unconfigured proxy answers the same to every probe.
    let table = match sh.table.current() {
        Some(t) if t.has_verifier() => t,
        _ => return unauthorized(),
    };
    // OPEN: an unknown route is 404 before authentication, which tells an
    // unauthenticated caller which route ids exist (the task fixes 404).
    let Some(route) = table.route(route_id) else {
        return fixed(StatusCode::NOT_FOUND, "not_found");
    };
    let principal = bearer_token(&parts.headers).and_then(|t| route.authenticate(t));
    // `authenticate("")` is never a match, so a missing header needs no
    // separate timing-equalising pass.
    let Some(principal) = principal else {
        return unauthorized();
    };
    if !origin_ok(route, &parts.headers) {
        return fixed(StatusCode::FORBIDDEN, "forbidden");
    }
    if parts.method != Method::POST {
        // GET SSE is a fixed 405 after auth with no upstream contact (decisions.md
        // "P1 기능 범위"). Every other method is 405 as well.
        // OPEN: T-12b. DELETE (session termination) will be handled there.
        let mut r = fixed(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
        r.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("POST"));
        return r;
    }

    // Admission: queue depth is 0, so saturation is an immediate rejection. The
    // permits live until the response body ends (an open SSE stream counts).
    let permits = match (
        sh.total.clone().try_acquire_owned(),
        route.sem.clone().try_acquire_owned(),
        principal.sem.clone().try_acquire_owned(),
    ) {
        (Ok(a), Ok(b), Ok(c)) => Permits(vec![a, b, c]),
        _ => return fixed(StatusCode::TOO_MANY_REQUESTS, "too_many_requests"),
    };

    let lim = &sh.limits;
    let call_deadline = Instant::now() + Duration::from_secs(lim.call_timeout_secs);

    // The request body is read in full under the request limit BEFORE any
    // upstream contact: an oversized body is a 413 with upstream untouched, and
    // the copy used for parsing is the very bytes forwarded.
    // OPEN: bounded buffering (<= max_request_body_bytes) instead of a pure
    // stream; the upstream sees a Content-Length body, not the client's framing.
    let max_body = lim.max_request_body_bytes;
    if content_length(&parts.headers).is_some_and(|n| n > max_body) {
        return fixed(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large");
    }
    let collected = tokio::time::timeout_at(
        call_deadline,
        Limited::new(body, max_body as usize).collect(),
    )
    .await;
    let request_body: Bytes = match collected {
        Err(_) => return fixed(StatusCode::REQUEST_TIMEOUT, "request_timeout"),
        Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return fixed(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large")
        }
        Ok(Err(_)) => return fixed(StatusCode::BAD_REQUEST, "bad_request"),
        Ok(Ok(c)) => c.to_bytes(),
    };

    // Destination: resolve once, check every address, connect to a checked one.
    let addrs = match resolve_checked(&*sh.resolver, &route.upstream, route.allow_private).await {
        Ok(a) => a,
        Err(DestError::Unresolved) => return fixed(StatusCode::BAD_GATEWAY, "upstream_unresolved"),
        Err(DestError::Refused(why)) => {
            tracing::warn!(
                route = route.id.as_str(),
                class = why,
                "destination refused"
            );
            return fixed(StatusCode::BAD_GATEWAY, "destination_refused");
        }
    };

    let Ok(headers) = upstream_request_headers(
        &parts.headers,
        &route.upstream_authorization,
        &route.upstream.host_header,
    ) else {
        return fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable");
    };
    let Ok(uri) = route.upstream.path.parse::<http::Uri>() else {
        return fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable");
    };
    let mut up_req = Request::new(Full::new(request_body.clone()));
    *up_req.method_mut() = Method::POST;
    *up_req.uri_mut() = uri;
    *up_req.headers_mut() = headers;

    let connect_for = Duration::from_secs(lim.connect_timeout_secs);
    let io = match connect(sh, route, &addrs, connect_for).await {
        Ok(io) => io,
        Err(ConnectError::Timeout) => {
            return fixed(StatusCode::GATEWAY_TIMEOUT, "upstream_timeout")
        }
        Err(ConnectError::Io) => return fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
    };
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(io)).await {
        Ok(p) => p,
        Err(_) => return fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // One fresh connection per exchange and one send: a failed exchange is never
    // retried (PX-015). First byte = response headers, bounded by the idle limit
    // and the call deadline.
    let first_byte =
        (Instant::now() + Duration::from_secs(lim.response_idle_timeout_secs)).min(call_deadline);
    let resp = match tokio::time::timeout_at(first_byte, sender.send_request(up_req)).await {
        Err(_) => return fixed(StatusCode::GATEWAY_TIMEOUT, "upstream_timeout"),
        Ok(Err(_)) => return fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
        Ok(Ok(r)) => r,
    };

    let (rparts, rbody) = resp.into_parts();
    let status = rparts.status;
    if status.is_redirection() {
        // Redirects are neither followed nor relayed (PX-014).
        return fixed(StatusCode::BAD_GATEWAY, "upstream_redirect_refused");
    }
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return upstream_auth_rejected(&request_body);
    }

    let sse = is_sse(&rparts.headers);
    // A declared length over the limit is refused while the status line can
    // still be replaced.
    let declared_cap = if sse {
        lim.max_call_response_bytes
    } else {
        lim.max_json_response_bytes.min(lim.max_call_response_bytes)
    };
    if content_length(&rparts.headers).is_some_and(|n| n > declared_cap) {
        return fixed(StatusCode::BAD_GATEWAY, "upstream_response_too_large");
    }

    let metered = MeteredBody::new(
        rbody,
        crate::body::Limits {
            sse,
            max_json_bytes: lim.max_json_response_bytes,
            max_sse_event_bytes: lim.max_sse_event_bytes,
            max_call_bytes: lim.max_call_response_bytes,
            idle: Duration::from_secs(lim.response_idle_timeout_secs),
            call_deadline,
        },
        permits,
    );
    let mut out = Response::new(metered.boxed());
    *out.status_mut() = status;
    *out.headers_mut() = downstream_response_headers(&rparts.headers);
    out
}

// ------------------------------------------------------------------ connect

/// Connect to one of the CHECKED addresses (in order, never re-resolving), and
/// complete the TLS handshake for https. The whole step is bounded by `limit`.
async fn connect(
    sh: &Shared,
    route: &Route,
    addrs: &[SocketAddr],
    limit: Duration,
) -> Result<Box<dyn Io>, ConnectError> {
    let attempt = async {
        let mut last = io::Error::from(io::ErrorKind::NotFound);
        for a in addrs {
            match TcpStream::connect(a).await {
                Ok(tcp) => {
                    let _ = tcp.set_nodelay(true);
                    return wrap_tls(sh, route, tcp).await;
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    };
    match tokio::time::timeout(limit, attempt).await {
        Err(_) => Err(ConnectError::Timeout),
        Ok(Ok(io)) => Ok(io),
        Ok(Err(_)) => Err(ConnectError::Io),
    }
}

enum ConnectError {
    Timeout,
    Io,
}

#[cfg(unix)]
async fn wrap_tls(sh: &Shared, route: &Route, tcp: TcpStream) -> io::Result<Box<dyn Io>> {
    if !route.upstream.https {
        return Ok(Box::new(tcp));
    }
    let name = tls::server_name(&route.upstream.host)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid server name"))?;
    Ok(Box::new(sh.upstream_tls.connect(name, tcp).await?))
}

#[cfg(not(unix))]
async fn wrap_tls(_: &Shared, route: &Route, tcp: TcpStream) -> io::Result<Box<dyn Io>> {
    if route.upstream.https {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "https upstream is not supported on this platform",
        ));
    }
    Ok(Box::new(tcp))
}
