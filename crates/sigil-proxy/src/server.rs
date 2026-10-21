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
//! 10. classify the JSON-RPC message (`mcp`)  -> 400 / 200 fixed refusals,
//!     202 for a held or pre-dispatch cancel
//! 11. start observation (may defer)          -> 503 if the sink refuses
//! 12. resolve + destination check, connect   -> 502 / 504
//! 13. cancel check, then dispatch
//! 14. relay; response streamed through the metered body, which classifies
//!     the outcome for the observation seam
//!
//! The forwarded request body and the response bytes are never re-encoded
//! (D-01 relay-first). No MCP SDK type is on this path.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

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

use crate::body::{BodyMode, MeteredBody, Permits};
use crate::bootstrap::{is_loopback, is_loopback_host, normalize_origin};
use crate::dest::{resolve_checked, DestError, Resolver};
use crate::headers::{downstream_response_headers, upstream_request_headers};
use crate::lifecycle::{drain, DrainOutcome};
use crate::limits::Limits;
use crate::mcp::cancel::{CancelKey, CancelOutcome, CancelRegistry};
use crate::mcp::classify::{self, HeaderVersion, Message, NotificationInfo, Refusal, RefusalKind};
use crate::mcp::observation::{
    CallRef, CancelDisposition, CancelObserved, Cause, Delivery, Method as McpMethod, NoopSink,
    Observation, ObservationSink, Outcome, RequestRefused, RequestStarted, StartVerdict, ToolField,
};
use crate::mcp::response::{CallCtx, CaptureLimits, Resolution, ResponseTracker};
use crate::route::{Route, TableHandle};
use crate::tls;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type RespBody = BoxBody<Bytes, BoxError>;

/// JSON-RPC message for an upstream 401/403 (control-plane.md §5.4).
// OPEN: the fixed text is not defined anywhere in the contract (control-plane
// open question 3). This wording is a placeholder.
pub const UPSTREAM_REJECTED_MESSAGE: &str = "upstream request failed";

/// Default idle limit for a client that has connected but not finished its
/// headers (slowloris). Also bounds a TLS handshake.
// OPEN: not in the D-04 table; a fixed value so a stalled client cannot hold a
// connection open forever.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Open connections allowed per unit of `max_concurrent_calls`. A connection
/// (including one still in its TLS handshake) holds a slot, so idle or
/// handshaking sockets cannot exhaust file descriptors.
// OPEN: the factor 4 is a review-chosen value, not a D-04 number.
const CONNECTIONS_PER_CALL: usize = 4;

// OPEN: D-04 per-call (4 MiB/s) and process (32 MiB/s) response bandwidth are
// NOT enforced in this slice; no backpressure shaping exists yet.

/// Never matches a real token; only used to spend the same hashing work as a
/// real verification when the route is unknown.
const DUMMY_VERIFIER: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// OPEN: the route path shape `/mcp/{route_id}` is a candidate (task T-12a).
const ROUTE_PREFIX: &str = "/mcp/";

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Clone, Copy)]
enum HostPolicy {
    /// Loopback listener: `Host` must be a loopback name or literal with this
    /// port. A `Host` without a port is read as port 80, so it matches only a
    /// listener bound to 80.
    // OPEN: caveat: behind a port mapping (container `-p 9000:8480`, SSH or
    // reverse-proxy forwarding) the client's `Host` port differs from the bound
    // port and is refused with 403. Use a matching port or a non-loopback
    // listener (TLS) for such setups.
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
    header_read_timeout: Duration,
    sink: Arc<dyn ObservationSink>,
    cancel: Arc<CancelRegistry>,
    /// Relay-local call numbers (not invocation ids).
    seq: AtomicU64,
    #[cfg(unix)]
    upstream_tls: tls::Connector,
}

pub struct Proxy {
    limits: Limits,
    table: TableHandle,
    resolver: Arc<dyn Resolver>,
    header_read_timeout: Duration,
    sink: Arc<dyn ObservationSink>,
    cancel: Arc<CancelRegistry>,
}

impl Proxy {
    pub fn new(limits: Limits, table: TableHandle, resolver: Arc<dyn Resolver>) -> Proxy {
        Proxy {
            limits,
            table,
            resolver,
            header_read_timeout: HEADER_READ_TIMEOUT,
            // No producer until T-13: nothing is observed and behaviour is
            // exactly the plain relay.
            sink: Arc::new(NoopSink),
            cancel: Arc::new(CancelRegistry::default()),
        }
    }

    /// Install the consumer of observations (T-13). The default observes
    /// nothing.
    pub fn with_sink(mut self, sink: Arc<dyn ObservationSink>) -> Proxy {
        self.sink = sink;
        self
    }

    /// The cancel registry, for its counters (`unmatched_total`).
    pub fn cancel_registry(&self) -> Arc<CancelRegistry> {
        self.cancel.clone()
    }

    /// Override the header-read (and TLS handshake) timeout; used by tests.
    pub fn with_header_read_timeout(mut self, d: Duration) -> Proxy {
        self.header_read_timeout = d;
        self
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
            header_read_timeout: self.header_read_timeout,
            sink: self.sink,
            cancel: self.cancel,
            seq: AtomicU64::new(1),
            limits: self.limits,
            table: self.table,
            resolver: self.resolver,
            #[cfg(unix)]
            upstream_tls: tls::upstream_connector(),
        });
        let graceful = GracefulShutdown::new();
        let conn_slots = Arc::new(Semaphore::new(
            (shared.limits.max_concurrent_calls as usize).saturating_mul(CONNECTIONS_PER_CALL),
        ));
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
                    // Connection cap: refuse at accept, before any bytes are read.
                    let Ok(slot) = conn_slots.clone().try_acquire_owned() else {
                        drop(sock);
                        continue;
                    };
                    let _ = sock.set_nodelay(true);
                    let shared = shared.clone();
                    match &acceptor {
                        None => {
                            let conn = graceful.watcher().watch(connection(sock, shared));
                            tokio::spawn(async move {
                                let _ = conn.await;
                                drop(slot);
                            });
                        }
                        Some(a) => {
                            let a = a.clone();
                            // The handshake runs inside the spawned task, so a slow
                            // TLS client cannot stall the accept loop. It is not
                            // tracked by `graceful` until established.
                            // The connection slot covers the handshake.
                            let watch = graceful.watcher();
                            tokio::spawn(async move {
                                handshake_and_serve(a, sock, shared, watch).await;
                                drop(slot);
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
        match tokio::time::timeout(shared.header_read_timeout, a.accept(sock)).await {
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
    let timeout = shared.header_read_timeout;
    let svc = service_fn(move |req| handle(req, shared.clone()));
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(timeout)
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

/// The request's JSON-RPC `id` exactly as written (string or number), from the
/// parse COPY only. Kept as raw JSON so large integers and escapes are echoed
/// verbatim. A duplicate `id` key, a non-object body (batch) or any other type
/// gives `None`.
fn request_id(body: &[u8]) -> Option<Box<serde_json::value::RawValue>> {
    #[derive(serde::Deserialize)]
    struct Probe {
        id: Option<Box<serde_json::value::RawValue>>,
    }
    let id = serde_json::from_slice::<Probe>(body).ok()?.id?;
    match id.get().as_bytes().first()? {
        b'"' | b'-' | b'0'..=b'9' => Some(id),
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
            // `id` is validated JSON; the message is a constant without quotes.
            let v = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":-32603,\"message\":\"{}\"}}}}",
                id.get(),
                UPSTREAM_REJECTED_MESSAGE
            );
            let mut r = Response::new(boxed_full(Bytes::from(v)));
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
    // An unknown route answers exactly like a failed authentication on a known
    // route (same status, body and headers), after the same kind of hashing
    // work, so route ids are not an oracle. Only a path that is not shaped
    // `/mcp/{id}` at all is a 404.
    let Some(route) = table.route(route_id) else {
        let _ = std::hint::black_box(sigil_proxy_api::verify(
            bearer_token(&parts.headers).unwrap_or(""),
            DUMMY_VERIFIER,
        ));
        return unauthorized();
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

    // Effective per-route limits: min(local, remote) (#260).
    let lim = route.limits();
    let call_deadline = Instant::now() + Duration::from_secs(lim.call_timeout_secs);
    let received_at = SystemTime::now();
    let t0 = std::time::Instant::now();
    let call = CallRef {
        seq: sh.seq.fetch_add(1, Ordering::Relaxed),
        route_id: route.id.as_str().to_string(),
        principal_id: principal.id.as_str().to_string(),
    };

    // The request body is read in full under the request limit BEFORE any
    // upstream contact: an oversized body is a 413 with upstream untouched, and
    // the copy used for parsing is the very bytes forwarded.
    // OPEN: bounded buffering (<= max_request_body_bytes) instead of a pure
    // stream; the upstream sees a Content-Length body, not the client's framing.
    let max_body = lim.max_request_body_bytes;
    if content_length(&parts.headers).is_some_and(|n| n > max_body) {
        return refuse_too_large(sh, call, received_at);
    }
    let collected = tokio::time::timeout_at(
        call_deadline,
        Limited::new(body, max_body as usize).collect(),
    )
    .await;
    let request_body: Bytes = match collected {
        Err(_) => return fixed(StatusCode::REQUEST_TIMEOUT, "request_timeout"),
        Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return refuse_too_large(sh, call, received_at)
        }
        Ok(Err(_)) => return fixed(StatusCode::BAD_REQUEST, "bad_request"),
        Ok(Ok(c)) => c.to_bytes(),
    };

    // Classify a parse COPY of the body (T-12b1). The bytes forwarded below are
    // `request_body` itself, untouched.
    let message = classify::classify(&request_body, HeaderVersion::from_headers(&parts.headers));
    // `Some` for a client request that is observed (start, completion, cancel).
    let mut ctx: Option<CallCtx> = None;
    match message {
        Message::Refused(r) => {
            return refuse(sh, call, r, request_body.len() as u64, received_at);
        }
        // Client answers to server requests and other notifications are relayed
        // as they are; no events.
        Message::ClientResponse | Message::Notification(NotificationInfo::Other) => {}
        Message::Notification(NotificationInfo::Cancelled { target }) => {
            let key = CancelKey {
                route: call.route_id.clone(),
                principal: call.principal_id.clone(),
                id: target.clone(),
            };
            match sh.cancel.cancel(&key, Instant::now()) {
                CancelOutcome::AfterDispatch(seq) => {
                    // The target is in flight: the cancel goes upstream (below).
                    sh.sink.observe(Observation::Cancel(CancelObserved {
                        target: CallRef {
                            seq,
                            route_id: call.route_id.clone(),
                            principal_id: call.principal_id.clone(),
                        },
                        target_id: target,
                        disposition: CancelDisposition::AfterDispatch,
                        at: SystemTime::now(),
                    }));
                }
                // Not dispatched yet (the target's handler records it), already
                // cancelled, or held for a request that has not arrived: never
                // forwarded (M3, no hold-and-forward).
                CancelOutcome::BeforeDispatch
                | CancelOutcome::AlreadyCancelled
                | CancelOutcome::Held => return empty(StatusCode::ACCEPTED),
            }
        }
        Message::Request(info) => {
            let key = CancelKey {
                route: call.route_id.clone(),
                principal: call.principal_id.clone(),
                id: info.id.clone(),
            };
            // Two in-flight requests of one principal on one route may not share
            // an id: a cancel could not tell them apart. The second is refused.
            let Some(registration) = sh.cancel.register(key, call.seq, Instant::now()) else {
                return refuse(
                    sh,
                    call,
                    Refusal {
                        kind: RefusalKind::InvalidRequest,
                        id: Some(info.id),
                        method: info.method,
                        tool: info.tool,
                    },
                    request_body.len() as u64,
                    received_at,
                );
            };
            let mut c = CallCtx::new(
                sh.sink.clone(),
                call.clone(),
                info.method,
                info.id,
                t0,
                registration,
            );
            // The sink may defer dispatch (local spool commit of the start). The
            // no-op sink has nothing to wait for or record.
            if sh.sink.wants_observations() {
                let started = RequestStarted {
                    call: call.clone(),
                    method: info.method,
                    request_id: c.request_id().clone(),
                    tool: info.tool.clone(),
                    list_cursor: info.list_cursor,
                    task_augmented: info.task_augmented,
                    request_bytes: request_body.len() as u64,
                    received_at,
                };
                if sh.sink.request_started(&started).await == StartVerdict::Refuse {
                    c.abandon();
                    return fixed(StatusCode::SERVICE_UNAVAILABLE, "audit_unavailable");
                }
            }
            if c.registration().is_cancelled() {
                return cancelled_before_dispatch(sh, c);
            }
            ctx = Some(c);
        }
    }

    // Fail the observed call (if any) and answer.
    macro_rules! bail {
        ($resp:expr, $res:expr) => {{
            let resp = $resp;
            if let Some(c) = ctx.as_mut() {
                c.complete($res);
            }
            return resp;
        }};
    }

    // Destination: resolve once, check every address, connect to a checked one.
    // Resolution is bounded by the connect timeout (a hanging resolver is a 504).
    let resolved = tokio::time::timeout(
        Duration::from_secs(lim.connect_timeout_secs),
        resolve_checked(&*sh.resolver, &route.upstream, route.allow_private),
    )
    .await;
    let addrs = match resolved {
        Err(_) => bail!(
            fixed(StatusCode::GATEWAY_TIMEOUT, "upstream_timeout"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::ConnectTimeout)
        ),
        Ok(Ok(a)) => a,
        Ok(Err(DestError::Unresolved)) => bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_unresolved"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::Unresolved)
        ),
        Ok(Err(DestError::Refused(why))) => {
            tracing::warn!(
                route = route.id.as_str(),
                class = why,
                "destination refused"
            );
            bail!(
                fixed(StatusCode::BAD_GATEWAY, "destination_refused"),
                Resolution::not_sent(Outcome::TransportFailure, Cause::DestinationRefused)
            )
        }
    };

    let Ok(headers) = upstream_request_headers(
        &parts.headers,
        &route.upstream_authorization,
        &route.upstream.host_header,
    ) else {
        bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::UpstreamRequestBuild)
        )
    };
    let Ok(uri) = route.upstream.path.parse::<http::Uri>() else {
        bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::UpstreamRequestBuild)
        )
    };
    let mut up_req = Request::new(Full::new(request_body.clone()));
    *up_req.method_mut() = Method::POST;
    *up_req.uri_mut() = uri;
    *up_req.headers_mut() = headers;

    let connect_for = Duration::from_secs(lim.connect_timeout_secs);
    let io = match connect(sh, route, &addrs, connect_for).await {
        Ok(io) => io,
        Err(ConnectError::Timeout) => bail!(
            fixed(StatusCode::GATEWAY_TIMEOUT, "upstream_timeout"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::ConnectTimeout)
        ),
        Err(ConnectError::Io) => bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::ConnectFailed)
        ),
    };
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(io)).await {
        Ok(p) => p,
        Err(_) => bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::ConnectFailed)
        ),
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // M3: the dispatch decision. A cancel that got here first wins and the
    // request is never written; otherwise the request is dispatched and any
    // later cancel is forwarded instead.
    if let Some(c) = ctx.as_mut() {
        if c.registration().try_dispatch().is_err() {
            let c = ctx.take().expect("checked above");
            return cancelled_before_dispatch(sh, c);
        }
        c.mark_dispatched();
    }

    // One fresh connection per exchange and one send: a failed exchange is never
    // retried (PX-015). First byte = response headers, bounded by the idle limit
    // and the call deadline.
    let first_byte =
        (Instant::now() + Duration::from_secs(lim.response_idle_timeout_secs)).min(call_deadline);
    let resp = match tokio::time::timeout_at(first_byte, sender.send_request(up_req)).await {
        Err(_) => bail!(
            fixed(StatusCode::GATEWAY_TIMEOUT, "upstream_timeout"),
            Resolution::after_dispatch(
                Outcome::Timeout,
                Delivery::Unknown,
                Cause::FirstByteTimeout,
                None
            )
        ),
        Ok(Err(_)) => bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
            Resolution::after_dispatch(
                Outcome::Unknown,
                Delivery::Unknown,
                Cause::SendFailed,
                None
            )
        ),
        Ok(Ok(r)) => r,
    };

    let (rparts, rbody) = resp.into_parts();
    let status = rparts.status;
    let sent = |cause| {
        Resolution::after_dispatch(
            Outcome::Unknown,
            Delivery::Sent,
            cause,
            Some(status.as_u16()),
        )
    };
    if status.is_redirection() {
        // Redirects are neither followed nor relayed (PX-014).
        bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_redirect_refused"),
            sent(Cause::UpstreamRedirect)
        )
    }
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        // decisions.md D-02 #7: unknown/sent, no reason.
        bail!(
            upstream_auth_rejected(&request_body),
            sent(Cause::UpstreamAuthRejected)
        )
    }

    let sse = is_sse(&rparts.headers);
    // A content-encoded stream is opaque to the proxy: the event tracker cannot
    // see event boundaries in compressed bytes, so only the call cap applies. It
    // is never decoded, and the call's outcome is reported as unobservable.
    let encoded = rparts
        .headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            let v = v.trim();
            !v.is_empty() && !v.eq_ignore_ascii_case("identity")
        });
    let mode = match (sse, encoded) {
        (true, false) => BodyMode::Sse,
        (true, true) => BodyMode::Opaque,
        (false, _) => BodyMode::Json,
    };
    // The limits above treat an encoded plain body like JSON (as before); the
    // outcome tracker cannot read it.
    let track_mode = if encoded { BodyMode::Opaque } else { mode };
    // A declared length over the limit is refused while the status line can
    // still be replaced.
    let declared_cap = if mode == BodyMode::Json {
        lim.max_json_response_bytes.min(lim.max_call_response_bytes)
    } else {
        lim.max_call_response_bytes
    };
    if content_length(&rparts.headers).is_some_and(|n| n > declared_cap) {
        bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_response_too_large"),
            sent(Cause::ResponseTooLarge)
        )
    }

    // From here the tracker owns the call and reports its completion when the
    // body ends, fails or is dropped.
    let page_cap = if mode == BodyMode::Json {
        lim.max_json_response_bytes
    } else {
        lim.max_sse_event_bytes
    }
    .min(lim.inventory_max_bytes);
    let tracker = ctx.take().map(|c| {
        ResponseTracker::new(
            c,
            track_mode,
            status.as_u16(),
            CaptureLimits {
                max_bytes: page_cap as usize,
                max_tools: lim.inventory_max_tools as usize,
            },
        )
    });
    let metered = MeteredBody::new(
        rbody,
        crate::body::Limits {
            mode,
            max_json_bytes: lim.max_json_response_bytes,
            max_sse_event_bytes: lim.max_sse_event_bytes,
            max_call_bytes: lim.max_call_response_bytes,
            idle: Duration::from_secs(lim.response_idle_timeout_secs),
            call_deadline,
        },
        permits,
        tracker,
    );
    let mut out = Response::new(metered.boxed());
    *out.status_mut() = status;
    *out.headers_mut() = downstream_response_headers(&rparts.headers);
    out
}

// ------------------------------------------------------- MCP-level answers

fn empty(status: StatusCode) -> Response<RespBody> {
    let mut r = Response::new(boxed_full(Bytes::new()));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

/// A fixed JSON-RPC error: constant message, no `data`, nothing echoed but the
/// request id (contracts/README.md "Client-visible errors for pre-dispatch
/// refusals"). Without an id the reply carries `"id":null`.
fn jsonrpc_error(
    id: Option<&classify::RequestId>,
    code: i32,
    message: &'static str,
    status: StatusCode,
) -> Response<RespBody> {
    // `id.raw()` is validated JSON (a string or number); the message is a
    // constant without quotes.
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":{code},\"message\":\"{message}\"}}}}",
        id.map(|i| i.raw()).unwrap_or("null")
    );
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

/// The client-visible answer to a refusal. Upstream is never contacted.
///
/// - modern-era request, legacy version header: HTTP 400, empty body (B1).
/// - `tasks/*`, `resources/(un)subscribe`: JSON-RPC `-32601`, HTTP 200.
/// - unparseable tool name: JSON-RPC `-32602`, HTTP 200.
/// - batch, malformed JSON-RPC, a method-less notification refusal: HTTP 400
///   with a JSON-RPC `-32700`/`-32600` error and `"id":null`.
// OPEN: the batch/malformed shape is not fixed by the contract ("batch 거절의
// client 응답 형태는 [OPEN]"); this is the JSON-RPC 2.0 Invalid Request shape
// over HTTP 400.
fn refusal_response(r: &Refusal) -> Response<RespBody> {
    let bad = StatusCode::BAD_REQUEST;
    match r.kind {
        RefusalKind::ModernRequest | RefusalKind::VersionHeader => empty(bad),
        RefusalKind::Parse => jsonrpc_error(None, -32700, "Parse error", bad),
        // The id is echoed when one was read (batches and unparseable bodies
        // have none).
        RefusalKind::InvalidRequest | RefusalKind::Batch => {
            jsonrpc_error(r.id.as_ref(), -32600, "Invalid Request", bad)
        }
        RefusalKind::TasksMethod | RefusalKind::ResourcesSubscription => match &r.id {
            Some(id) => jsonrpc_error(Some(id), -32601, "Method not found", StatusCode::OK),
            // a notification: there is nobody to answer by id
            None => jsonrpc_error(None, -32600, "Invalid Request", bad),
        },
        RefusalKind::ToolNameMalformed => {
            jsonrpc_error(r.id.as_ref(), -32602, "Invalid params", StatusCode::OK)
        }
        RefusalKind::RequestTooLarge => fixed(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"),
    }
}

fn refuse(
    sh: &Shared,
    call: CallRef,
    r: Refusal,
    request_bytes: u64,
    received_at: SystemTime,
) -> Response<RespBody> {
    let resp = refusal_response(&r);
    sh.sink.observe(Observation::Refused(RequestRefused {
        call,
        reason: r.kind,
        method: r.method,
        request_id: r.id,
        tool: r.tool,
        http_status: resp.status().as_u16(),
        request_bytes,
        received_at,
    }));
    resp
}

fn refuse_too_large(sh: &Shared, call: CallRef, received_at: SystemTime) -> Response<RespBody> {
    refuse(
        sh,
        call,
        Refusal {
            kind: RefusalKind::RequestTooLarge,
            id: None,
            method: McpMethod::Unknown,
            tool: ToolField::NotApplicable,
        },
        0,
        received_at,
    )
}

/// M3: a cancel won against dispatch. Nothing was written upstream and no
/// JSON-RPC response is sent; the open POST gets an event-less 200 event stream
/// (README "취소 순서(M3)", N13).
// OPEN: P1 verification: if Claude/Codex retry on this, close the connection
// without an HTTP response instead (decisions.md "취소 전 dispatch의 HTTP 종료").
fn cancelled_before_dispatch(sh: &Shared, mut ctx: CallCtx) -> Response<RespBody> {
    sh.sink.observe(Observation::Cancel(CancelObserved {
        target: ctx.call().clone(),
        target_id: ctx.request_id().clone(),
        disposition: CancelDisposition::BeforeDispatch,
        at: SystemTime::now(),
    }));
    ctx.complete(Resolution::not_sent(
        Outcome::Unknown,
        Cause::CancelledBeforeDispatch,
    ));
    let mut r = empty(StatusCode::OK);
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    r
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
