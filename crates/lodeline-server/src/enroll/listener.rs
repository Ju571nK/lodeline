//! #553: the enrollment listener, for hosts that have no client certificate
//! yet. TLS with the main server certificate and no client certificates, one
//! route (`POST /v1/enroll`), and the same `AppState` as the main listener, so
//! both use one `EnrollState` and one mint lock.
//!
//! Before the TLS handshake a connection takes a slot (at most
//! `MAX_CONNECTIONS`) and a token from its source's bucket, or it is dropped.
//! It then lives at most `CONN_LIFETIME` from accept, except while a request is
//! inside the handler, and serves one request on HTTP/1 and HTTP/2 alike.

use crate::app::SharedState;
use crate::proxy::ingest::DenyLog;
use anyhow::Context as _;
use axum::extract::DefaultBodyLimit;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::server::TlsStream;

pub const ROUTE: &str = "/v1/enroll";
/// From TCP accept to close, unless a request is inside the handler.
pub const CONN_LIFETIME: Duration = Duration::from_secs(15);
/// Concurrent connections on the whole listener.
pub const MAX_CONNECTIONS: usize = 64;
/// Per source: `BURST` connections, then one every 6 s (10 a minute).
pub const BURST: f64 = 10.0;
const REFILL_PER_SEC: f64 = 1.0 / 6.0;
/// Bound on the limiter table.
pub const MAX_SOURCES: usize = 10_000;
const SWEEP_EVERY: Duration = Duration::from_secs(1);
/// Time a response gets to be written once its handler returns, so a handler
/// that ran past the deadline still gets its answer out.
const WRITE_GRACE: Duration = Duration::from_secs(2);
/// The largest CSR the main path accepts, plus room for the token and JSON.
pub const MAX_BODY: usize = super::sign::MAX_CSR_BYTES + 1024;

/// The bucket key: an IPv4 address, or the /64 of an IPv6 one (one host can
/// rotate through its /64). A v4-mapped v6 address keys as its IPv4 address.
fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & (u128::MAX << 64))),
        v4 => v4,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Admit {
    Yes,
    /// Admitted after the least recently seen source was evicted.
    TableFull,
    No,
}

#[derive(Default)]
pub struct RateLimiter {
    inner: Mutex<Buckets>,
}

#[derive(Default)]
struct Buckets {
    map: HashMap<IpAddr, Bucket>,
    last_sweep: Option<Instant>,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn refilled(&self, now: Instant) -> f64 {
        (self.tokens + now.saturating_duration_since(self.at).as_secs_f64() * REFILL_PER_SEC)
            .min(BURST)
    }
}

impl RateLimiter {
    pub fn check(&self, ip: IpAddr, now: Instant) -> Admit {
        let key = source_key(ip);
        let mut b = self.inner.lock();
        let mut full = false;
        if b.map.len() >= MAX_SOURCES && !b.map.contains_key(&key) {
            if b.last_sweep
                .is_none_or(|t| now.saturating_duration_since(t) >= SWEEP_EVERY)
            {
                // A full bucket is the same as a new one.
                b.map.retain(|_, v| v.refilled(now) < BURST);
                b.last_sweep = Some(now);
            }
            if b.map.len() >= MAX_SOURCES {
                full = true;
                let oldest = b.map.iter().min_by_key(|(_, v)| v.at).map(|(k, _)| *k);
                if let Some(k) = oldest {
                    b.map.remove(&k);
                }
            }
        }
        let e = b.map.entry(key).or_insert(Bucket {
            tokens: BURST,
            at: now,
        });
        let tokens = e.refilled(now);
        e.at = now;
        if tokens < 1.0 {
            e.tokens = tokens;
            return Admit::No;
        }
        e.tokens = tokens - 1.0;
        if full {
            Admit::TableFull
        } else {
            Admit::Yes
        }
    }
}

/// One connection's deadline, shared by its I/O wrapper and its service.
pub struct ConnLife {
    state: Mutex<LifeState>,
    served: AtomicBool,
}

struct LifeState {
    deadline: tokio::time::Instant,
    in_handler: bool,
    /// The I/O side's waker while it skips the deadline, so the guard's drop
    /// makes it arm the new one even if nothing is written.
    waker: Option<Waker>,
}

impl ConnLife {
    pub fn new(deadline: tokio::time::Instant) -> Arc<Self> {
        Arc::new(ConnLife {
            state: Mutex::new(LifeState {
                deadline,
                in_handler: false,
                waker: None,
            }),
            served: AtomicBool::new(false),
        })
    }

    /// The deadline does not cut the connection while the guard lives.
    pub fn enter(self: &Arc<Self>) -> InHandler {
        self.state.lock().in_handler = true;
        InHandler(self.clone())
    }
}

pub struct InHandler(Arc<ConnLife>);

impl Drop for InHandler {
    fn drop(&mut self) {
        let waker = {
            let mut s = self.0.state.lock();
            s.in_handler = false;
            s.deadline = s.deadline.max(tokio::time::Instant::now() + WRITE_GRACE);
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

/// Reads and writes fail with `TimedOut` once the deadline passes and no
/// request is inside the handler. Holds the connection's slot until dropped.
pub struct Deadline<I> {
    inner: I,
    sleep: Pin<Box<tokio::time::Sleep>>,
    life: Arc<ConnLife>,
    _slot: OwnedSemaphorePermit,
}

impl<I> Deadline<I> {
    pub fn new(inner: I, life: Arc<ConnLife>, slot: OwnedSemaphorePermit) -> Self {
        let deadline = life.state.lock().deadline;
        Deadline {
            inner,
            sleep: Box::pin(tokio::time::sleep_until(deadline)),
            life,
            _slot: slot,
        }
    }

    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        let deadline = {
            let mut s = self.life.state.lock();
            if s.in_handler {
                s.waker = Some(cx.waker().clone());
                return false;
            }
            s.deadline
        };
        if self.sleep.deadline() != deadline {
            self.sleep.as_mut().reset(deadline);
        }
        self.sleep.as_mut().poll(cx).is_ready()
    }
}

fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "enrollment connection lifetime exceeded",
    )
}

impl<I: AsyncRead + Unpin> AsyncRead for Deadline<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.expired(cx) {
            return Poll::Ready(Err(timed_out()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for Deadline<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.expired(cx) {
            return Poll::Ready(Err(timed_out()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Per-connection service: the first request reaches the router with the
/// connection's `Arc<ConnLife>`; every later one (HTTP/2 streams) gets 421
/// and never reaches it. axum-server builds one service per connection, and
/// hyper clones it per request, so the flag lives in the shared `ConnLife`.
#[derive(Clone)]
pub struct OneRequest<S> {
    inner: S,
    life: Arc<ConnLife>,
    peer: IpAddr,
    log: Arc<DenyLog>,
}

impl<S, B> tower::Service<Request<B>> for OneRequest<S>
where
    S: tower::Service<Request<B>, Response = Response>,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if self.life.served.swap(true, Ordering::AcqRel) {
            self.log.note_from(ROUTE, "second_request", Some(self.peer));
            return Box::pin(std::future::ready(Ok(crate::routes::enroll::err(
                StatusCode::MISDIRECTED_REQUEST,
                "one_request_per_connection",
                "send each request on a new connection",
            ))));
        }
        req.extensions_mut().insert(self.life.clone());
        Box::pin(self.inner.call(req))
    }
}

#[derive(Clone)]
struct EnrollAcceptor {
    tls: RustlsAcceptor,
    slots: Arc<Semaphore>,
    limiter: Arc<RateLimiter>,
    log: Arc<DenyLog>,
}

impl<S: Send + 'static> Accept<TcpStream, S> for EnrollAcceptor {
    type Stream = TlsStream<Deadline<TcpStream>>;
    type Service = OneRequest<S>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let peer = stream.peer_addr()?.ip();
            let refuse = |reason: &'static str| {
                this.log.note_from(ROUTE, reason, Some(peer));
                Err(io::Error::other(reason))
            };
            let Ok(slot) = this.slots.clone().try_acquire_owned() else {
                return refuse("listener_full");
            };
            match this.limiter.check(peer, Instant::now()) {
                Admit::Yes => {}
                Admit::TableFull => this.log.note_from(ROUTE, "rate_table_full", Some(peer)),
                Admit::No => return refuse("rate_limited"),
            }
            let life = ConnLife::new(tokio::time::Instant::now() + CONN_LIFETIME);
            let io = Deadline::new(stream, life.clone(), slot);
            let (stream, inner) = this.tls.accept(io, service).await?;
            Ok((
                stream,
                OneRequest {
                    inner,
                    life,
                    peer,
                    log: this.log,
                },
            ))
        })
    }
}

/// TLS with the server certificate and no client certificate request.
pub fn tls_config(cert: &Path, key: &Path) -> anyhow::Result<RustlsConfig> {
    use crate::tls_accept::{load_certs, load_key};
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(load_certs(cert)?, load_key(key)?)
        .context("build rustls ServerConfig (enrollment listener)")?;
    Ok(RustlsConfig::from_config(Arc::new(config)))
}

pub fn router(st: SharedState) -> Router {
    Router::new()
        .route(ROUTE, post(crate::routes::enroll::post_enroll_listener))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(st)
}

/// Serve the enrollment listener on an already bound socket. Fails at once
/// when enrollment is off.
pub async fn serve(
    sock: std::net::TcpListener,
    tls: RustlsConfig,
    st: SharedState,
) -> anyhow::Result<()> {
    let log = st
        .enroll
        .as_ref()
        .context("enrollment listener: enrollment is off")?
        .deny_log
        .clone();
    let acceptor = EnrollAcceptor {
        tls: RustlsAcceptor::new(tls),
        slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        limiter: Arc::default(),
        log,
    };
    let mut server = axum_server::from_tcp(sock).acceptor(acceptor);
    server.http_builder().http1().keep_alive(false);
    server
        .serve(router(st).into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("serve enrollment listener")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn burst_then_refill() {
        let l = RateLimiter::default();
        let t0 = Instant::now();
        for _ in 0..10 {
            assert_eq!(l.check(ip("192.0.2.1"), t0), Admit::Yes);
        }
        assert_eq!(l.check(ip("192.0.2.1"), t0), Admit::No);
        assert_eq!(l.check(ip("192.0.2.2"), t0), Admit::Yes, "other source");
        let t1 = t0 + Duration::from_secs(6);
        assert_eq!(l.check(ip("192.0.2.1"), t1), Admit::Yes);
        assert_eq!(l.check(ip("192.0.2.1"), t1), Admit::No);
        let t2 = t1 + Duration::from_secs(600);
        for _ in 0..10 {
            assert_eq!(
                l.check(ip("192.0.2.1"), t2),
                Admit::Yes,
                "refill caps at the burst"
            );
        }
        assert_eq!(l.check(ip("192.0.2.1"), t2), Admit::No);
    }

    #[test]
    fn ipv6_keys_by_64_and_mapped_v4_by_address() {
        let l = RateLimiter::default();
        let t = Instant::now();
        for i in 0..10 {
            assert_eq!(l.check(ip(&format!("2001:db8:1:2::{i:x}")), t), Admit::Yes);
        }
        assert_eq!(
            l.check(ip("2001:db8:1:2:ffff::1"), t),
            Admit::No,
            "same /64"
        );
        assert_eq!(l.check(ip("2001:db8:1:3::1"), t), Admit::Yes, "other /64");
        for _ in 0..10 {
            assert_eq!(l.check(ip("::ffff:198.51.100.7"), t), Admit::Yes);
        }
        assert_eq!(
            l.check(ip("198.51.100.7"), t),
            Admit::No,
            "v4-mapped shares"
        );
    }

    /// The i-th source of a full table: one 2001:db8::/32 /64 each.
    fn nth(i: u32) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            (i >> 16) as u16,
            i as u16,
            0,
            0,
            0,
            1,
        ))
    }

    fn fill(l: &RateLimiter, t: Instant) {
        for i in 0..MAX_SOURCES as u32 {
            assert_eq!(l.check(nth(i), t), Admit::Yes);
        }
    }

    #[test]
    fn full_table_sweeps_idle_sources() {
        let l = RateLimiter::default();
        let t0 = Instant::now();
        fill(&l, t0);
        let t1 = t0 + Duration::from_secs(60);
        for _ in 0..3 {
            assert_eq!(l.check(nth(0), t1), Admit::Yes, "known source");
        }
        let t2 = t0 + Duration::from_secs(61);
        assert_eq!(l.check(ip("192.0.2.9"), t2), Admit::Yes, "idle ones swept");
        assert_eq!(l.inner.lock().map.len(), 2);
    }

    #[test]
    fn full_table_of_active_sources_evicts_the_oldest() {
        let l = RateLimiter::default();
        let t0 = Instant::now();
        fill(&l, t0);
        let t1 = t0 + Duration::from_millis(10);
        for _ in 0..9 {
            l.check(nth(1), t1);
        }
        assert_eq!(l.check(ip("192.0.2.9"), t1), Admit::TableFull);
        let b = l.inner.lock();
        assert_eq!(b.map.len(), MAX_SOURCES);
        assert!(b.map.contains_key(&ip("192.0.2.9")));
        assert!(
            b.map.contains_key(&source_key(nth(1))),
            "recently seen stays"
        );
        drop(b);
        assert_eq!(l.check(nth(1), t1), Admit::No, "kept its spent bucket");
    }

    fn deadline_pair(
        life: Duration,
    ) -> (
        Deadline<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
        Arc<ConnLife>,
    ) {
        let (a, b) = tokio::io::duplex(1024);
        let life = ConnLife::new(tokio::time::Instant::now() + life);
        let slot = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        (Deadline::new(a, life.clone(), slot), b, life)
    }

    #[tokio::test]
    async fn idle_io_fails_at_the_deadline() {
        let (mut d, _peer, _) = deadline_pair(Duration::from_millis(100));
        let t0 = Instant::now();
        let mut buf = [0u8; 8];
        let e = d.read(&mut buf).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(t0.elapsed() >= Duration::from_millis(100));
        assert_eq!(
            d.write(b"x").await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn a_handler_past_the_deadline_still_writes_its_response() {
        let (mut d, mut peer, life) = deadline_pair(Duration::from_millis(50));
        let guard = life.enter();
        tokio::time::sleep(Duration::from_millis(150)).await;
        d.write_all(b"in handler").await.unwrap();
        drop(guard);
        d.write_all(b" response").await.unwrap();
        let mut got = vec![0u8; 19];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(got, b"in handler response");
        tokio::time::sleep(WRITE_GRACE + Duration::from_millis(100)).await;
        assert_eq!(
            d.write(b"x").await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn an_idle_read_times_out_after_a_handler_ends_without_writing() {
        let (mut d, _peer, life) = deadline_pair(Duration::from_millis(100));
        let read = tokio::spawn(async move { d.read(&mut [0u8; 8]).await.map(|_| ()) });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let guard = life.enter();
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(guard);
        let e = tokio::time::timeout(WRITE_GRACE + Duration::from_secs(1), read)
            .await
            .expect("idle read never timed out after the guard dropped")
            .unwrap()
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    }
}
