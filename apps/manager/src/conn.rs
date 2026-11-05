//! The listener and connection loop, with the behavior of Go's `http.Server` as `main.go` sets
//! it up: HTTP/1.1 only, a 10 s header read timeout, no idle timeout, and a 5 s drain. An
//! answer sent before its request body was read closes the connection unless the rest of the
//! body can be read and dropped first.

use std::future::{poll_fn, Future};
use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::pin::{pin, Pin};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes, HttpBody};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::{Extension, Router};
use hyper::body::{Frame, SizeHint};
use hyper::rt::{Sleep, Timer};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tower::Layer;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// The most early answers that read their request body at once, across all connections; past
/// that, an early answer closes at once.
const MAX_DRAINS: usize = 64;
/// How long an early answer reads the rest of the request body, which a client sends right
/// behind the head.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
/// How much of the rest an early answer reads, the size of a login body.
const DRAIN_LIMIT: usize = 64 << 10;
const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Go's listener default for both the keep-alive idle time and the probe interval.
const KEEPALIVE: Duration = Duration::from_secs(15);

/// Go's `:port` listens on every interface, IPv4 and IPv6 alike. A `[::]` socket accepts IPv4
/// too only with `IPV6_V6ONLY` off, which Windows does not default to.
pub async fn bind(addr: &str) -> io::Result<TcpListener> {
    let Some(port) = addr.strip_prefix(':') else {
        return TcpListener::bind(addr).await;
    };
    match port.parse().ok().map(dual_stack) {
        Some(Ok(listener)) => Ok(listener),
        _ => TcpListener::bind(format!("0.0.0.0:{port}")).await,
    }
}

fn dual_stack(port: u16) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(false)?;
    // As tokio's `TcpListener::bind` and Go do on Unix.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// Serves `app` until `shutdown` completes, then drains open connections for up to 5 s.
pub async fn serve(listener: TcpListener, app: Router, shutdown: impl Future<Output = ()>) {
    let drains = Arc::new(Semaphore::new(MAX_DRAINS));
    let app = app.layer(middleware::from_fn_with_state(drains, close_unread));
    let graceful = GracefulShutdown::new();
    let mut shutdown = pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            accepted = accept(&listener) => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    eprintln!("lodeline-manager: accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let reads = Arc::new(AtomicU64::new(0));
        let timer = HeadTimer {
            reads: reads.clone(),
            armed: AtomicBool::new(false),
        };
        // Go's `Request.RemoteAddr`, which the login limiter keys on.
        let app = Extension(ConnectInfo(peer)).layer(app.clone());
        // HTTP/1.1 only, as Go's server on a plain listener.
        let conn = http1::Builder::new()
            .timer(timer)
            .header_read_timeout(READ_HEADER_TIMEOUT)
            .serve_connection(
                TokioIo::new(CountReads { stream, reads }),
                TowerToHyperService::new(app),
            );
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            let _ = conn.await;
        });
    }

    drop(listener);
    eprintln!("lodeline-manager: shutdown signal received, draining for up to {SHUTDOWN_GRACE:?}");
    if tokio::time::timeout(SHUTDOWN_GRACE, graceful.shutdown())
        .await
        .is_err()
    {
        eprintln!("lodeline-manager: shutdown error: drain timed out");
    }
}

/// Turns on TCP keep-alive and `TCP_NODELAY` as Go's listener does, so a peer that vanishes
/// without a FIN does not hold an idle connection open forever. Go ignores these errors too.
async fn accept(listener: &TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    let (stream, peer) = listener.accept().await?;
    let _ = stream.set_nodelay(true);
    let keepalive = TcpKeepalive::new()
        .with_time(KEEPALIVE)
        .with_interval(KEEPALIVE);
    let _ = SockRef::from(&stream).set_tcp_keepalive(&keepalive);
    Ok((stream, peer))
}

/// Reads the rest of any request body the app left unread, such as after a 401, 405, 413, 415
/// or 429, or the terminator after a chunked body's JSON value. While one of `MAX_DRAINS`
/// permits is free, up to `DRAIN_LIMIT` of it is read and dropped for at most `DRAIN_TIMEOUT`,
/// and a body read to its end keeps the connection. Otherwise the answer carries
/// `Connection: close`. A client that sent an `Expect` header may still be waiting to send its
/// body, and reading the body would tell it to go ahead, so its answer goes out at once.
async fn close_unread(State(drains): State<Arc<Semaphore>>, req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let expects = parts.headers.contains_key(header::EXPECT);
    let unread = Arc::new(Mutex::new(Some(body)));
    let req = Request::from_parts(parts, Body::new(Unread(unread.clone())));
    let mut res = next.run(req).await;
    let rest = lock(&unread).take().filter(|b| !b.is_end_stream());
    if let Some(rest) = rest {
        let permit = if expects {
            None
        } else {
            drains.try_acquire().ok()
        };
        let ended = match permit {
            Some(_permit) => tokio::time::timeout(DRAIN_TIMEOUT, discard(rest))
                .await
                .unwrap_or(false),
            None => false,
        };
        if !ended {
            let headers = res.headers_mut();
            headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
        }
    }
    res
}

/// Reads and drops `body` frame by frame. True when it ends within `DRAIN_LIMIT`, false when it
/// fails or passes the limit.
async fn discard(body: Body) -> bool {
    let mut body = pin!(body);
    let mut left = DRAIN_LIMIT;
    loop {
        match poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
            None => return true,
            Some(Ok(frame)) => {
                let n = frame.data_ref().map_or(0, Bytes::len);
                let Some(rest) = left.checked_sub(n) else {
                    return false;
                };
                left = rest;
            }
            Some(Err(_)) => return false,
        }
    }
}

/// A request body the app reads through, which lets go of the body once it ends or fails, so
/// whatever is left after the app answers is the part it did not read.
struct Unread(Arc<Mutex<Option<Body>>>);

fn lock(body: &Mutex<Option<Body>>) -> MutexGuard<'_, Option<Body>> {
    body.lock().unwrap_or_else(PoisonError::into_inner)
}

impl HttpBody for Unread {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let mut slot = lock(&self.0);
        let Some(body) = slot.as_mut() else {
            return Poll::Ready(None);
        };
        let frame = ready!(Pin::new(body).poll_frame(cx));
        if !matches!(frame, Some(Ok(_))) {
            *slot = None;
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        lock(&self.0).as_ref().is_none_or(HttpBody::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        lock(&self.0)
            .as_ref()
            .map_or(SizeHint::with_exact(0), HttpBody::size_hint)
    }
}

/// hyper starts its header read timeout as soon as it waits for a request head, which closes an
/// idle keep-alive connection after 10 s. Go starts it at accept for the first request and at the
/// first bytes of each later one, and this timer does the same.
///
/// shortcut: a partial head that arrived in the same read as the previous request is not timed;
/// Go times it. Go keeps idle connections open without limit anyway, so this holds no more.
struct HeadTimer {
    /// Reads that returned bytes on this connection.
    reads: Arc<AtomicU64>,
    armed: AtomicBool,
}

impl Timer for HeadTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        TokioTimer::new().sleep(duration)
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        let first = !self.armed.swap(true, Ordering::Relaxed);
        Box::pin(HeadSleep {
            idle_at: (!first).then(|| self.reads.load(Ordering::Relaxed)),
            reads: self.reads.clone(),
            timeout: deadline.saturating_duration_since(Instant::now()),
            sleep: None,
        })
    }
}

struct HeadSleep {
    /// The read count when the timeout was set, while it waits for the next request's bytes.
    idle_at: Option<u64>,
    reads: Arc<AtomicU64>,
    timeout: Duration,
    sleep: Option<Pin<Box<dyn Sleep>>>,
}

impl Future for HeadSleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        if this
            .idle_at
            .is_some_and(|n| this.reads.load(Ordering::Relaxed) == n)
        {
            // hyper polls this only after a read returned Pending, so that read wakes the task.
            return Poll::Pending;
        }
        this.sleep
            .get_or_insert_with(|| TokioTimer::new().sleep(this.timeout))
            .as_mut()
            .poll(cx)
    }
}

impl Sleep for HeadSleep {}

struct CountReads {
    stream: TcpStream,
    reads: Arc<AtomicU64>,
}

impl AsyncRead for CountReads {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.stream).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.reads.fetch_add(1, Ordering::Relaxed);
        }
        res
    }
}

impl AsyncWrite for CountReads {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
