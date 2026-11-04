//! The listener and connection loop, with the behavior of Go's `http.Server` as `main.go` sets
//! it up: HTTP/1.1 only, a 10 s header read timeout, no idle timeout, and a 5 s drain.

use std::future::Future;
use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::pin::{pin, Pin};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::extract::ConnectInfo;
use axum::{Extension, Router};
use hyper::rt::{Sleep, Timer};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tower::Layer;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
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
