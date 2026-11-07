//! Idle HTTP/1.1 connections to one route's upstream, reused by later calls.
//!
//! One pool per [`crate::route::Route`], so a new route table (a config apply)
//! starts with no connections. Everything a connection carries is fixed by the
//! route: scheme, host, port, TLS server name and the destination check. The
//! upstream credential, the upstream session id and the other headers are set on
//! each request, so a connection can carry calls of any principal of the route.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http1::SendRequest;

pub(crate) type Sender = SendRequest<Full<Bytes>>;

/// Stop reusing a connection after this much idle time. It is below the idle
/// timeouts of common server stacks (gunicorn 2 s, Node `http` and uvicorn 5 s),
/// so the upstream does not close a connection at the moment the proxy reuses it.
const MAX_IDLE: Duration = Duration::from_secs(1);

struct Idle {
    sender: Sender,
    peer: SocketAddr,
    since: Instant,
}

#[derive(Default)]
pub(crate) struct UpstreamPool(Mutex<Vec<Idle>>);

impl UpstreamPool {
    /// The most recently idle connection to one of `checked`, the addresses this
    /// request's destination check allowed. Expired and closed entries are
    /// closed. Entries to other addresses stay until they expire.
    pub(crate) fn take(&self, checked: &[SocketAddr]) -> Option<(Sender, SocketAddr)> {
        let mut idle = self.0.lock().unwrap_or_else(|e| e.into_inner());
        idle.retain(|c| c.since.elapsed() < MAX_IDLE && c.sender.is_ready());
        let i = idle.iter().rposition(|c| checked.contains(&c.peer))?;
        let c = idle.remove(i);
        Some((c.sender, c.peer))
    }

    /// Put `sender` back once hyper reports it ready for the next request.
    /// hyper signals ready only when the connection is back in its initial
    /// state, which is after the previous response was read to the end. A
    /// response that was not read to the end, a `Connection: close` or an error
    /// closes the connection instead, and it is not pooled. At most `cap`
    /// connections stay idle; the oldest is closed to make room.
    pub(crate) fn put_when_idle(
        self: &Arc<Self>,
        mut sender: Sender,
        peer: SocketAddr,
        cap: usize,
    ) {
        let pool = self.clone();
        tokio::spawn(async move {
            if sender.ready().await.is_ok() {
                pool.push(sender, peer, cap);
            }
        });
    }

    fn push(&self, sender: Sender, peer: SocketAddr, cap: usize) {
        let mut idle = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() >= cap {
            idle.remove(0);
        }
        idle.push(Idle {
            sender,
            peer,
            since: Instant::now(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper_util::rt::TokioIo;

    #[tokio::test]
    async fn push_keeps_at_most_cap_connections() {
        let pool = UpstreamPool::default();
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut far_ends = Vec::new();
        for _ in 0..3 {
            let (near, far) = tokio::io::duplex(64);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(near))
                .await
                .unwrap();
            tokio::spawn(conn);
            sender.ready().await.unwrap();
            far_ends.push(far);
            pool.push(sender, peer, 2);
        }
        assert!(pool.take(&[peer]).is_some());
        assert!(pool.take(&[peer]).is_some());
        assert!(
            pool.take(&[peer]).is_none(),
            "a third idle connection was kept"
        );
    }
}
