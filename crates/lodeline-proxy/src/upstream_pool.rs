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

    /// Put `sender` back once hyper reports it ready for the next request, which
    /// is after the previous response was read to the end. A response that was
    /// not read to the end, a `Connection: close` or an error closes the
    /// connection instead, and it is not pooled. In a rare race hyper reports
    /// ready early. A request sent then waits in hyper's queue until the
    /// previous response ends, so responses never mix.
    pub(crate) fn put_when_idle(self: &Arc<Self>, mut sender: Sender, peer: SocketAddr) {
        let pool = self.clone();
        tokio::spawn(async move {
            if sender.ready().await.is_ok() {
                pool.0.lock().unwrap_or_else(|e| e.into_inner()).push(Idle {
                    sender,
                    peer,
                    since: Instant::now(),
                });
            }
        });
    }
}
