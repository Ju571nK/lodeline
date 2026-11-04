//! The login limiter: a fixed window per client address, shared by login and the two OIDC
//! routes. No address is exempt, loopback included: a reverse proxy on the same host is a
//! loopback peer.
//!
//! The client address is the connection's peer. Only when the peer is a trusted proxy
//! (`TRUSTED_PROXIES`) does `X-Forwarded-For` count, and then the client is the rightmost hop
//! that is not a trusted proxy: the hops a client writes itself sit to the left of the ones its
//! proxies append, so it cannot pick its own key. An IPv6 client is keyed by its /64, the
//! smallest block a host is usually given, so it cannot step through addresses of its own.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;

use crate::api::LOGIN_BODY_LIMIT;
use crate::server::error_response;

/// How long a 429 waits for the rest of the request body, which a client sends right behind
/// the head.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// The most addresses with a window of their own. While the table is full of open windows, new
/// addresses share one overflow window with the same limit, so no open window is ever dropped
/// early. Until the overflow window resets, a new address that gets a window of its own starts
/// with the overflow window's count and reset.
const MAX_KEYS: usize = 1 << 16;

pub struct RateLimiter {
    max: u32,
    window: Duration,
    trusted: Arc<[IpNet]>,
    hits: Mutex<Hits>,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

#[derive(Default)]
struct Hits {
    windows: HashMap<IpAddr, Window>,
    /// Each window's key and reset, oldest first. Every window has the same length, so this is
    /// also the order they reset in.
    order: VecDeque<(IpAddr, Instant)>,
    overflow: Option<Window>,
}

#[derive(Clone, Copy)]
struct Window {
    count: u32,
    reset: Instant,
}

impl Window {
    fn take(&mut self, max: u32, now: Instant) -> Result<(), Duration> {
        if self.count >= max {
            return Err(self.reset - now);
        }
        self.count += 1;
        Ok(())
    }
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration, trusted: Arc<[IpNet]>) -> Self {
        Self {
            max,
            window,
            trusted,
            hits: Mutex::default(),
            now: Box::new(Instant::now),
        }
    }

    /// Counts an attempt for `key`. Over the limit, the time until its window resets.
    fn allow(&self, key: IpAddr) -> Result<(), Duration> {
        let mut hits = self.hits.lock().unwrap_or_else(PoisonError::into_inner);
        let now = (self.now)();
        if let Some(w) = hits.windows.get_mut(&key).filter(|w| now <= w.reset) {
            return w.take(self.max, now);
        }
        while let Some(&(old, reset)) = hits.order.front() {
            if now <= reset {
                break;
            }
            hits.order.pop_front();
            if hits.windows.get(&old).is_some_and(|w| w.reset == reset) {
                hits.windows.remove(&old);
            }
        }
        // While the overflow window is open, a new window starts as a copy of it: the overflow
        // window does not record which addresses it counted, so this one may be among them.
        // Its reset is no earlier than any open window's, so `order` stays sorted.
        let mut w = hits.overflow.filter(|w| now <= w.reset).unwrap_or(Window {
            count: 0,
            reset: now + self.window,
        });
        let taken = w.take(self.max, now);
        if hits.windows.len() >= MAX_KEYS {
            hits.overflow = Some(w);
        } else {
            hits.windows.insert(key, w);
            hits.order.push_back((key, w.reset));
        }
        taken
    }

    /// The peer, or behind trusted proxies the rightmost `X-Forwarded-For` hop that is not one.
    /// A hop that is not an address ends the walk at the proxy that passed it on.
    fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let hops: Vec<&[u8]> = headers
            .get_all("x-forwarded-for")
            .iter()
            .flat_map(|v| v.as_bytes().split(|&b| b == b','))
            .collect();
        let mut ip = peer;
        for hop in hops.into_iter().rev() {
            if !self.trusted.iter().any(|net| net.contains(&ip)) {
                break;
            }
            match std::str::from_utf8(hop).ok().and_then(parse_hop) {
                Some(next) => ip = next,
                None => break,
            }
        }
        ip
    }
}

/// An address as proxies write it in `X-Forwarded-For`, with or without a port.
fn parse_hop(hop: &str) -> Option<IpAddr> {
    let hop = hop.trim_matches([' ', '\t']);
    let ip = hop
        .parse::<IpAddr>()
        .or_else(|_| hop.parse::<SocketAddr>().map(|s| s.ip()))
        .ok()?;
    Some(ip.to_canonical())
}

/// The limiter key for a client address: an IPv4 address itself, an IPv6 address its /64.
fn key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => Ipv6Addr::from(u128::from(v6) & !(u64::MAX as u128)).into(),
        v4 => v4,
    }
}

/// Answers 429 with `Retry-After` (whole seconds left, plus one) and `Connection: close` once a
/// client address is over its limit. Successful attempts count too.
pub async fn limit(State(limiter): State<Arc<RateLimiter>>, req: Request, next: Next) -> Response {
    // `conn.rs` sets the peer on every connection; without one, every such request shares a key.
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(Ipv4Addr::UNSPECIFIED.into(), |c| c.0.ip().to_canonical());
    let ip = limiter.client_ip(peer, req.headers());
    match limiter.allow(key(ip)) {
        Ok(()) => next.run(req).await,
        Err(retry) => {
            // A connection closed with unread input resets, and the client can lose the 429 to
            // that reset, so read a login-sized body that arrives soon; past that, close anyway.
            let body = axum::body::to_bytes(req.into_body(), LOGIN_BODY_LIMIT);
            let _ = tokio::time::timeout(DRAIN_TIMEOUT, body).await;
            let mut res = error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many login attempts — slow down and try again shortly",
            );
            let headers = res.headers_mut();
            headers.insert(header::RETRY_AFTER, HeaderValue::from(retry.as_secs() + 1));
            headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
            res
        }
    }
}

#[cfg(test)]
mod tests;
