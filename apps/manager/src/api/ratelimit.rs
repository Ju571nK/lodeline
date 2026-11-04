//! The login limiter: a fixed window per client address, shared by login and the two OIDC
//! routes, with loopback exempt.
//!
//! The client address is the connection's peer. Only when the peer is a trusted proxy
//! (`TRUSTED_PROXIES`) does `X-Forwarded-For` count, and then the client is the rightmost hop
//! that is not a trusted proxy: the hops a client writes itself sit to the left of the ones its
//! proxies append, so it cannot pick its own key.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;

use crate::server::error_response;

/// The most addresses with an open window. Past it the oldest window is dropped: it is the one
/// closest to its reset, and dropping a window can only let an address try again early, never
/// lock one out.
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
}

struct Window {
    count: u32,
    reset: Instant,
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
            if w.count >= self.max {
                return Err(w.reset - now);
            }
            w.count += 1;
            return Ok(());
        }
        while let Some(&(old, reset)) = hits.order.front() {
            if now <= reset && hits.windows.len() < MAX_KEYS {
                break;
            }
            hits.order.pop_front();
            if hits.windows.get(&old).is_some_and(|w| w.reset == reset) {
                hits.windows.remove(&old);
            }
        }
        let reset = now + self.window;
        hits.windows.insert(key, Window { count: 1, reset });
        hits.order.push_back((key, reset));
        Ok(())
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

/// Answers 429 with `Retry-After` (whole seconds left, plus one) once a remote address is over
/// its limit. Successful attempts count too.
pub async fn limit(State(limiter): State<Arc<RateLimiter>>, req: Request, next: Next) -> Response {
    let Some(&ConnectInfo(peer)) = req.extensions().get::<ConnectInfo<SocketAddr>>() else {
        return next.run(req).await;
    };
    let peer = peer.ip().to_canonical();
    let ip = limiter.client_ip(peer, req.headers());
    // Loopback is exempt only on a loopback connection, so a header cannot claim it.
    if peer.is_loopback() && ip.is_loopback() {
        return next.run(req).await;
    }
    match limiter.allow(ip) {
        Ok(()) => next.run(req).await,
        Err(retry) => {
            let mut res = error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many login attempts — slow down and try again shortly",
            );
            res.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(retry.as_secs() + 1));
            res
        }
    }
}

#[cfg(test)]
mod tests;
