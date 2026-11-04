//! Go's login limiter (`internal/api/v1/ratelimit.go`): a fixed window per client address,
//! shared by login and the two OIDC routes, with loopback exempt.
//!
//! The address comes from chi's `RealIP` (`True-Client-IP`, then `X-Real-IP`, then the first
//! `X-Forwarded-For` hop), which trusts those headers from any caller. A caller can therefore
//! pick its own key, loopback included. Go has the same defect; it is kept here for parity and
//! fixed in a later change.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use crate::server::error_response;

/// Go prunes expired windows once the map holds more keys than this.
const PRUNE_ABOVE: usize = 1024;

pub struct RateLimiter {
    max: u32,
    window: Duration,
    hits: Mutex<HashMap<String, Window>>,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

struct Window {
    count: u32,
    reset: Instant,
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            hits: Mutex::default(),
            now: Box::new(Instant::now),
        }
    }

    /// Go's `allow`: counts an attempt for `key`. Over the limit, the time until its window
    /// resets.
    fn allow(&self, key: &str) -> Result<(), Duration> {
        let mut hits = self.hits.lock().unwrap_or_else(PoisonError::into_inner);
        let now = (self.now)();
        match hits.get_mut(key) {
            Some(w) if now <= w.reset => {
                if w.count >= self.max {
                    return Err(w.reset - now);
                }
                w.count += 1;
            }
            _ => {
                if hits.len() > PRUNE_ABOVE {
                    hits.retain(|_, w| now <= w.reset);
                }
                let reset = now + self.window;
                hits.insert(key.to_owned(), Window { count: 1, reset });
            }
        }
        Ok(())
    }
}

/// Answers 429 with `Retry-After` (whole seconds left, plus one) once a remote address is over
/// its limit. Successful attempts count too.
pub async fn limit(State(limiter): State<Arc<RateLimiter>>, req: Request, next: Next) -> Response {
    let ip = client_ip(&req);
    let loopback = ip
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.to_canonical().is_loopback());
    if ip.is_empty() || loopback {
        return next.run(req).await;
    }
    match limiter.allow(&ip) {
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

/// The limiter key: chi's `RealIP` header value when it parses as an IP address, as written,
/// else the connection's address as Go prints it. Empty when there is neither (tests).
fn client_ip(req: &Request) -> String {
    if let Some(ip) = real_ip(req.headers()) {
        return ip.to_owned();
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| peer.ip().to_canonical().to_string())
        .unwrap_or_default()
}

/// chi's `realIP`: the first header present decides, and an unparsable value means none.
fn real_ip(headers: &HeaderMap) -> Option<&str> {
    let value = |name| {
        headers
            .get(name)
            .map(HeaderValue::as_bytes)
            .filter(|v| !v.is_empty())
    };
    let ip = value("true-client-ip")
        .or_else(|| value("x-real-ip"))
        .or_else(|| value("x-forwarded-for").and_then(|v| v.split(|&b| b == b',').next()))?;
    let ip = std::str::from_utf8(ip).ok()?;
    ip.parse::<IpAddr>().is_ok().then_some(ip)
}

#[cfg(test)]
mod tests;
