//! Go's `ratelimit_test.go`, plus chi `RealIP` precedence, pruning and `Retry-After`.

use std::net::Ipv4Addr;

use axum::body::Body;
use axum::middleware;
use axum::routing::post;
use axum::Router;
use tower::ServiceExt;

use super::*;

const IP: &str = "203.0.113.7";

/// A limiter whose clock the test moves.
fn limiter(max: u32) -> (RateLimiter, Arc<Mutex<Instant>>) {
    let clock = Arc::new(Mutex::new(Instant::now()));
    let mut rl = RateLimiter::new(max, Duration::from_secs(60));
    let c = clock.clone();
    rl.now = Box::new(move || *c.lock().unwrap());
    (rl, clock)
}

fn advance(clock: &Mutex<Instant>, d: Duration) {
    *clock.lock().unwrap() += d;
}

#[test]
fn allows_up_to_max_then_blocks() {
    let rl = RateLimiter::new(3, Duration::from_secs(60));
    for i in 1..=3 {
        assert!(rl.allow(IP).is_ok(), "attempt {i}");
    }
    assert!(rl.allow(IP).unwrap_err() > Duration::ZERO);
}

#[test]
fn the_window_resets_after_it_has_passed() {
    let (rl, clock) = limiter(1);
    assert!(rl.allow(IP).is_ok());
    assert_eq!(rl.allow(IP), Err(Duration::from_secs(60)));
    // Go's window is closed at both ends: the reset instant itself is still inside it.
    advance(&clock, Duration::from_secs(60));
    assert_eq!(rl.allow(IP), Err(Duration::ZERO));
    advance(&clock, Duration::from_nanos(1));
    assert!(rl.allow(IP).is_ok(), "a fresh window allows again");
    assert!(rl.allow(IP).is_err());
}

#[test]
fn each_address_has_its_own_window() {
    let rl = RateLimiter::new(1, Duration::from_secs(60));
    assert!(rl.allow("203.0.113.1").is_ok());
    assert!(rl.allow("203.0.113.2").is_ok());
}

#[test]
fn expired_windows_are_pruned_only_above_1024_keys() {
    let (rl, clock) = limiter(10);
    let key = |i: usize| format!("k{i}");
    for i in 0..=PRUNE_ABOVE {
        rl.allow(&key(i)).unwrap();
    }
    advance(&clock, Duration::from_secs(61));
    let len = || rl.hits.lock().unwrap().len();
    assert_eq!(len(), PRUNE_ABOVE + 1);
    rl.allow("new").unwrap();
    assert_eq!(len(), 1);
    let (rl, clock) = limiter(10);
    for i in 0..PRUNE_ABOVE {
        rl.allow(&key(i)).unwrap();
    }
    advance(&clock, Duration::from_secs(61));
    rl.allow("new").unwrap();
    assert_eq!(
        rl.hits.lock().unwrap().len(),
        PRUNE_ABOVE + 1,
        "1024 keys is not above"
    );
}

async fn send(
    app: &Router,
    peer: Option<SocketAddr>,
    headers: &[(&'static str, &str)],
) -> Response {
    let mut req = axum::http::Request::post("/").body(Body::empty()).unwrap();
    if let Some(peer) = peer {
        req.extensions_mut().insert(ConnectInfo(peer));
    }
    for (name, value) in headers {
        req.headers_mut()
            .insert(*name, HeaderValue::from_str(value).unwrap());
    }
    app.clone().oneshot(req).await.unwrap()
}

fn app(rl: RateLimiter) -> Router {
    Router::new()
        .route("/", post(|| async { StatusCode::OK }))
        .layer(middleware::from_fn_with_state(Arc::new(rl), limit))
}

fn peer(ip: Ipv4Addr) -> Option<SocketAddr> {
    Some(SocketAddr::from((ip, 54321)))
}

#[tokio::test]
async fn loopback_is_never_limited() {
    let app = app(RateLimiter::new(1, Duration::from_secs(60)));
    let mapped: SocketAddr = "[::ffff:127.0.0.1]:1".parse().unwrap();
    for addr in [
        peer(Ipv4Addr::LOCALHOST),
        peer(Ipv4Addr::new(127, 0, 0, 2)),
        Some("[::1]:1".parse().unwrap()),
        Some(mapped),
        None,
    ] {
        for i in 0..5 {
            let res = send(&app, addr, &[]).await;
            assert_eq!(res.status(), StatusCode::OK, "{addr:?} attempt {i}");
        }
    }
}

#[tokio::test]
async fn a_remote_address_over_the_limit_gets_429() {
    let (rl, clock) = limiter(1);
    let app = app(rl);
    let remote = peer(Ipv4Addr::new(203, 0, 113, 9));
    assert_eq!(send(&app, remote, &[]).await.status(), StatusCode::OK);
    advance(&clock, Duration::from_millis(500));
    let blocked = send(&app, remote, &[]).await;
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    // 59.5 s left: Go's int(Seconds()) + 1.
    assert_eq!(blocked.headers()[header::RETRY_AFTER], "60");
    let body = axum::body::to_bytes(blocked.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(body.to_vec()).unwrap(),
        "{\"error\":{\"code\":\"rate_limited\",\"message\":\"too many login attempts — slow down and try again shortly\"}}\n"
    );
}

/// chi `RealIP`: `True-Client-IP`, then `X-Real-IP`, then the first `X-Forwarded-For` hop; the
/// first header present decides, and a value that is not an IP address falls back to the peer.
#[test]
fn the_key_follows_chi_real_ip() {
    let key = |headers: &[(&'static str, &str)]| {
        let mut req = Request::new(Body::empty());
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 40000))));
        for (name, value) in headers {
            req.headers_mut()
                .append(*name, HeaderValue::from_bytes(value.as_bytes()).unwrap());
        }
        client_ip(&req)
    };
    let cases: [(&[(&str, &str)], &str); 11] = [
        (&[], "192.0.2.1"),
        (
            &[("x-forwarded-for", "203.0.113.20, 198.51.100.7")],
            "203.0.113.20",
        ),
        (&[("x-forwarded-for", " 203.0.113.20")], "192.0.2.1"),
        (&[("x-real-ip", "203.0.113.21")], "203.0.113.21"),
        (&[("true-client-ip", "203.0.113.22")], "203.0.113.22"),
        (
            &[
                ("true-client-ip", "203.0.113.23"),
                ("x-real-ip", "203.0.113.24"),
                ("x-forwarded-for", "203.0.113.25"),
            ],
            "203.0.113.23",
        ),
        // An invalid first header is not passed over for the next one.
        (
            &[("true-client-ip", "nope"), ("x-real-ip", "203.0.113.24")],
            "192.0.2.1",
        ),
        (&[("x-forwarded-for", "not-an-address")], "192.0.2.1"),
        (&[("x-forwarded-for", "::1")], "::1"),
        (
            &[("x-real-ip", "203.0.113.1"), ("x-real-ip", "203.0.113.2")],
            "203.0.113.1",
        ),
        (&[("x-forwarded-for", "2001:DB8::1")], "2001:DB8::1"),
    ];
    for (headers, want) in cases {
        assert_eq!(key(headers), want, "{headers:?}");
    }
    let mut req = Request::new(Body::empty());
    req.extensions_mut().insert(ConnectInfo(
        "[::ffff:192.0.2.5]:1".parse::<SocketAddr>().unwrap(),
    ));
    assert_eq!(client_ip(&req), "192.0.2.5");
}

/// The forwarding headers can name loopback, which is exempt: Go's defect, kept for parity.
#[tokio::test]
async fn a_forwarded_loopback_address_is_exempt() {
    let app = app(RateLimiter::new(1, Duration::from_secs(60)));
    let remote = peer(Ipv4Addr::new(203, 0, 113, 9));
    for _ in 0..3 {
        let res = send(&app, remote, &[("x-forwarded-for", "::ffff:127.0.0.1")]).await;
        assert_eq!(res.status(), StatusCode::OK);
    }
}
