//! The limiter's window, its storage cap, and how it picks the client address.

use std::net::Ipv4Addr;

use axum::body::Body;
use axum::middleware;
use axum::routing::post;
use axum::Router;
use tower::ServiceExt;

use super::*;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

fn nets(list: &[&str]) -> Arc<[IpNet]> {
    crate::config::trusted_proxies(&list.join(","))
        .unwrap()
        .into()
}

/// A limiter whose clock the test moves.
fn limiter(max: u32) -> (RateLimiter, Arc<Mutex<Instant>>) {
    let clock = Arc::new(Mutex::new(Instant::now()));
    let mut rl = RateLimiter::new(max, Duration::from_secs(60), nets(&[]));
    let c = clock.clone();
    rl.now = Box::new(move || *c.lock().unwrap());
    (rl, clock)
}

fn advance(clock: &Mutex<Instant>, d: Duration) {
    *clock.lock().unwrap() += d;
}

/// A distinct address for each `i`.
fn addr(i: usize) -> IpAddr {
    IpAddr::V6((0x2001_0db8_u128 << 96 | i as u128).into())
}

#[test]
fn allows_up_to_max_then_blocks() {
    let (rl, _) = limiter(3);
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
    // The window is closed at both ends: the reset instant itself is still inside it.
    advance(&clock, Duration::from_secs(60));
    assert_eq!(rl.allow(IP), Err(Duration::ZERO));
    advance(&clock, Duration::from_nanos(1));
    assert!(rl.allow(IP).is_ok(), "a fresh window allows again");
    assert!(rl.allow(IP).is_err());
}

#[test]
fn each_address_has_its_own_window() {
    let (rl, _) = limiter(1);
    assert!(rl.allow(addr(1)).is_ok());
    assert!(rl.allow(addr(2)).is_ok());
}

#[test]
fn windows_that_have_reset_are_dropped() {
    let (rl, clock) = limiter(10);
    for i in 0..100 {
        rl.allow(addr(i)).unwrap();
    }
    advance(&clock, Duration::from_secs(30));
    rl.allow(addr(100)).unwrap();
    advance(&clock, Duration::from_secs(31));
    rl.allow(addr(101)).unwrap();
    let hits = rl.hits.lock().unwrap();
    assert_eq!(hits.windows.len(), 2);
    assert_eq!(hits.order.len(), 2);
}

/// Past `MAX_KEYS` addresses the oldest window goes. A new address is never refused for room,
/// and a blocked address stays blocked until its window is the oldest.
#[test]
fn the_table_is_capped_by_dropping_the_oldest_window() {
    let (rl, clock) = limiter(1);
    rl.allow(IP).unwrap();
    assert!(rl.allow(IP).is_err());
    for i in 1..MAX_KEYS {
        advance(&clock, Duration::from_nanos(1));
        assert!(rl.allow(addr(i)).is_ok(), "address {i}");
    }
    assert!(rl.allow(IP).is_err(), "still blocked with the table full");
    assert!(
        rl.allow(addr(MAX_KEYS)).is_ok(),
        "a new address past the cap"
    );
    assert_eq!(rl.hits.lock().unwrap().windows.len(), MAX_KEYS);
    assert!(rl.allow(IP).is_ok(), "the oldest window was dropped");
    assert!(
        rl.allow(addr(1)).is_ok(),
        "so was the next oldest, for IP's new window"
    );
    let hits = rl.hits.lock().unwrap();
    assert_eq!((hits.windows.len(), hits.order.len()), (MAX_KEYS, MAX_KEYS));
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
    let app = app(limiter(1).0);
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
    // 59.5 s left: whole seconds plus one.
    assert_eq!(blocked.headers()[header::RETRY_AFTER], "60");
    let body = axum::body::to_bytes(blocked.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(body.to_vec()).unwrap(),
        "{\"error\":{\"code\":\"rate_limited\",\"message\":\"too many login attempts — slow down and try again shortly\"}}\n"
    );
}

/// The peer is the client unless it is a trusted proxy; then `X-Forwarded-For` is walked from
/// the right while the address so far is trusted.
#[test]
fn the_key_is_the_peer_or_the_hop_before_the_trusted_proxies() {
    let trusted = ["192.0.2.0/24", "2001:db8::1", "203.0.113.128/25"];
    let rl = RateLimiter::new(10, Duration::from_secs(60), nets(&trusted));
    let key = |peer: &str, xff: &[&str]| {
        let mut headers = HeaderMap::new();
        for v in xff {
            headers.append("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        }
        rl.client_ip(peer.parse().unwrap(), &headers).to_string()
    };
    let cases: [(&str, &[&str], &str); 13] = [
        ("203.0.113.9", &[], "203.0.113.9"),
        ("203.0.113.9", &["198.51.100.7"], "203.0.113.9"),
        ("192.0.2.1", &[], "192.0.2.1"),
        ("192.0.2.1", &["198.51.100.7"], "198.51.100.7"),
        ("192.0.2.1", &["127.0.0.1, 198.51.100.7"], "198.51.100.7"),
        (
            "192.0.2.1",
            &["198.51.100.1, 198.51.100.7, 192.0.2.9"],
            "198.51.100.7",
        ),
        (
            "192.0.2.1",
            &["198.51.100.1", "198.51.100.7"],
            "198.51.100.7",
        ),
        ("192.0.2.1", &["203.0.113.200,192.0.2.9"], "203.0.113.200"),
        ("192.0.2.1", &["198.51.100.7, not-an-address"], "192.0.2.1"),
        ("192.0.2.1", &["198.51.100.7:4711"], "198.51.100.7"),
        ("192.0.2.1", &["[2001:db8::7]:4711"], "2001:db8::7"),
        ("2001:db8::1", &["::ffff:198.51.100.7"], "198.51.100.7"),
        ("2001:db8::2", &["198.51.100.7"], "2001:db8::2"),
    ];
    for (peer, xff, want) in cases {
        assert_eq!(key(peer, xff), want, "{peer} {xff:?}");
    }
}

/// Loopback named in a header is exempt only on a loopback connection: from a remote proxy,
/// trusted or not, it counts.
#[tokio::test]
async fn forwarded_loopback_is_exempt_only_from_a_loopback_peer() {
    let trusted = nets(&["127.0.0.1", "192.0.2.1"]);
    let app = app(RateLimiter::new(1, Duration::from_secs(60), trusted));
    let via = |ip: [u8; 4]| peer(Ipv4Addr::from(ip));
    for _ in 0..3 {
        let res = send(&app, via([127, 0, 0, 1]), &[("x-forwarded-for", "::1")]).await;
        assert_eq!(res.status(), StatusCode::OK);
    }
    assert_eq!(
        send(
            &app,
            via([127, 0, 0, 1]),
            &[("x-forwarded-for", "198.51.100.7")]
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        send(
            &app,
            via([127, 0, 0, 1]),
            &[("x-forwarded-for", "198.51.100.7")]
        )
        .await
        .status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a local proxy's clients are limited"
    );
    for (ip, xff) in [
        ([192, 0, 2, 1], "127.0.0.1"),
        ([203, 0, 113, 5], "127.0.0.1"),
    ] {
        assert_eq!(
            send(&app, via(ip), &[("x-forwarded-for", xff)])
                .await
                .status(),
            StatusCode::OK
        );
        let res = send(&app, via(ip), &[("x-forwarded-for", xff)]).await;
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS, "{ip:?}");
    }
}

async fn login_from(app: &Router, peer: &str, headers: &[(&'static str, &str)]) -> StatusCode {
    let mut req = axum::http::Request::post("/api/v1/auth/login")
        .header(header::HOST, "console.example")
        .body(Body::from("{"))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    for (name, value) in headers {
        req.headers_mut()
            .insert(*name, HeaderValue::from_str(value).unwrap());
    }
    app.clone().oneshot(req).await.unwrap().status()
}

fn console() -> Router {
    crate::server::router(crate::server::AppState::for_tests(
        "0123456789abcdefghijklmnopqrstuv",
        Arc::new(crate::fleet::Mock::new(1_779_192_000)),
    ))
}

/// A remote client cannot claim loopback, or any other address, through a forwarding header
/// when no proxy is trusted: every attempt counts against its own address.
#[tokio::test]
async fn forwarding_headers_from_an_untrusted_peer_are_ignored() {
    let names = ["true-client-ip", "x-real-ip", "x-forwarded-for"];
    for name in names {
        let app = console();
        for i in 0..10 {
            let status = login_from(&app, "203.0.113.9:4000", &[(name, "127.0.0.1")]).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{name} attempt {i}");
        }
        let status = login_from(&app, "203.0.113.9:4000", &[(name, "127.0.0.1")]).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{name}");
    }
    let app = console();
    for i in 0..10 {
        let ip = format!("198.51.100.{i}");
        let status = login_from(&app, "203.0.113.9:4000", &[("x-forwarded-for", &ip)]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "attempt {i}");
    }
    let status = login_from(
        &app,
        "203.0.113.9:4000",
        &[("x-forwarded-for", "198.51.100.99")],
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "rotating addresses");
}
