//! Raw-socket checks of the connection timeouts and the listener, against Go's `http.Server`.

use super::*;
use axum::routing::get;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";

async fn start() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/", get(|| async { "ok" }));
    tokio::spawn(serve(listener, app, std::future::pending()));
    addr
}

async fn exchange(stream: &mut TcpStream) -> String {
    stream.write_all(REQUEST).await.unwrap();
    let mut buf = vec![0; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// Seconds until the server closes `stream`.
async fn closed_after(stream: &mut TcpStream) -> f64 {
    let start = Instant::now();
    let mut buf = [0; 64];
    while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
    start.elapsed().as_secs_f64()
}

#[tokio::test]
async fn an_idle_keep_alive_connection_waits_for_the_next_request() {
    let mut s = TcpStream::connect(start().await).await.unwrap();
    assert!(exchange(&mut s).await.starts_with("HTTP/1.1 200"));
    tokio::time::sleep(Duration::from_secs(13)).await;
    assert!(exchange(&mut s).await.starts_with("HTTP/1.1 200"));
}

#[tokio::test]
async fn a_later_partial_head_is_closed_10_s_after_its_first_bytes() {
    let mut s = TcpStream::connect(start().await).await.unwrap();
    assert!(exchange(&mut s).await.starts_with("HTTP/1.1 200"));
    tokio::time::sleep(Duration::from_secs(3)).await;
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
    let secs = closed_after(&mut s).await;
    assert!((9.5..11.0).contains(&secs), "closed after {secs:.2} s");
}

#[tokio::test]
async fn a_first_request_head_is_timed_from_accept() {
    let mut s = TcpStream::connect(start().await).await.unwrap();
    let secs = closed_after(&mut s).await;
    assert!((9.5..11.0).contains(&secs), "closed after {secs:.2} s");
}

#[tokio::test]
async fn a_port_alone_listens_on_ipv4_and_ipv6() {
    let listener = bind(":0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    for host in ["127.0.0.1", "[::1]"] {
        TcpStream::connect(format!("{host}:{port}"))
            .await
            .unwrap_or_else(|e| panic!("{host}: {e}"));
    }
}

async fn start_console() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = crate::server::AppState::for_tests(
        "0123456789abcdefghijklmnopqrstuv",
        Arc::new(crate::fleet::Mock::new(1_767_225_600)),
    );
    tokio::spawn(serve(
        listener,
        crate::server::router(state),
        std::future::pending(),
    ));
    addr
}

fn head(target: &str, content_type: &str, len: usize) -> String {
    format!("{target} HTTP/1.1\r\nHost: x\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\n\r\n")
}

/// Requests the console answers before it has read their whole body, the parts their body is
/// sent in, and the status of each. A 413 answers once the first part passes the limit.
fn early_answers() -> Vec<(&'static str, String, Vec<Vec<u8>>, &'static str)> {
    let json = "application/json";
    let small = || vec![b"{}".to_vec()];
    let big = vec![
        [b"{\"username\":\"".as_slice(), &[b'x'; 70_000]].concat(),
        vec![b'x'; 1000],
    ];
    [
        ("session", "POST /api/v1/triage/note", json, small(), "401"),
        ("method", "POST /api/v1/fleet/meta", json, small(), "405"),
        ("too large", "POST /api/v1/auth/login", json, big, "413"),
        (
            "media type",
            "POST /api/v1/auth/login",
            "text/plain",
            small(),
            "415",
        ),
        ("no route", "POST /api/v1/nope", json, small(), "404"),
        ("bad path", "POST /%zz", json, small(), "400"),
    ]
    .into_iter()
    .map(|(what, target, ct, parts, status)| {
        let len = parts.iter().map(Vec::len).sum();
        (what, head(target, ct, len), parts, status)
    })
    .collect()
}

/// The answers in `raw`, each checked to be whole by its `Content-Length`.
fn responses(raw: &[u8]) -> Vec<String> {
    let mut text = String::from_utf8_lossy(raw).into_owned();
    let mut out = Vec::new();
    while let Some(end) = text.find("\r\n\r\n") {
        let len: usize = text[..end]
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .map_or(0, |n| n.parse().unwrap());
        let rest = text.split_off((end + 4 + len).min(text.len()));
        assert_eq!(text.len(), end + 4 + len, "a whole answer: {text}");
        out.push(std::mem::replace(&mut text, rest));
    }
    assert!(text.is_empty(), "trailing bytes: {text}");
    out
}

/// Sends `head`, then each part 200 ms after the last, and reads to the end of stream, which must
/// come within 5 s and be clean.
async fn send_late(addr: SocketAddr, what: &str, head: &str, parts: &[Vec<u8>]) -> Vec<String> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(head.as_bytes()).await.unwrap();
    let mut sent = Ok(());
    for part in parts {
        tokio::time::sleep(Duration::from_millis(200)).await;
        sent = sent.and(s.write_all(part).await);
    }
    let mut raw = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut raw)).await;
    let read = read.unwrap_or(Err(io::ErrorKind::TimedOut.into()));
    assert!(sent.is_ok() && read.is_ok(), "{what}: {sent:?} {read:?}");
    responses(&raw)
}

/// A client that sends its body after the head still reads the whole early answer and a clean
/// end of stream, and is told the connection closes.
#[tokio::test]
async fn an_early_answer_waits_for_a_body_sent_after_the_head() {
    let addr = start_console().await;
    for (what, head, body, status) in early_answers() {
        let res = send_late(addr, what, &head, &body).await;
        assert_eq!(res.len(), 1, "{what}: {res:?}");
        assert!(
            res[0].starts_with(&format!("HTTP/1.1 {status} ")),
            "{what}: {res:?}"
        );
        assert!(
            res[0].contains("\r\nconnection: close\r\n"),
            "{what}: {res:?}"
        );
    }
}

/// A keep-alive client that sends its next request right behind the body gets the early answer,
/// told the connection closes, and a clean end of stream instead of a reset. A body read in full
/// keeps the connection open for the next request.
#[tokio::test]
async fn a_reused_connection_closes_cleanly_after_an_early_answer() {
    let addr = start_console().await;
    let next = b"GET /api/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    for (what, head, body, status) in early_answers() {
        let mut parts = body;
        parts.last_mut().unwrap().extend_from_slice(next);
        let res = send_late(addr, what, &head, &parts).await;
        assert_eq!(res.len(), 1, "{what}: {res:?}");
        assert!(
            res[0].starts_with(&format!("HTTP/1.1 {status} ")),
            "{what}: {res:?}"
        );
        assert!(
            res[0].contains("\r\nconnection: close\r\n"),
            "{what}: {res:?}"
        );
    }
    let body = b"{\"username\":1}";
    let head = head("POST /api/v1/auth/login", "application/json", body.len());
    let res = send_late(
        addr,
        "read in full",
        &head,
        &[[body.as_slice(), next].concat()],
    )
    .await;
    assert_eq!(res.len(), 2, "{res:?}");
    assert!(res[0].starts_with("HTTP/1.1 400 "), "{res:?}");
    assert!(!res[0].contains("connection: close"), "{res:?}");
    assert!(res[1].starts_with("HTTP/1.1 200 "), "{res:?}");
}

/// With every drain permit held, an early answer goes out at once instead of waiting for the
/// body, and still closes the connection.
#[tokio::test]
async fn an_early_answer_without_a_drain_permit_answers_at_once() {
    let addr = start_console().await;
    let stalled = head("POST /api/v1/fleet/meta", "application/json", 2);
    let mut holders = Vec::new();
    for _ in 0..MAX_DRAINS {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(stalled.as_bytes()).await.unwrap();
        holders.push(s);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(stalled.as_bytes()).await.unwrap();
    let start = Instant::now();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    assert!(start.elapsed() < DRAIN_TIMEOUT / 2, "{:?}", start.elapsed());
    let res = responses(&raw);
    assert!(res[0].starts_with("HTTP/1.1 405 "), "{res:?}");
    assert!(res[0].contains("\r\nconnection: close\r\n"), "{res:?}");
    for mut s in holders {
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).await.unwrap();
        assert!(responses(&raw)[0].starts_with("HTTP/1.1 405 "));
    }
}

/// A client waiting for `100 Continue` gets the early answer at once, and no go-ahead.
#[tokio::test]
async fn an_early_answer_to_a_client_that_expects_100_continue_goes_out_at_once() {
    let mut s = TcpStream::connect(start_console().await).await.unwrap();
    let head = head("POST /api/v1/fleet/meta", "application/json", 2);
    let head = head.replace("\r\n\r\n", "\r\nExpect: 100-continue\r\n\r\n");
    s.write_all(head.as_bytes()).await.unwrap();
    let start = Instant::now();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    assert!(start.elapsed() < DRAIN_TIMEOUT / 2, "{:?}", start.elapsed());
    let res = responses(&raw);
    assert_eq!(res.len(), 1, "{res:?}");
    assert!(res[0].starts_with("HTTP/1.1 405 "), "{res:?}");
    assert!(res[0].contains("\r\nconnection: close\r\n"), "{res:?}");
}

#[tokio::test]
async fn accepted_connections_have_keepalive_nodelay_and_their_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, peer) = accept(&listener).await.unwrap();
    assert_eq!(peer, client.local_addr().unwrap());
    assert!(SockRef::from(&stream).keepalive().unwrap());
    assert!(stream.nodelay().unwrap());
}
