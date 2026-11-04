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
