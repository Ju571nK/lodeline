#![cfg(unix)]
//! D-04 limits (PX-013, AC-07): sizes, timeouts and concurrency with queue
//! depth 0. Limits are lowered through the public `Limits` fields; the config
//! loader only permits lowering (see limits.rs tests).

mod common;
use bytes::Bytes;
use common::*;
use sigil_proxy::lifecycle::DrainOutcome;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

fn lim(f: impl FnOnce(&mut sigil_proxy::limits::Limits)) -> sigil_proxy::limits::Limits {
    let mut l = limits();
    f(&mut l);
    l
}

/// PX-013: request body over the limit is 413 before any upstream contact, by
/// Content-Length and by chunked framing; a body exactly at the limit relays.
#[tokio::test]
async fn request_body_limit() {
    let up = ok_upstream().await;
    let px = simple(&up, lim(|l| l.max_request_body_bytes = 1024)).await;

    let r = px
        .post("/mcp/a", Some("tok-a"), &[], &vec![b'x'; 1025])
        .await;
    assert_eq!(r.status, 413);
    assert_eq!(r.text(), "{\"error\":\"request_too_large\"}");

    let mut raw = format!(
        "POST /mcp/a HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAuthorization: Bearer tok-a\r\nTransfer-Encoding: chunked\r\n\r\n",
        px.addr
    )
    .into_bytes();
    for _ in 0..3 {
        raw.extend_from_slice(b"200\r\n");
        raw.extend_from_slice(&vec![b'x'; 512]);
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    assert_eq!(px.send(&raw).await.status, 413, "chunked over the limit");
    assert_eq!(up.conns(), 0, "upstream untouched");

    let body = vec![b'y'; 1024];
    assert_eq!(
        px.post("/mcp/a", Some("tok-a"), &[], &body).await.status,
        200
    );
    assert_eq!(up.last().body, body);
}

/// PX-013: header block over the limit is 431 and never reaches upstream.
#[tokio::test]
async fn header_size_limit() {
    let up = ok_upstream().await;
    let px = simple(&up, limits()).await; // 32 KiB
    let big = "a".repeat(40 * 1024);
    let r = px
        .post("/mcp/a", Some("tok-a"), &[("X-Big", &big)], b"{}")
        .await;
    assert_eq!(r.status, 431, "{r:?}");
    assert_eq!(up.conns(), 0);
    // just under the limit still works
    let ok = "a".repeat(20 * 1024);
    assert_eq!(
        px.post("/mcp/a", Some("tok-a"), &[("X-Big", &ok)], b"{}")
            .await
            .status,
        200
    );
}

/// PX-013: a declared Content-Length over the JSON limit is refused while the
/// status can still be replaced (fixed 502), and a body that outgrows the limit
/// while streaming is cut (truncated, never completed).
#[tokio::test]
async fn json_response_limit() {
    let up = Up::start(|_| full(200, "application/json", &vec![b'j'; 2000])).await;
    let px = simple(&up, lim(|l| l.max_json_response_bytes = 1000)).await;
    let r = px.post("/mcp/a", Some("tok-a"), &[], b"{}").await;
    assert_eq!(r.status, 502);
    assert_eq!(r.text(), "{\"error\":\"upstream_response_too_large\"}");

    // chunked (no declared length): 3 x 600 bytes with a 1000 byte limit
    let (tx, reply) = {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        (
            tx,
            Reply::Stream {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                rx,
            },
        )
    };
    let slot = Mutex::new(Some(reply));
    let up = Up::start(move |_| slot.lock().unwrap().take().unwrap()).await;
    let px = simple(&up, lim(|l| l.max_json_response_bytes = 1000)).await;
    let t = tokio::spawn(async move {
        for _ in 0..3 {
            if tx.send(Bytes::from(vec![b'j'; 600])).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    let r = px.post("/mcp/a", Some("tok-a"), &[], b"{}").await;
    t.await.unwrap();
    assert_eq!(r.status, 200);
    let (chunks, complete) = r.chunks();
    assert!(!complete, "stream must be aborted, not completed");
    assert!(chunks.concat().len() <= 1000 + 600);
    assert!(chunks.concat().len() < 1800);
}

/// PX-013: one SSE event over the event limit ends the stream; many events
/// under it, in total larger than the limit, do not.
#[tokio::test]
async fn sse_event_limit() {
    let (tx, reply) = sse_stream();
    let slot = Mutex::new(Some(reply));
    let up = Up::start(move |_| slot.lock().unwrap().take().unwrap()).await;
    let px = simple(&up, lim(|l| l.max_sse_event_bytes = 100)).await;
    let t = tokio::spawn(async move {
        // 10 events of 60 bytes (600 total > 100), each well under the limit
        for _ in 0..10 {
            let ev = format!("data: {}\n\n", "e".repeat(51));
            tx.send(Bytes::from(ev)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // one 200 byte event with no blank line until the end
        let _ = tx
            .send(Bytes::from(format!("data: {}\n\n", "E".repeat(200))))
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = tx.send(Bytes::from_static(b"data: after\n\n")).await;
    });
    let r = px.post("/mcp/a", Some("tok-a"), &[], b"{}").await;
    t.await.unwrap();
    assert_eq!(r.status, 200);
    let (chunks, complete) = r.chunks();
    assert!(!complete);
    let text = String::from_utf8_lossy(&chunks.concat()).into_owned();
    assert_eq!(
        text.matches("data: eee").count(),
        10,
        "small events all arrived"
    );
    assert!(!text.contains('E'), "the oversized event is not forwarded");
    assert!(!text.contains("after"));
}

/// PX-013: accumulated response bytes per call.
#[tokio::test]
async fn call_total_limit() {
    let (tx, reply) = sse_stream();
    let slot = Mutex::new(Some(reply));
    let up = Up::start(move |_| slot.lock().unwrap().take().unwrap()).await;
    let px = simple(&up, lim(|l| l.max_call_response_bytes = 500)).await;
    let t = tokio::spawn(async move {
        for _ in 0..20 {
            if tx
                .send(Bytes::from(format!("data: {}\n\n", "c".repeat(50))))
                .await
                .is_err()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    let r = px.post("/mcp/a", Some("tok-a"), &[], b"{}").await;
    t.abort();
    let (chunks, complete) = r.chunks();
    assert!(!complete);
    assert!(chunks.concat().len() <= 500);
}

/// PX-013: no response headers within the response-idle window is a fixed 504.
#[tokio::test]
async fn first_byte_timeout_is_504() {
    let up = Up::start(|_| Reply::Hang).await;
    let px = simple(&up, lim(|l| l.response_idle_timeout_secs = 1)).await;
    let t = Instant::now();
    let r = px.post("/mcp/a", Some("tok-a"), &[], b"{}").await;
    assert_eq!(r.status, 504);
    assert_eq!(r.text(), "{\"error\":\"upstream_timeout\"}");
    assert!(t.elapsed() < Duration::from_secs(5));
    assert_eq!(up.count(), 1, "sent once, never retried");
}

/// PX-013: a stream that stalls longer than the idle limit is cut; the events
/// delivered before the stall are kept.
#[tokio::test]
async fn idle_timeout_cuts_a_stalled_stream() {
    let (tx, reply) = sse_stream();
    let slot = Mutex::new(Some(reply));
    let up = Up::start(move |_| slot.lock().unwrap().take().unwrap()).await;
    let px = simple(&up, lim(|l| l.response_idle_timeout_secs = 1)).await;
    tx.send(Bytes::from_static(b"data: first\n\n"))
        .await
        .unwrap();
    let t = Instant::now();
    let r = px.post("/mcp/a", Some("tok-a"), &[], b"{}").await; // tx stays open: stall
    assert!(t.elapsed() < Duration::from_secs(6));
    let (chunks, complete) = r.chunks();
    assert!(!complete);
    assert_eq!(chunks.concat(), b"data: first\n\n");
    drop(tx);
}

/// PX-013: the whole-call limit ends a stream that never goes idle.
#[tokio::test]
async fn call_timeout_cuts_a_trickling_stream() {
    let (tx, reply) = sse_stream();
    let slot = Mutex::new(Some(reply));
    let up = Up::start(move |_| slot.lock().unwrap().take().unwrap()).await;
    let px = simple(&up, lim(|l| l.call_timeout_secs = 1)).await;
    let t = tokio::spawn(async move {
        loop {
            if tx.send(Bytes::from_static(b": ping\n\n")).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let start = Instant::now();
    let r = px.post("/mcp/a", Some("tok-a"), &[], b"{}").await;
    let took = start.elapsed();
    t.abort();
    assert!(!r.chunks().1, "stream cut, not completed");
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_secs(6),
        "{took:?}"
    );
}

/// Hold a call open until the returned sender is dropped. Waits until the
/// proxy has accepted it (upstream saw the request).
async fn hold(px: &Px, up: &Up, path: &str, token: &str) -> (tokio::task::JoinHandle<Raw>, usize) {
    let before = up.count();
    let req = px.request("POST", path, Some(token), &[], b"{}");
    let addr = px.addr;
    let h = tokio::spawn(async move { send_raw(addr, &req).await });
    let end = Instant::now() + Duration::from_secs(5);
    while up.count() == before && Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(up.count() > before, "held call never reached upstream");
    (h, before)
}

/// A gated upstream: every request becomes an open SSE stream whose sender the
/// test keeps.
async fn gated_upstream() -> (
    Up,
    std::sync::Arc<Mutex<Vec<tokio::sync::mpsc::Sender<Bytes>>>>,
) {
    let senders = std::sync::Arc::new(Mutex::new(Vec::new()));
    let s2 = senders.clone();
    let up = Up::start(move |_| {
        let (tx, reply) = sse_stream();
        s2.lock().unwrap().push(tx);
        reply
    })
    .await;
    (up, senders)
}

/// PX-013: route concurrency with queue depth 0. The second call is an
/// immediate 429 (upstream untouched); finishing the first frees the slot.
#[tokio::test]
async fn route_concurrency_limit() {
    let (up, senders) = gated_upstream().await;
    let l = lim(|l| l.max_calls_per_route = 1);
    let px = simple(&up, l).await;
    let (h, _) = hold(&px, &up, "/mcp/a", "tok-a").await;
    let t = Instant::now();
    let r = px.post("/mcp/a", Some("tok-a"), &[], b"{}").await;
    assert_eq!(r.status, 429);
    assert_eq!(r.text(), "{\"error\":\"too_many_requests\"}");
    assert!(t.elapsed() < Duration::from_secs(1), "no queueing");
    assert_eq!(up.count(), 1);
    senders.lock().unwrap().clear(); // ends the first stream
    h.await.unwrap();
    let (h2, _) = hold(&px, &up, "/mcp/a", "tok-a").await;
    assert_eq!(up.count(), 2, "slot was released");
    senders.lock().unwrap().clear();
    h2.await.unwrap();
}

/// PX-013: principal concurrency is shared across routes; another principal is
/// unaffected.
#[tokio::test]
async fn principal_concurrency_limit() {
    let (up, senders) = gated_upstream().await;
    let l = lim(|l| l.max_calls_per_principal = 1);
    let t = table(
        &[
            R::new("a", up.url("/up"), &[("p1", "tok-1"), ("p2", "tok-2")]),
            R::new("b", up.url("/up"), &[("p1", "tok-1b")]),
        ],
        &l,
    );
    let px = Px::start(Some(t), l).await;
    let (h, _) = hold(&px, &up, "/mcp/a", "tok-1").await;
    // same principal, other route (same principal id) -> 429
    assert_eq!(
        px.post("/mcp/b", Some("tok-1b"), &[], b"{}").await.status,
        429
    );
    // same principal, same route -> 429
    assert_eq!(
        px.post("/mcp/a", Some("tok-1"), &[], b"{}").await.status,
        429
    );
    // another principal still gets in
    let (h2, _) = hold(&px, &up, "/mcp/a", "tok-2").await;
    senders.lock().unwrap().clear();
    h.await.unwrap();
    h2.await.unwrap();
}

/// PX-013: the process-wide limit spans routes.
#[tokio::test]
async fn total_concurrency_limit() {
    let (up, senders) = gated_upstream().await;
    let l = lim(|l| l.max_concurrent_calls = 1);
    let t = table(
        &[
            R::new("a", up.url("/up"), &[("pa", "tok-a")]),
            R::new("b", up.url("/up"), &[("pb", "tok-b")]),
        ],
        &l,
    );
    let px = Px::start(Some(t), l).await;
    let (h, _) = hold(&px, &up, "/mcp/a", "tok-a").await;
    assert_eq!(
        px.post("/mcp/b", Some("tok-b"), &[], b"{}").await.status,
        429
    );
    senders.lock().unwrap().clear();
    h.await.unwrap();
}

/// PX-013: shutdown drains an in-flight call within the grace; when the grace
/// elapses first the outcome is `GraceExpired` (remaining calls are unknown).
#[tokio::test]
async fn shutdown_respects_grace() {
    let (up, senders) = gated_upstream().await;
    let mut px = simple(&up, lim(|l| l.shutdown_grace_secs = 1)).await;
    let (h, _) = hold(&px, &up, "/mcp/a", "tok-a").await;
    let t = Instant::now();
    assert_eq!(px.stop().await, DrainOutcome::GraceExpired);
    assert!(t.elapsed() >= Duration::from_millis(900));
    drop(senders);
    h.abort();

    // and an in-flight call that finishes inside the grace is Drained
    let (up, senders) = gated_upstream().await;
    let mut px = simple(&up, lim(|l| l.shutdown_grace_secs = 5)).await;
    let (h, _) = hold(&px, &up, "/mcp/a", "tok-a").await;
    let s2 = senders.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        s2.lock().unwrap().clear();
    });
    assert_eq!(px.stop().await, DrainOutcome::Drained);
    h.await.unwrap();
}

/// New connections are refused after shutdown begins.
#[tokio::test]
async fn no_accept_after_shutdown() {
    let up = ok_upstream().await;
    let mut px = simple(&up, limits()).await;
    let addr = px.addr;
    px.stop().await;
    let r = tokio::time::timeout(Duration::from_secs(2), async {
        match TcpStream::connect(addr).await {
            Err(_) => true,
            Ok(mut s) => {
                s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.is_err() || {
                    use tokio::io::AsyncReadExt;
                    let mut b = [0u8; 16];
                    matches!(s.read(&mut b).await, Ok(0) | Err(_))
                }
            }
        }
    })
    .await;
    assert_eq!(r, Ok(true));
}
