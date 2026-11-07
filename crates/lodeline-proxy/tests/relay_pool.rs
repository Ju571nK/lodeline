#![cfg(unix)]
//! Upstream connection reuse: calls of a route reuse its idle upstream
//! connections, a connection whose response was not read to the end is not
//! reused, and a new route table does not keep the old upstream.

mod common;

use bytes::Bytes;
use common::*;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const PING: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;

fn ping(id: u32) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#).into_bytes()
}

/// Answers each call with a result for the call's own id.
fn answer(s: &Seen) -> Reply {
    let v: serde_json::Value = serde_json::from_slice(&s.body).unwrap();
    let body = format!(r#"{{"jsonrpc":"2.0","id":{},"result":{{}}}}"#, v["id"]);
    full(200, "application/json", body.as_bytes())
}

/// Sequential calls of two principals on one route open far fewer upstream
/// connections than calls, and every call gets the answer to its own id.
#[tokio::test]
async fn sequential_calls_reuse_upstream_connections() {
    let up = Up::start(answer).await;
    let l = limits();
    let t = table(
        &[R::new(
            "a",
            up.url("/up"),
            &[("pa", "tok-a"), ("pb", "tok-b")],
        )],
        &l,
    );
    let px = Px::start(Some(t), l).await;
    for i in 1..=40 {
        let tok = if i % 2 == 0 { "tok-a" } else { "tok-b" };
        let r = px.post("/mcp/a", Some(tok), &[], &ping(i)).await;
        assert_eq!(r.status, 200, "call {i}");
        assert_eq!(
            r.body(),
            format!(r#"{{"jsonrpc":"2.0","id":{i},"result":{{}}}}"#).as_bytes(),
            "call {i} got its own answer"
        );
    }
    assert_eq!(up.count(), 40);
    assert!(
        up.conns() <= 4,
        "2 initializes and 40 calls opened {} upstream connections",
        up.conns()
    );
}

/// The client stops reading an event stream: the proxy closes that upstream
/// connection, and the next call gets its own complete answer.
#[tokio::test]
async fn unfinished_response_is_not_reused() {
    let (tx, reply) = sse_stream();
    let slot = std::sync::Mutex::new(Some(reply));
    let up = Up::start(move |s| slot.lock().unwrap().take().unwrap_or_else(|| answer(s))).await;
    let px = simple(&up, limits()).await;
    let req = px.request(
        "POST",
        "/mcp/a",
        Some("tok-a"),
        &[
            ("Accept", "application/json, text/event-stream"),
            (
                "Mcp-Session-Id",
                &px.session("/mcp/a", "tok-a").await.unwrap(),
            ),
            ("MCP-Protocol-Version", "2025-11-25"),
        ],
        PING,
    );
    let mut s = TcpStream::connect(px.addr).await.unwrap();
    s.write_all(&req).await.unwrap();
    tx.send(Bytes::from_static(
        b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n",
    ))
    .await
    .unwrap();
    let mut buf = Vec::new();
    assert!(
        read_until(
            &mut s,
            &mut buf,
            b"notifications/progress",
            Duration::from_secs(5)
        )
        .await
    );
    drop(s);

    // The upstream body ends only when the proxy drops that upstream connection.
    let mut closed = false;
    for _ in 0..100 {
        if tx.send(Bytes::from_static(b": keep\n\n")).await.is_err() {
            closed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(closed, "the upstream stream stayed open");

    let r = px.post("/mcp/a", Some("tok-a"), &[], &ping(2)).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body(), br#"{"jsonrpc":"2.0","id":2,"result":{}}"#);
}

/// A config apply that moves the route to another upstream sends later calls
/// there, never over a connection to the old one.
#[tokio::test]
async fn new_table_uses_the_new_upstream() {
    let (old, new) = (ok_upstream().await, ok_upstream().await);
    let l = limits();
    let route = |up: &Up| table(&[R::new("a", up.url("/up"), &[("pa", "tok-a")])], &l);
    let px = Px::start(Some(route(&old)), l.clone()).await;
    assert_eq!(
        px.post("/mcp/a", Some("tok-a"), &[], PING).await.status,
        200
    );

    px.handle.set(Some(route(&new)));
    px.forget_sessions();
    for _ in 0..3 {
        assert_eq!(
            px.post("/mcp/a", Some("tok-a"), &[], PING).await.status,
            200
        );
    }
    assert_eq!(old.count(), 1);
    assert_eq!(new.count(), 3);
}
