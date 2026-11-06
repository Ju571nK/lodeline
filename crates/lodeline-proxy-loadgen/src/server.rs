//! Synthetic upstream MCP server (Streamable HTTP, revision 2025-11-25, JSON
//! answers only). One tool, `load_echo`, answers `echo:<marker>` and pads the
//! reply to the `reply_bytes` the call asks for. It does no I/O per call, so the
//! direct side measures the driver, the loopback and this server only.
//!
//! `GET /_load/counters` reports how many calls it answered, so a run can check
//! that every successful reply was one upstream call and nothing was retried.

use std::convert::Infallible;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use crate::outcome::echo_text;

pub const TOOL: &str = "load_echo";
pub const PROTOCOL: &str = "2025-11-25";
/// Largest request body accepted (the proxy's own limit is 1 MiB).
const MAX_BODY: usize = 2 << 20;
/// Largest reply a call may ask for (the proxy's JSON response limit is 8 MiB).
pub const MAX_REPLY: usize = 16 << 20;

#[derive(Default)]
pub struct Counters {
    pub posts: AtomicU64,
    pub initialize: AtomicU64,
    pub tools_calls: AtomicU64,
    pub deletes: AtomicU64,
}

impl Counters {
    fn json(&self) -> Value {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        json!({"posts": g(&self.posts), "initialize": g(&self.initialize),
               "tools_calls": g(&self.tools_calls), "deletes": g(&self.deletes)})
    }
}

/// Serve until `shutdown` resolves. Connections still open then are dropped.
pub async fn serve(
    listener: TcpListener,
    counters: Arc<Counters>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    tokio::pin!(shutdown);
    loop {
        let (sock, _) = tokio::select! {
            _ = &mut shutdown => return Ok(()),
            a = listener.accept() => a?,
        };
        let _ = sock.set_nodelay(true);
        let c = counters.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| handle(req, c.clone()));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(sock), svc)
                .await;
        });
    }
}

fn reply(status: StatusCode, content_type: Option<&str>, body: Bytes) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(body));
    *r.status_mut() = status;
    if let Some(ct) = content_type {
        r.headers_mut()
            .insert(hyper::header::CONTENT_TYPE, ct.parse().expect("static"));
    }
    r
}

fn empty(status: StatusCode) -> Response<Full<Bytes>> {
    reply(status, None, Bytes::new())
}

fn rpc(id: &Value, result: Value) -> Bytes {
    Bytes::from(
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "result": result})).expect("json"),
    )
}

/// The `load_echo` answer, padded so the whole body is at least `reply_bytes`.
pub fn echo_reply(id: &Value, marker: &str, reply_bytes: usize) -> Bytes {
    let body = |pad: &str| {
        rpc(
            id,
            json!({"content": [{"type": "text", "text": echo_text(marker)},
                               {"type": "text", "text": pad}]}),
        )
    };
    let base = body("").len();
    if reply_bytes <= base {
        return body("");
    }
    body(&"x".repeat(reply_bytes - base))
}

async fn handle(
    req: Request<Incoming>,
    c: Arc<Counters>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    if parts.method == Method::GET && parts.uri.path() == "/_load/counters" {
        let b = Bytes::from(c.json().to_string());
        return Ok(reply(StatusCode::OK, Some("application/json"), b));
    }
    if parts.method == Method::DELETE {
        c.deletes.fetch_add(1, Ordering::Relaxed);
        return Ok(empty(StatusCode::NO_CONTENT));
    }
    if parts.method != Method::POST {
        return Ok(empty(StatusCode::METHOD_NOT_ALLOWED));
    }
    c.posts.fetch_add(1, Ordering::Relaxed);
    let Ok(collected) = Limited::new(body, MAX_BODY).collect().await else {
        return Ok(empty(StatusCode::PAYLOAD_TOO_LARGE));
    };
    let Ok(msg) = serde_json::from_slice::<Value>(&collected.to_bytes()) else {
        return Ok(empty(StatusCode::BAD_REQUEST));
    };
    let Some(id) = msg.get("id") else {
        // A notification (`notifications/initialized`) or a client response.
        return Ok(empty(StatusCode::ACCEPTED));
    };
    let json_ct = Some("application/json");
    let body = match msg.get("method").and_then(Value::as_str) {
        Some("initialize") => {
            let n = c.initialize.fetch_add(1, Ordering::Relaxed);
            let b = rpc(
                id,
                json!({"protocolVersion": PROTOCOL, "capabilities": {"tools": {"listChanged": false}},
                       "serverInfo": {"name": "lodeline-proxy-loadgen", "version": env!("CARGO_PKG_VERSION")}}),
            );
            let mut r = reply(StatusCode::OK, json_ct, b);
            r.headers_mut().insert(
                "mcp-session-id",
                format!("load-{n}").parse().expect("ascii"),
            );
            return Ok(r);
        }
        Some("ping") => rpc(id, json!({})),
        Some("tools/list") => rpc(
            id,
            json!({"tools": [{"name": TOOL, "description": "Synthetic echo for load tests",
                              "inputSchema": {"type": "object"}}]}),
        ),
        Some("tools/call") if msg.pointer("/params/name").and_then(Value::as_str) == Some(TOOL) => {
            c.tools_calls.fetch_add(1, Ordering::Relaxed);
            let args = msg.pointer("/params/arguments");
            let marker = args
                .and_then(|a| a.get("marker"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let size = args
                .and_then(|a| a.get("reply_bytes"))
                .and_then(Value::as_u64)
                .map_or(0, |n| n.min(MAX_REPLY as u64) as usize);
            echo_reply(id, marker, size)
        }
        _ => Bytes::from(
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": "Method not found"}}))
            .expect("json"),
        ),
    };
    Ok(reply(StatusCode::OK, json_ct, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reply_is_padded_to_the_asked_size() {
        let id = json!(42);
        let small = echo_reply(&id, "m", 0);
        assert!(small.len() < 200);
        let b = echo_reply(&id, "m-1", 4096);
        assert_eq!(b.len(), 4096);
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["result"]["content"][0]["text"], "echo:m-1");
        assert_eq!(v["id"], 42);
    }
}
