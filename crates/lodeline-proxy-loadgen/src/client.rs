//! One MCP session per lane, the way a client uses the proxy: `initialize`,
//! `notifications/initialized` and a `tools/list` once, then `tools/call` on
//! that session. Calls of one lane run in parallel on pooled connections.

use std::time::Duration;

use anyhow::{bail, Context};
use serde_json::{json, Value};

use crate::outcome::{classify, Outcome};
use crate::server::{PROTOCOL, TOOL};

/// One endpoint and the bearer it is called with (a principal's token on the
/// proxy; none is needed by the load server).
#[derive(Debug, Clone)]
pub struct Target {
    pub url: String,
    pub token: Option<String>,
}

pub struct Lane {
    http: reqwest::Client,
    target: Target,
    session: Option<String>,
    /// Makes each `tools/call` request body this many bytes.
    request_bytes: usize,
    reply_bytes: usize,
}

pub fn http_client(timeout: Duration) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .no_proxy()
        .tcp_nodelay(true)
        .build()
}

impl Lane {
    fn post(&self, body: String) -> reqwest::RequestBuilder {
        let mut r = self
            .http
            .post(&self.target.url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(body);
        if let Some(t) = &self.target.token {
            r = r.bearer_auth(t);
        }
        if let Some(s) = &self.session {
            r = r
                .header("mcp-session-id", s)
                .header("mcp-protocol-version", PROTOCOL);
        }
        r
    }

    /// Open a session on `target` and check that it lists the load tool.
    pub async fn open(
        http: reqwest::Client,
        target: Target,
        request_bytes: usize,
        reply_bytes: usize,
    ) -> anyhow::Result<Lane> {
        let mut lane = Lane {
            http,
            target,
            session: None,
            request_bytes,
            reply_bytes,
        };
        let init = json!({"jsonrpc": "2.0", "id": "init", "method": "initialize",
            "params": {"protocolVersion": PROTOCOL, "capabilities": {},
                       "clientInfo": {"name": "lodeline-proxy-loadgen", "version": env!("CARGO_PKG_VERSION")}}});
        let r = lane
            .post(init.to_string())
            .send()
            .await
            .context("initialize")?;
        let status = r.status();
        lane.session = r
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = r.text().await.context("initialize body")?;
        if status != 200 || lane.session.is_none() {
            bail!(
                "initialize on {} answered {status} without a session: {body:.200}",
                lane.target.url
            );
        }
        let n = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let st = lane
            .post(n.to_string())
            .send()
            .await
            .context("initialized")?
            .status();
        if st != 202 {
            bail!("notifications/initialized answered {st}");
        }
        let list = json!({"jsonrpc": "2.0", "id": "list", "method": "tools/list"});
        let r = lane
            .post(list.to_string())
            .send()
            .await
            .context("tools/list")?;
        let (st, body) = (r.status(), r.text().await.context("tools/list body")?);
        let listed = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| v.pointer("/result/tools").cloned())
            .and_then(|t| t.as_array().cloned())
            .is_some_and(|t| t.iter().any(|t| t["name"] == TOOL));
        if st != 200 || !listed {
            bail!("tools/list answered {st} without {TOOL}: {body:.200}");
        }
        Ok(lane)
    }

    /// The `tools/call` body for call `seq`, padded to `request_bytes`.
    pub fn call_body(&self, seq: u64, marker: &str) -> String {
        let body = |pad: &str| {
            format!(
                r#"{{"jsonrpc":"2.0","id":{seq},"method":"tools/call","params":{{"name":"{TOOL}","arguments":{{"marker":"{marker}","reply_bytes":{},"pad":"{pad}"}}}}}}"#,
                self.reply_bytes
            )
        };
        let base = body("").len();
        body(&"x".repeat(self.request_bytes.saturating_sub(base)))
    }

    pub async fn call(&self, seq: u64, marker: &str) -> Outcome {
        let r = match self.post(self.call_body(seq, marker)).send().await {
            Ok(r) => r,
            Err(e) => return Outcome::from_reqwest(&e),
        };
        let status = r.status().as_u16();
        match r.bytes().await {
            Ok(b) => classify(status, &b, seq, marker),
            Err(e) => Outcome::from_reqwest(&e),
        }
    }

    /// End the session (best effort).
    pub async fn close(&self) {
        let mut r = self.http.delete(&self.target.url);
        if let Some(t) = &self.target.token {
            r = r.bearer_auth(t);
        }
        if let Some(s) = &self.session {
            r = r.header("mcp-session-id", s);
        }
        let _ = r.send().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_call_body_has_the_asked_size_and_parses() {
        let lane = Lane {
            http: reqwest::Client::new(),
            target: Target {
                url: "http://127.0.0.1:1/mcp".into(),
                token: None,
            },
            session: None,
            request_bytes: 1024,
            reply_bytes: 4096,
        };
        let b = lane.call_body(17, "d1-17");
        assert_eq!(b.len(), 1024);
        let v: Value = serde_json::from_str(&b).unwrap();
        assert_eq!(v["id"], 17);
        assert_eq!(v["params"]["arguments"]["marker"], "d1-17");
        assert_eq!(v["params"]["arguments"]["reply_bytes"], 4096);
    }
}
