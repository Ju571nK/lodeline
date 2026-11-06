//! What one call ended as. Every reply is checked against the call's own id and
//! marker, so a wrong, cached or empty answer is an error, never a success.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    /// A non-200 HTTP answer. `code` is the proxy's `{"error": "<code>"}` body
    /// when there is one (`too_many_requests`, `audit_unavailable`, ...).
    Http {
        status: u16,
        code: Option<String>,
    },
    /// HTTP 200 carrying a JSON-RPC error.
    JsonRpcError(i64),
    /// HTTP 200 whose result is not the echo of this call's marker and id.
    BadReply,
    Timeout,
    Transport,
}

impl Outcome {
    /// The key of this outcome in a report's error breakdown.
    pub fn key(&self) -> String {
        match self {
            Outcome::Ok => "ok".into(),
            Outcome::Http {
                status,
                code: Some(c),
            } => format!("http_{status}_{c}"),
            Outcome::Http { status, code: None } => format!("http_{status}"),
            Outcome::JsonRpcError(c) => format!("jsonrpc_error_{c}"),
            Outcome::BadReply => "bad_reply".into(),
            Outcome::Timeout => "timeout".into(),
            Outcome::Transport => "transport".into(),
        }
    }

    pub fn from_reqwest(e: &reqwest::Error) -> Outcome {
        if e.is_timeout() {
            Outcome::Timeout
        } else {
            Outcome::Transport
        }
    }
}

/// The text the load server answers a `load_echo` call with.
pub fn echo_text(marker: &str) -> String {
    format!("echo:{marker}")
}

/// Classify one complete HTTP answer to the `tools/call` with `id` and `marker`.
pub fn classify(status: u16, body: &[u8], id: u64, marker: &str) -> Outcome {
    let v: Option<Value> = serde_json::from_slice(body).ok();
    if status != 200 {
        let code = v
            .as_ref()
            .and_then(|v| v.get("error"))
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
            .map(str::to_string);
        return Outcome::Http { status, code };
    }
    let Some(v) = v else {
        return Outcome::BadReply;
    };
    if v.get("id").and_then(Value::as_u64) != Some(id) {
        return Outcome::BadReply;
    }
    if let Some(e) = v.get("error") {
        return Outcome::JsonRpcError(e.get("code").and_then(Value::as_i64).unwrap_or(0));
    }
    let text = v.pointer("/result/content/0/text").and_then(Value::as_str);
    if text == Some(echo_text(marker).as_str()) {
        Outcome::Ok
    } else {
        Outcome::BadReply
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_body(id: u64, text: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"jsonrpc": "2.0", "id": id,
            "result": {"content": [{"type": "text", "text": text}, {"type": "text", "text": "pad"}]}}))
        .unwrap()
    }

    #[test]
    fn only_the_echo_of_this_call_is_ok() {
        assert_eq!(classify(200, &ok_body(7, "echo:m7"), 7, "m7"), Outcome::Ok);
        assert_eq!(
            classify(200, &ok_body(7, "echo:m6"), 7, "m7"),
            Outcome::BadReply
        );
        assert_eq!(
            classify(200, &ok_body(6, "echo:m7"), 7, "m7"),
            Outcome::BadReply
        );
        assert_eq!(classify(200, b"", 7, "m7"), Outcome::BadReply);
        assert_eq!(
            classify(
                200,
                b"{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}",
                7,
                "m7"
            ),
            Outcome::BadReply
        );
    }

    #[test]
    fn a_jsonrpc_error_is_its_own_class() {
        let b = br#"{"jsonrpc":"2.0","id":3,"error":{"code":-32603,"message":"Internal error"}}"#;
        let o = classify(200, b, 3, "m");
        assert_eq!(o, Outcome::JsonRpcError(-32603));
        assert_eq!(o.key(), "jsonrpc_error_-32603");
    }

    #[test]
    fn proxy_refusals_keep_their_code() {
        let k = |s, b: &[u8]| classify(s, b, 1, "m").key();
        assert_eq!(
            k(429, br#"{"error":"too_many_requests"}"#),
            "http_429_too_many_requests"
        );
        assert_eq!(
            k(503, br#"{"error":"audit_unavailable"}"#),
            "http_503_audit_unavailable"
        );
        assert_eq!(
            k(401, br#"{"error":"unauthorized"}"#),
            "http_401_unauthorized"
        );
        assert_eq!(k(400, b""), "http_400");
        assert_eq!(k(502, b"<html>bad gateway</html>"), "http_502");
        // A code that is not a plain identifier is not copied into the key.
        assert_eq!(k(500, br#"{"error":"a b/../c"}"#), "http_500");
    }

    #[test]
    fn transport_classes_have_stable_keys() {
        assert_eq!(Outcome::Timeout.key(), "timeout");
        assert_eq!(Outcome::Transport.key(), "transport");
        assert_eq!(Outcome::Ok.key(), "ok");
    }
}
