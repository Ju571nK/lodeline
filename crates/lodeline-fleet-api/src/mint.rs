//! `POST /v1/enroll-tokens` on the main listener: a console with a management
//! credential asks the server to make one single-use enrollment token.
//!
//! The server and the console compile this one definition. The request refuses
//! unknown fields, because it changes state and a field the server does not know
//! would otherwise be dropped without a word. The response accepts them, like
//! every other type of the crate.

use serde::{Deserialize, Serialize};

/// Path of the mint route on the main (mutual TLS) listener.
pub const MINT_PATH: &str = "/v1/enroll-tokens";

/// Header with the name of the person behind the call, as the caller says it.
/// The server records it as asserted and never uses it to decide anything.
pub const REQUESTED_BY_HEADER: &str = "x-lodeline-requested-by";

/// The request body.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MintRequest {
    /// Lowercase hyphenated version 4 UUID the token is bound to.
    pub host_id: String,
}

/// The 201 answer. The token is shown once and is not stored in plain text.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct MintResponse {
    /// When the token expires, RFC 3339, the server's clock.
    pub expires_at: String,
    pub host_id: String,
    pub token: String,
}

impl std::fmt::Debug for MintResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintResponse")
            .field("expires_at", &self.expires_at)
            .field("host_id", &self.host_id)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_refuses_unknown_fields_and_response_ignores_them() {
        assert!(serde_json::from_str::<MintRequest>(r#"{"host_id":"h","ttl":5}"#).is_err());
        assert!(serde_json::from_str::<MintRequest>("{}").is_err());
        let r: MintResponse =
            serde_json::from_str(r#"{"expires_at":"e","host_id":"h","token":"t","later":1}"#)
                .unwrap();
        assert_eq!(r.token, "t");
    }

    #[test]
    fn debug_hides_the_token() {
        let r = MintResponse {
            expires_at: "e".into(),
            host_id: "h".into(),
            token: "secret-token-value".into(),
        };
        let shown = format!("{r:?} {r:#?}");
        assert!(!shown.contains("secret-token-value"), "{shown}");
        assert!(shown.contains("<redacted>"));
    }
}
