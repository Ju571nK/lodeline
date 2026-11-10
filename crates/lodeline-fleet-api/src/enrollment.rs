//! The enrollment file read by `lodeline-sender enroll`.
//!
//! It is JSON. A reader refuses any `lodeline_enrollment` other than
//! [`ENROLLMENT_FORMAT`], and warns about a field it does not know.

use serde::{Deserialize, Serialize};

/// Version this build reads and writes.
pub const ENROLLMENT_FORMAT: u32 = 1;

/// Largest enrollment file a reader accepts.
pub const MAX_ENROLLMENT_FILE_BYTES: u64 = 64 * 1024;

/// One host's enrollment file. It carries the token, so it is a secret until the
/// token is spent or expired. It never carries a private key.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct EnrollmentFile {
    /// Origin of the enrollment listener, e.g. `https://lodeline.example.com:8444`.
    pub enroll_url: String,
    /// When the token expires. A hint for messages; the server decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Lowercase hyphenated version 4 UUID the token is bound to.
    pub host_id: String,
    /// Format version, [`ENROLLMENT_FORMAT`].
    pub lodeline_enrollment: u32,
    /// Written as the agent's policy-signing keystore.
    pub policy_keystore: PolicyKeystore,
    /// PEM roots: the CA of the server's certificates and of the client chain.
    pub server_ca_pem: String,
    /// Origin of the main listener; becomes the sender's `server_base_url`.
    pub server_url: String,
    /// Single-use enrollment token from `lodeline-server enroll-token`.
    pub token: String,
}

impl std::fmt::Debug for EnrollmentFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentFile")
            .field("enroll_url", &self.enroll_url)
            .field("expires_at", &self.expires_at)
            .field("host_id", &self.host_id)
            .field("lodeline_enrollment", &self.lodeline_enrollment)
            .field("policy_keystore", &self.policy_keystore)
            .field("server_ca_pem", &self.server_ca_pem)
            .field("server_url", &self.server_url)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// The keystore document, with the JSON shape of
/// `lodeline_core::policy::pubkeys::Keystore`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PolicyKeystore {
    pub pubkeys: Vec<PolicyKey>,
}

/// One signing key and its validity window (RFC 3339).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PolicyKey {
    pub ed25519_pubkey_b64: String,
    pub id: String,
    pub valid_from: String,
    pub valid_until: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_the_token() {
        let f: EnrollmentFile = serde_json::from_str(
            r#"{"enroll_url":"u","host_id":"h","lodeline_enrollment":1,
                "policy_keystore":{"pubkeys":[]},"server_ca_pem":"p","server_url":"s",
                "token":"secret-token-value"}"#,
        )
        .unwrap();
        let shown = format!("{f:?} {f:#?}");
        assert!(!shown.contains("secret-token-value"), "{shown}");
        assert!(shown.contains("<redacted>"));
    }

    #[test]
    fn round_trips_and_ignores_unknown_fields() {
        let f = EnrollmentFile {
            enroll_url: "https://lodeline.example.com:8444".into(),
            expires_at: None,
            host_id: "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f".into(),
            lodeline_enrollment: ENROLLMENT_FORMAT,
            policy_keystore: PolicyKeystore {
                pubkeys: vec![PolicyKey {
                    ed25519_pubkey_b64: "k".into(),
                    id: "prod-key-1".into(),
                    valid_from: "2026-01-01T00:00:00Z".into(),
                    valid_until: "2027-01-01T00:00:00Z".into(),
                }],
            },
            server_ca_pem: "pem".into(),
            server_url: "https://lodeline.example.com:8443".into(),
            token: "t".into(),
        };
        let mut v = serde_json::to_value(&f).unwrap();
        assert!(v.get("expires_at").is_none(), "an unset hint is omitted");
        v["later_field"] = true.into();
        assert_eq!(serde_json::from_value::<EnrollmentFile>(v).unwrap(), f);
    }
}
