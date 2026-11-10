//! `POST /v1/renew` on the main listener: a host that holds a client certificate
//! asks for a new one for the same host id.
//!
//! The host id is the presented certificate's CN. The body carries only the CSR,
//! which must be for a new key.

use serde::{Deserialize, Serialize};

/// Path of the renewal route on the main (mutual TLS) listener.
pub const RENEW_PATH: &str = "/v1/renew";

/// The request body.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RenewRequest {
    /// PEM certificate signing request, CN equal to the host id, new key.
    pub csr_pem: String,
}

/// The 200 answer. The fields are the ones `POST /v1/enroll` returns.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RenewResponse {
    /// The enrollment CA file, as `POST /v1/enroll` returns it.
    pub ca_chain_pem: String,
    /// The new client certificate.
    pub client_cert_pem: String,
    pub host_id: String,
    /// `notAfter` as openssl prints it.
    pub not_after: String,
    /// Serial of the new certificate, hex.
    pub serial: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answer_has_the_enroll_field_names_and_ignores_unknown_fields() {
        let r: RenewResponse = serde_json::from_str(
            r#"{"ca_chain_pem":"c","client_cert_pem":"p","host_id":"h","not_after":"n","serial":"s","later":1}"#,
        )
        .unwrap();
        assert_eq!(r.client_cert_pem, "p");
        let v = serde_json::to_value(&r).unwrap();
        let keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            [
                "ca_chain_pem",
                "client_cert_pem",
                "host_id",
                "not_after",
                "serial"
            ]
        );
        let q: RenewRequest = serde_json::from_str(r#"{"csr_pem":"x","extra":true}"#).unwrap();
        assert_eq!(q.csr_pem, "x");
    }
}
