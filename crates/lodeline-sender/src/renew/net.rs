//! The one request renewal makes: `POST /v1/renew` over the host's current client.

use lodeline_fleet_api::renewal::{RenewRequest, RenewResponse, RENEW_PATH};
use std::time::Duration;

/// Longest wait a `Retry-After` can ask for.
const MAX_RETRY_AFTER: u64 = 3600;

/// What the server said, as far as renewal acts on it.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// 200: a new certificate.
    Issued(RenewResponse),
    /// 409: the certificate is not past half of its validity. The wait is the server's
    /// `Retry-After`, kept between 1 s and 1 h.
    TooEarly(Duration),
    /// 403 or 404: the server will not renew this host. Waiting does not fix it.
    Refused(u16),
    /// Anything else, with the cause to log: no answer, TLS, 5xx, a body that is not an answer.
    Failed(String),
}

pub fn classify(status: u16, retry_after: Option<&str>, body: &str) -> Answer {
    match status {
        200 => match serde_json::from_str(body) {
            Ok(r) => Answer::Issued(r),
            Err(e) => Answer::Failed(format!("the 200 answer is not a certificate: {e}")),
        },
        409 => {
            let secs = retry_after
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(60);
            Answer::TooEarly(Duration::from_secs(secs.clamp(1, MAX_RETRY_AFTER)))
        }
        403 | 404 => Answer::Refused(status),
        other => Answer::Failed(format!(
            "status {other}: {}",
            crate::transport::cap_server_text(body)
        )),
    }
}

pub async fn request(client: &reqwest::Client, server_base_url: &str, csr_pem: &str) -> Answer {
    let url = format!("{}{RENEW_PATH}", server_base_url.trim_end_matches('/'));
    let body = RenewRequest {
        csr_pem: csr_pem.to_owned(),
    };
    let resp = match client.post(&url).json(&body).send().await {
        Ok(r) => r,
        Err(e) => return Answer::Failed(crate::transport::failure_cause(e)),
    };
    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    match resp.text().await {
        Ok(text) => classify(status, retry_after.as_deref(), &text),
        Err(e) => Answer::Failed(crate::transport::failure_cause(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_status_has_its_own_handling() {
        let ok = r#"{"ca_chain_pem":"c","client_cert_pem":"p","host_id":"h","not_after":"n","serial":"s"}"#;
        assert!(matches!(classify(200, None, ok), Answer::Issued(r) if r.client_cert_pem == "p"));
        assert!(matches!(classify(200, None, "{}"), Answer::Failed(_)));
        assert_eq!(classify(403, None, ""), Answer::Refused(403));
        assert_eq!(classify(404, None, ""), Answer::Refused(404));
        for status in [400, 413, 500, 503] {
            assert!(
                matches!(classify(status, None, "x"), Answer::Failed(_)),
                "{status}"
            );
        }
    }

    #[test]
    fn retry_after_is_honoured_and_capped() {
        let wait = |h| match classify(409, h, "") {
            Answer::TooEarly(d) => d.as_secs(),
            other => panic!("{other:?}"),
        };
        assert_eq!(wait(Some("90")), 90);
        assert_eq!(wait(Some("0")), 1);
        assert_eq!(wait(Some("999999")), 3600);
        assert_eq!(wait(None), 60);
        assert_eq!(wait(Some("soon")), 60);
    }
}
