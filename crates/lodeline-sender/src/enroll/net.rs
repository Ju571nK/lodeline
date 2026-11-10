//! The one request enroll makes to the enrollment listener: `POST /v1/enroll`.
//!
//! The listener allows 10 connections per source, then one every 6 s, and answers
//! one request per connection. Each attempt here is a new connection, and the whole
//! run stops after [`MAX_ATTEMPTS`].

use crate::transport::{cap_server_text, classify_send_error, SendOutcome};
use lodeline_fleet_api::ErrorBody;
use serde_json::Value;
use std::time::Duration;

pub const MAX_ATTEMPTS: u32 = 8;
const MAX_BUSY_RETRIES: u32 = 5;

pub struct Pacing {
    /// Waits before each retry after a network error.
    pub network_waits: Vec<Duration>,
}

impl Default for Pacing {
    fn default() -> Self {
        Self {
            network_waits: [10, 20, 30, 60].map(Duration::from_secs).into(),
        }
    }
}

pub struct Issued {
    pub cert_pem: String,
    pub chain_pem: String,
}

/// A failure with the exit code and the message to print.
#[derive(Debug)]
pub struct NetFail {
    pub code: i32,
    pub msg: String,
}

fn fail(code: i32, msg: impl Into<String>) -> NetFail {
    NetFail {
        code,
        msg: msg.into(),
    }
}

pub struct Request<'a> {
    pub enroll_url: &'a str,
    pub server_ca_pem: &'a str,
    pub token: &'a str,
    pub host_id: &'a str,
    pub csr_pem: &'a str,
    pub expires_at: Option<&'a str>,
    /// The key existed before this run, so an earlier run may have spent the token.
    pub earlier_run: bool,
}

fn client(ca_pem: &str) -> Result<reqwest::Client, NetFail> {
    let roots = reqwest::Certificate::from_pem_bundle(ca_pem.as_bytes())
        .map_err(|e| fail(1, format!("cannot use server_ca_pem: {e}")))?;
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .http1_only()
        .pool_max_idle_per_host(0)
        .connect_timeout(crate::transport::CONNECT_TIMEOUT)
        .timeout(Duration::from_secs(60));
    for r in roots {
        b = b.add_root_certificate(r);
    }
    b.build()
        .map_err(|e| fail(1, format!("cannot build the HTTP client: {e}")))
}

fn spent_hint(r: &Request<'_>) -> String {
    let mut s = format!(
        "Issue a new token with `lodeline-server enroll-token --host-id {}` and run enroll with the new file. The host's key is kept.",
        r.host_id
    );
    if r.earlier_run {
        s.push_str(" An earlier run may have spent this token and lost the answer.");
    }
    s
}

/// `Retry-After` in seconds, kept between 1 and 10 s; 1 s when absent or not a number.
pub fn busy_wait(header: Option<&str>) -> Duration {
    let secs = header
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(1);
    Duration::from_secs(secs.clamp(1, 10))
}

fn server_error(text: &str) -> String {
    match serde_json::from_str::<ErrorBody>(text) {
        Ok(b) => cap_server_text(&format!("{}: {}", b.error.code, b.error.message)),
        Err(_) => cap_server_text(text),
    }
}

pub async fn post(r: &Request<'_>, pacing: &Pacing) -> Result<Issued, NetFail> {
    let client = client(r.server_ca_pem)?;
    let url = format!("{}/v1/enroll", r.enroll_url);
    let body = serde_json::json!({"token": r.token, "host_id": r.host_id, "csr_pem": r.csr_pem});
    let (mut attempts, mut busy, mut waits, mut retried_421) = (0u32, 0u32, 0usize, false);
    loop {
        attempts += 1;
        let resp = match client.post(&url).json(&body).send().await {
            Ok(resp) => resp,
            Err(e) => match classify_send_error::<()>(e) {
                SendOutcome::TlsFailure(cause) if cause.contains("invalid peer certificate") => {
                    return Err(fail(6, format!(
                        "{} presented a certificate that the CA in the enrollment file does not trust, or that does not name its host. The token was not sent.",
                        r.enroll_url
                    )))
                }
                SendOutcome::TlsFailure(cause) => {
                    return Err(fail(6, format!("TLS failed: {cause}. The token was not sent.")))
                }
                SendOutcome::Network(cause) => {
                    if attempts >= MAX_ATTEMPTS || waits >= pacing.network_waits.len() {
                        return Err(fail(6, format!(
                            "could not reach {}: {cause}. The port may be firewalled, the server down, or this host over the port's limit of 10 connections, then one every 6 s. Run enroll again later.",
                            r.enroll_url
                        )));
                    }
                    let wait = pacing.network_waits[waits];
                    eprintln!(
                        "could not reach {} ({cause}); trying again in {} s",
                        r.enroll_url,
                        wait.as_secs()
                    );
                    tokio::time::sleep(wait).await;
                    waits += 1;
                    continue;
                }
                _ => return Err(fail(1, "unexpected client failure")),
            },
        };
        let status = resp.status().as_u16();
        let retry_after = busy_wait(
            resp.headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
        );
        let text = resp.text().await.unwrap_or_default();
        match status {
            200 => {
                let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                let get = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
                return match (get("client_cert_pem"), get("ca_chain_pem")) {
                    (Some(cert_pem), Some(chain_pem)) => Ok(Issued { cert_pem, chain_pem }),
                    _ => Err(fail(5, "the server answered 200 with a body enroll cannot read. The token is spent. Read the server log, then issue a new token.")),
                };
            }
            403 => {
                return Err(fail(5, format!(
                    "the token was refused: it is unknown, spent, expired{}, or for another host_id. {}",
                    r.expires_at.map(|e| format!(" (the file says {e})")).unwrap_or_default(),
                    spent_hint(r)
                )))
            }
            404 => {
                return Err(fail(6, format!(
                    "{} is not an enrollment listener, or enrollment is off.",
                    r.enroll_url
                )))
            }
            421 if !retried_421 => {
                retried_421 = true;
                continue;
            }
            503 => {
                busy += 1;
                if busy > MAX_BUSY_RETRIES || attempts >= MAX_ATTEMPTS {
                    return Err(fail(6, "the server stayed busy. The token was not used. Run enroll again."));
                }
                eprintln!(
                    "the server is busy; trying again in {} s",
                    retry_after.as_secs()
                );
                tokio::time::sleep(retry_after).await;
                continue;
            }
            500..=599 => {
                let mut m = format!(
                    "the server failed ({}). The token may be spent. Read the server log, then issue a new token.",
                    server_error(&text)
                );
                if text.contains("token store error") {
                    m.push_str(" The server cannot read its token file; see install-server.md, Troubleshooting.");
                }
                return Err(fail(5, m));
            }
            400 | 413 | 415 | 421 | 422 => {
                return Err(fail(1, format!(
                    "the server rejected the request as malformed ({status}: {}). This is a lodeline-sender bug or a version mismatch. The token was not used.",
                    server_error(&text)
                )))
            }
            other => {
                return Err(fail(1, format!(
                    "unexpected answer {other}: {}",
                    server_error(&text)
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_is_clamped_to_one_to_ten_seconds() {
        for (h, want) in [
            (None, 1),
            (Some("0"), 1),
            (Some("3"), 3),
            (Some("999"), 10),
            (Some("soon"), 1),
        ] {
            assert_eq!(busy_wait(h), Duration::from_secs(want), "{h:?}");
        }
    }
}
