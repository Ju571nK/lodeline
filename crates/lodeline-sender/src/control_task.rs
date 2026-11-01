//! Control plane: poll /v1/policy, hand 200 results to the agent IPC.

use crate::agent_ipc::{self, Settlement};
use crate::heartbeat::{Plane, SharedStats};
use crate::state;
use crate::transport::{classify_send_error, failure_cause, SendOutcome};
use crate::wire::SignedPolicyResponse;
use lodeline_core::sender_status::LinkFailure;
use reqwest::Client;
use time::OffsetDateTime;

#[derive(Debug)]
pub enum PollOutcome {
    /// Server returned a fresh policy. The control loop offers it to the agent.
    NewPolicy {
        etag: String,
        response: SignedPolicyResponse,
    },
    /// Server returned a fresh rule-pack bundle. The control loop offers it to
    /// the agent. Same response shape as a policy.
    NewRulePacks {
        etag: String,
        response: SignedPolicyResponse,
    },
    /// Server returned 304 — no work to do.
    Unmodified,
    /// 404 → host is not in inventory; emit local event.
    HostUnknown,
    /// TLS handshake failure.
    TlsFailure(String),
    /// Network failure.
    Network(String),
    /// Other / parse failure. `status` is set when the status itself was the problem.
    ProtocolViolation { status: Option<u16>, detail: String },
}

impl PollOutcome {
    pub(crate) fn link_result(&self) -> Result<(), LinkFailure> {
        match self {
            PollOutcome::NewPolicy { .. }
            | PollOutcome::NewRulePacks { .. }
            | PollOutcome::Unmodified => Ok(()),
            PollOutcome::HostUnknown => Err(LinkFailure::Response {
                last_response_code: 404,
            }),
            PollOutcome::TlsFailure(_) => Err(LinkFailure::Tls),
            PollOutcome::Network(_) => Err(LinkFailure::Network),
            PollOutcome::ProtocolViolation {
                status: Some(code), ..
            } => Err(LinkFailure::Response {
                last_response_code: *code,
            }),
            PollOutcome::ProtocolViolation { status: None, .. } => Err(LinkFailure::Protocol),
        }
    }
}

fn protocol_violation(detail: String) -> PollOutcome {
    PollOutcome::ProtocolViolation {
        status: None,
        detail,
    }
}

fn bad_status(status: u16, body: &str) -> PollOutcome {
    PollOutcome::ProtocolViolation {
        status: Some(status),
        detail: format!("status {status}: {body}"),
    }
}

pub async fn poll_policy(
    client: &Client,
    server_base_url: &str,
    host_id: &str,
    cached_etag: Option<&str>,
) -> PollOutcome {
    let url = format!(
        "{}/v1/policy?host_id={}",
        server_base_url.trim_end_matches('/'),
        urlencoding::encode(host_id)
    );
    let mut req = client.get(&url);
    if let Some(etag) = cached_etag {
        req = req.header("if-none-match", etag);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => match classify_send_error::<()>(e) {
            SendOutcome::TlsFailure(s) => return PollOutcome::TlsFailure(s),
            SendOutcome::Network(s) => return PollOutcome::Network(s),
            other => return protocol_violation(format!("{other:?}")),
        },
    };
    let status = resp.status().as_u16();
    if status == 304 {
        return PollOutcome::Unmodified;
    }
    if status == 404 {
        // The server also answers 404 when it holds no policy, for a host it knows.
        let body = resp.text().await.unwrap_or_default();
        let error = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error")?.as_str().map(str::to_owned));
        return match error.as_deref() {
            Some("no_policy") => PollOutcome::Unmodified,
            _ => PollOutcome::HostUnknown,
        };
    }
    if !(200..300).contains(&status) {
        let body = resp.text().await.unwrap_or_default();
        return bad_status(status, &body);
    }
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();
    match resp.json::<SignedPolicyResponse>().await {
        Ok(response) => PollOutcome::NewPolicy { etag, response },
        Err(e) => protocol_violation(format!("policy json: {}", failure_cause(e))),
    }
}

/// Polls `/v1/rule-packs`. Mirrors [`poll_policy`] but hits the rule-packs
/// endpoint and maps success → [`PollOutcome::NewRulePacks`].
///
/// A 404 is BENIGN here: rule packs are opt-in, so a host without a
/// configured bundle (or an unknown host) returns 404. The authoritative
/// host-allowlist signal is the `/v1/policy` poll (which maps 404 →
/// `HostUnknown`); to avoid double-signalling we treat the rule-packs 404 as
/// `Unmodified` — there is simply nothing to apply.
pub async fn poll_rule_packs(
    client: &Client,
    server_base_url: &str,
    host_id: &str,
    cached_etag: Option<&str>,
) -> PollOutcome {
    let url = format!(
        "{}/v1/rule-packs?host_id={}",
        server_base_url.trim_end_matches('/'),
        urlencoding::encode(host_id)
    );
    let mut req = client.get(&url);
    if let Some(etag) = cached_etag {
        req = req.header("if-none-match", etag);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => match classify_send_error::<()>(e) {
            SendOutcome::TlsFailure(s) => return PollOutcome::TlsFailure(s),
            SendOutcome::Network(s) => return PollOutcome::Network(s),
            other => return protocol_violation(format!("{other:?}")),
        },
    };
    let status = resp.status().as_u16();
    if status == 304 {
        return PollOutcome::Unmodified;
    }
    if status == 404 {
        // Benign: no bundle configured / not present. Not an error.
        return PollOutcome::Unmodified;
    }
    if !(200..300).contains(&status) {
        let body = resp.text().await.unwrap_or_default();
        return bad_status(status, &body);
    }
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();
    match resp.json::<SignedPolicyResponse>().await {
        Ok(response) => PollOutcome::NewRulePacks { etag, response },
        Err(e) => protocol_violation(format!("rule-packs json: {}", failure_cause(e))),
    }
}

use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// One poll in this many offers a document the agent [refused for now] again. Each
/// offer costs a full body and a warning event in the fleet, so a document that never
/// passes costs 24 full fetches a day at the default poll interval.
///
/// [refused for now]: Settlement::RefusedForNow
const POLLS_PER_OFFER_REFUSED_FOR_NOW: u32 = 12;

pub struct ControlLoopCtx {
    pub client: Client,
    pub server_base_url: String,
    pub host_id: String,
    pub poll_interval: Duration,
    pub shutdown: CancellationToken,
    pub outcomes: mpsc::Sender<PollOutcome>,
    pub stats: SharedStats,
    pub agent_control: PathBuf,
    pub policy_etag_path: PathBuf,
    pub packs_etag_path: PathBuf,
}

/// The `If-None-Match` state of one kind of document. The sender stops asking for a
/// document only once the agent has settled it.
struct Offer {
    etag_path: PathBuf,
    /// The last document the agent settled. Survives a restart.
    settled: Option<String>,
    /// A document refused for now, and the polls left before it is offered again.
    /// Lost on a restart, so a restart offers it once more.
    refused: Option<(String, u32)>,
}

impl Offer {
    fn load(etag_path: &Path) -> Self {
        Self {
            etag_path: etag_path.to_owned(),
            settled: state::load_etag(etag_path).ok().flatten(),
            refused: None,
        }
    }

    /// The validator for the next poll. Call once per poll: it counts them.
    fn if_none_match(&mut self) -> Option<&str> {
        match &mut self.refused {
            Some((etag, polls_left)) if *polls_left > 0 => {
                *polls_left -= 1;
                Some(etag)
            }
            _ => self.settled.as_deref(),
        }
    }

    fn settle(&mut self, etag: &str, settlement: Settlement) {
        if settlement != Settlement::Applied {
            tracing::warn!(etag, ?settlement, "agent did not apply the document");
        }
        match settlement {
            Settlement::Applied | Settlement::Refused(_) => {
                if let Err(e) = state::store_etag(&self.etag_path, etag) {
                    tracing::warn!(error = ?e, "store_etag failed");
                }
                self.settled = Some(etag.to_owned());
                self.refused = None;
            }
            Settlement::RefusedForNow(_) => {
                self.refused = Some((etag.to_owned(), POLLS_PER_OFFER_REFUSED_FOR_NOW - 1));
            }
            Settlement::Undecided(_) => {}
        }
    }
}

/// Polls with the configured interval and offers each new document to the agent. One
/// task does both, in order, so a poll cannot overtake the agent's answer to the last
/// offer.
pub async fn run(ctx: ControlLoopCtx) {
    // Separate offers: policy and rule packs are versioned independently.
    let mut policy = Offer::load(&ctx.policy_etag_path);
    let mut packs = Offer::load(&ctx.packs_etag_path);
    let mut interval = tokio::time::interval(ctx.poll_interval);
    interval.tick().await; // skip immediate fire
    loop {
        tokio::select! {
            biased;
            _ = ctx.shutdown.cancelled() => break,
            _ = interval.tick() => {
                let p = poll_policy(
                    &ctx.client,
                    &ctx.server_base_url,
                    &ctx.host_id,
                    policy.if_none_match(),
                ).await;
                // Only the policy poll counts: `poll_rule_packs` maps 404 to `Unmodified`,
                // which would clear a host-unknown answer moments after it arrived.
                ctx.stats.write().record(Plane::Policy, p.link_result(), OffsetDateTime::now_utc());
                if let PollOutcome::NewPolicy { etag, response } = &p {
                    let answer = agent_ipc::apply_policy(&ctx.agent_control, response).await;
                    policy.settle(etag, answer.into());
                }
                if ctx.outcomes.send(p).await.is_err() {
                    // Receiver dropped — exit loop.
                    break;
                }
                let r = poll_rule_packs(
                    &ctx.client,
                    &ctx.server_base_url,
                    &ctx.host_id,
                    packs.if_none_match(),
                ).await;
                if let PollOutcome::NewRulePacks { etag, response } = &r {
                    let answer = agent_ipc::apply_rule_packs(&ctx.agent_control, response).await;
                    packs.settle(etag, answer.into());
                }
                if ctx.outcomes.send(r).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lodeline_core::event::PolicySignatureInvalidReason::Expired;

    #[test]
    fn a_document_that_never_passes_costs_24_full_fetches_a_day_at_the_default_poll() {
        let dir = tempfile::tempdir().unwrap();
        let mut offer = Offer::load(&dir.path().join("policy-etag.txt"));
        let default_polls_a_day = 86_400 / 300;

        let mut full_fetches = 0;
        for _ in 0..default_polls_a_day {
            if offer.if_none_match() != Some("v5") {
                full_fetches += 1;
                offer.settle("v5", Settlement::RefusedForNow(Expired));
            }
        }
        assert_eq!(full_fetches, 24);
    }
}
