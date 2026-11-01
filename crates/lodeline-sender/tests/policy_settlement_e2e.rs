#![cfg(unix)]
//! The running sender against a mock server and a fake agent on the real control
//! socket: a signed document stays on offer until the agent settles it.

mod common;

use common::SharedMock;
use ed25519_dalek::{Signer, SigningKey};
use lodeline_core::control_proto::ApplyPolicyResult;
use lodeline_core::policy::canonical::to_canonical_bytes;
use lodeline_core::policy::pubkeys::{Keystore, KeystoreEntry};
use lodeline_core::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
use lodeline_core::policy::verify_envelope;
use lodeline_core::sender_status::{status_path_for, Contact, SenderReport};
use lodeline_sender::config::SenderConfig;
use lodeline_sender::runtime::{run, RuntimeCtx};
use serde_json::{json, Value};
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::macros::datetime;
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const POLL: Duration = Duration::from_millis(20);
const APPLY_POLICY: &str = "apply_policy";
const APPLY_RULE_PACKS: &str = "apply_rule_packs";
/// Each of these can change with the document unchanged: the host's clock, its
/// keystore, or the agent's version decides them.
const REFUSALS_THAT_CAN_LIFT: [&str; 5] = [
    "pubkey_unknown",
    "pubkey_inactive",
    "signature_invalid",
    "expired",
    "parse_failed",
];

fn signed(etag: &str) -> SignedPolicyResponse {
    SignedPolicyResponse {
        etag: etag.into(),
        signed_envelope: SignedEnvelope {
            policy_version: 5,
            policy_bytes_b64: "AAA=".into(),
            valid_until: datetime!(2030-01-01 0:00 UTC),
            issued_at: datetime!(2026-01-01 0:00 UTC),
        },
        signature: "sig".into(),
        signing_pubkey_id: "k1".into(),
        applied_at: datetime!(2026-01-01 0:00 UTC),
    }
}

async fn publish_policy(mock: &SharedMock, etag: &str) {
    let mut s = mock.lock().await;
    s.policy_etag = etag.into();
    s.policy_response = Some(signed(etag));
}

async fn publish_rule_packs(mock: &SharedMock, etag: &str) {
    let mut s = mock.lock().await;
    s.rule_packs_etag = etag.into();
    s.rule_packs_response = Some(signed(etag));
}

/// A document that really is signed, and the keystore that accepts its signature.
fn really_signed(
    etag: &str,
    published: OffsetDateTime,
    valid_for: time::Duration,
) -> (SignedPolicyResponse, Keystore) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let envelope = SignedEnvelope {
        policy_version: 5,
        policy_bytes_b64: data_encoding::BASE64.encode(b"version: 1\n"),
        valid_until: published + valid_for,
        issued_at: published,
    };
    let signature = key.sign(&to_canonical_bytes(&envelope).unwrap());
    let response = SignedPolicyResponse {
        etag: etag.into(),
        signed_envelope: envelope,
        signature: data_encoding::BASE64.encode(&signature.to_bytes()),
        signing_pubkey_id: "k1".into(),
        applied_at: published,
    };
    let keystore = Keystore {
        pubkeys: vec![KeystoreEntry {
            id: "k1".into(),
            ed25519_pubkey_b64: data_encoding::BASE64.encode(key.verifying_key().as_bytes()),
            valid_from: published - time::Duration::days(365),
            valid_until: published + time::Duration::days(3650),
        }],
    };
    (response, keystore)
}

fn accepted() -> Value {
    json!({"ok": true, "apply_policy": {"outcome": "accepted", "applied_policy_version": 5}})
}

fn refused(reason: &str) -> Value {
    json!({"ok": false, "apply_policy": {"outcome": "rejected", "reason": reason}})
}

fn internal_failure() -> Value {
    json!({"ok": false, "apply_policy": null, "error": "internal: atomic disk write"})
}

struct FakeAgent {
    task: JoinHandle<()>,
    socket: PathBuf,
    offers: Arc<Mutex<Vec<String>>>,
    answer: Arc<Mutex<Value>>,
}

impl FakeAgent {
    fn up(socket: &Path, answer: Value) -> Self {
        let answer = Arc::new(Mutex::new(answer));
        let decide = {
            let answer = answer.clone();
            move |_: &Value| answer.lock().unwrap().clone()
        };
        Self::deciding(socket, answer, decide)
    }

    /// The real verifier decides, on a clock the test controls.
    fn verifying(socket: &Path, keystore: Keystore, clock: Arc<Mutex<OffsetDateTime>>) -> Self {
        let decide = move |request: &Value| {
            let response: SignedPolicyResponse =
                serde_json::from_value(request["response"].clone()).unwrap();
            let now = *clock.lock().unwrap();
            match verify_envelope(&keystore, &response, now, 0) {
                Ok(_) => accepted(),
                Err(refusal) => json!({
                    "ok": false,
                    "apply_policy": ApplyPolicyResult::Rejected {
                        reason: refusal.reason().unwrap(),
                    },
                }),
            }
        };
        Self::deciding(socket, Arc::new(Mutex::new(Value::Null)), decide)
    }

    fn deciding(
        socket: &Path,
        answer: Arc<Mutex<Value>>,
        decide: impl Fn(&Value) -> Value + Send + 'static,
    ) -> Self {
        let listener = UnixListener::bind(socket).unwrap();
        let offers = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let offers = offers.clone();
            async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let (rd, mut wr) = stream.into_split();
                    let mut line = String::new();
                    BufReader::new(rd).read_line(&mut line).await.unwrap();
                    let request: Value = serde_json::from_str(line.trim()).unwrap();
                    offers
                        .lock()
                        .unwrap()
                        .push(request["cmd"].as_str().unwrap().to_owned());
                    let mut reply = serde_json::to_vec(&decide(&request)).unwrap();
                    reply.push(b'\n');
                    wr.write_all(&reply).await.unwrap();
                }
            }
        });
        Self {
            task,
            socket: socket.to_owned(),
            offers,
            answer,
        }
    }

    fn offers_of(&self, cmd: &str) -> usize {
        self.offers
            .lock()
            .unwrap()
            .iter()
            .filter(|c| *c == cmd)
            .count()
    }

    fn answer_with(&self, answer: Value) {
        *self.answer.lock().unwrap() = answer;
    }

    async fn down(self) {
        self.task.abort();
        let _ = self.task.await;
        std::fs::remove_file(&self.socket).unwrap();
    }
}

struct Sender {
    shutdown: CancellationToken,
    task: JoinHandle<anyhow::Result<()>>,
}

impl Sender {
    fn start(dir: &Path, server: SocketAddr) -> Self {
        let events_dir = dir.join("events");
        std::fs::create_dir_all(&events_dir).unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run(RuntimeCtx {
            config: SenderConfig {
                server_base_url: format!("http://{server}"),
                client_cert_path: None,
                client_key_path: None,
                server_ca_path: None,
                events_dir,
                offset_path: dir.join("sender-offset.json"),
                agent_control: dir.join("control.sock"),
                dead_letter_dir: dir.join("dead-letter"),
                max_batch_events: 256,
                max_batch_bytes: 1024 * 1024,
                policy_poll_interval: POLL,
                host_id: None,
            },
            host_id: "h".into(),
            agent_version: "1".into(),
            sender_version: "1".into(),
            shutdown: shutdown.clone(),
        }));
        Self { shutdown, task }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        self.task.await.unwrap().unwrap();
    }
}

async fn eventually<F, Fut>(condition: F) -> bool
where
    F: Fn() -> Fut,
    Fut: Future<Output = bool>,
{
    for _ in 0..200 {
        if condition().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

async fn policy_polls(mock: &SharedMock) -> usize {
    mock.lock().await.policy_polls
}

async fn policy_bodies(mock: &SharedMock) -> usize {
    mock.lock().await.policy_bodies
}

/// Lets `count` more polls of `/v1/policy` finish.
async fn let_polls_pass(mock: &SharedMock, count: usize) {
    let target = policy_polls(mock).await + count;
    assert!(
        eventually(|| async { policy_polls(mock).await >= target }).await,
        "the sender stopped polling"
    );
}

fn persisted(dir: &Path, file: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(file)).ok()
}

fn contact(dir: &Path) -> Option<Contact> {
    let status = status_path_for(&dir.join("sender-offset.json"));
    let bytes = std::fs::read(status).ok()?;
    let report: SenderReport = serde_json::from_slice(&bytes).ok()?;
    Some(report.contact)
}

#[tokio::test]
async fn a_policy_reaches_an_agent_that_was_down_for_the_first_delivery() {
    let (addr, mock) = common::spawn_mock().await;
    publish_policy(&mock, "v5").await;
    let dir = tempfile::tempdir().unwrap();
    let sender = Sender::start(dir.path(), addr);
    let_polls_pass(&mock, 3).await;
    assert_eq!(persisted(dir.path(), "policy-etag.txt"), None);

    let agent = FakeAgent::up(&dir.path().join("control.sock"), accepted());
    let arrived = eventually(|| async { agent.offers_of(APPLY_POLICY) > 0 }).await;
    assert!(
        arrived,
        "the agent got no policy after {} polls, {} of them with a body",
        policy_polls(&mock).await,
        policy_bodies(&mock).await
    );

    let_polls_pass(&mock, 5).await;
    assert_eq!(
        agent.offers_of(APPLY_POLICY),
        1,
        "applied, so asked no more"
    );
    assert_eq!(
        persisted(dir.path(), "policy-etag.txt").as_deref(),
        Some("v5")
    );
    sender.stop().await;
}

#[tokio::test]
async fn an_agent_failure_is_retried_at_the_poll_interval() {
    let (addr, mock) = common::spawn_mock().await;
    publish_policy(&mock, "v5").await;
    let dir = tempfile::tempdir().unwrap();
    let agent = FakeAgent::up(&dir.path().join("control.sock"), internal_failure());
    let sender = Sender::start(dir.path(), addr);

    let retried = eventually(|| async { agent.offers_of(APPLY_POLICY) >= 3 }).await;
    assert!(
        retried,
        "only {} offers after {} polls",
        agent.offers_of(APPLY_POLICY),
        policy_polls(&mock).await
    );

    agent.answer_with(accepted());
    assert!(eventually(|| async { persisted(dir.path(), "policy-etag.txt").is_some() }).await);
    sender.stop().await;
}

#[tokio::test]
async fn a_policy_the_agent_can_never_take_is_fetched_once_across_a_restart() {
    let (addr, mock) = common::spawn_mock().await;
    publish_policy(&mock, "v5").await;
    let dir = tempfile::tempdir().unwrap();
    let agent = FakeAgent::up(
        &dir.path().join("control.sock"),
        refused("version_regression"),
    );

    let sender = Sender::start(dir.path(), addr);
    let_polls_pass(&mock, 5).await;
    sender.stop().await;
    let sender = Sender::start(dir.path(), addr);
    let_polls_pass(&mock, 15).await;
    sender.stop().await;

    assert_eq!(policy_bodies(&mock).await, 1);
    assert_eq!(agent.offers_of(APPLY_POLICY), 1);
}

#[tokio::test]
async fn a_refusal_that_can_lift_is_offered_every_12_polls_until_the_agent_takes_it() {
    for reason in REFUSALS_THAT_CAN_LIFT {
        let (addr, mock) = common::spawn_mock().await;
        publish_policy(&mock, "v5").await;
        publish_rule_packs(&mock, "packs-1").await;
        let dir = tempfile::tempdir().unwrap();
        let agent = FakeAgent::up(&dir.path().join("control.sock"), refused(reason));
        let sender = Sender::start(dir.path(), addr);

        let_polls_pass(&mock, 14).await;
        {
            let s = mock.lock().await;
            assert_eq!(
                s.policy_bodies,
                1 + (s.policy_polls - 1) / 12,
                "{reason}: {} polls",
                s.policy_polls
            );
        }
        assert_eq!(persisted(dir.path(), "policy-etag.txt"), None, "{reason}");

        agent.answer_with(accepted());
        let applied = eventually(|| async {
            persisted(dir.path(), "policy-etag.txt").is_some()
                && persisted(dir.path(), "rule-packs-etag.txt").is_some()
        })
        .await;
        assert!(applied, "{reason}: never applied without a restart");

        let bodies = policy_bodies(&mock).await;
        let_polls_pass(&mock, 13).await;
        assert_eq!(
            policy_bodies(&mock).await,
            bodies,
            "{reason}: applied, so asked no more"
        );
        assert_eq!(agent.offers_of(APPLY_POLICY), bodies, "{reason}");
        sender.stop().await;
    }
}

#[tokio::test]
async fn a_policy_refused_on_a_fast_clock_applies_once_the_clock_is_corrected() {
    let published = datetime!(2026-06-01 0:00 UTC);
    let (response, keystore) = really_signed("v5", published, time::Duration::days(1));
    let fast_clock = published + time::Duration::days(30);
    assert!(
        verify_envelope(&keystore, &response, fast_clock, 0).is_err(),
        "the fast clock must refuse this document"
    );
    let (addr, mock) = common::spawn_mock().await;
    {
        let mut s = mock.lock().await;
        s.policy_etag = "v5".into();
        s.policy_response = Some(response);
    }
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(Mutex::new(fast_clock));
    let agent = FakeAgent::verifying(&dir.path().join("control.sock"), keystore, clock.clone());
    let sender = Sender::start(dir.path(), addr);

    assert!(eventually(|| async { agent.offers_of(APPLY_POLICY) >= 1 }).await);
    assert_eq!(persisted(dir.path(), "policy-etag.txt"), None);

    *clock.lock().unwrap() = published + time::Duration::hours(1);
    let applied = eventually(|| async { persisted(dir.path(), "policy-etag.txt").is_some() }).await;
    assert!(
        applied,
        "still unapplied after {} polls, {} of them with a body",
        policy_polls(&mock).await,
        policy_bodies(&mock).await
    );
    let bodies = policy_bodies(&mock).await;
    assert!(bodies >= 2, "applied with no second fetch");
    assert_eq!(agent.offers_of(APPLY_POLICY), bodies);

    let_polls_pass(&mock, 13).await;
    assert_eq!(
        policy_bodies(&mock).await,
        bodies,
        "applied, so asked no more"
    );
    let reached =
        eventually(|| async { matches!(contact(dir.path()), Some(Contact::Reached { .. })) }).await;
    assert!(reached, "{:?}", contact(dir.path()));
    sender.stop().await;
}

#[tokio::test]
async fn a_restart_resumes_from_the_settled_policy() {
    let (addr, mock) = common::spawn_mock().await;
    publish_policy(&mock, "v5").await;
    let dir = tempfile::tempdir().unwrap();
    let agent = FakeAgent::up(&dir.path().join("control.sock"), accepted());

    let sender = Sender::start(dir.path(), addr);
    assert!(eventually(|| async { agent.offers_of(APPLY_POLICY) == 1 }).await);
    sender.stop().await;

    let sender = Sender::start(dir.path(), addr);
    let_polls_pass(&mock, 5).await;
    assert_eq!(
        policy_bodies(&mock).await,
        1,
        "the restart fetched it again"
    );
    assert_eq!(agent.offers_of(APPLY_POLICY), 1);

    publish_policy(&mock, "v6").await;
    assert!(eventually(|| async { agent.offers_of(APPLY_POLICY) == 2 }).await);
    sender.stop().await;
    assert_eq!(
        persisted(dir.path(), "policy-etag.txt").as_deref(),
        Some("v6")
    );
}

#[tokio::test]
async fn a_restart_during_an_outage_delivers_the_policy_it_never_settled() {
    let (addr, mock) = common::spawn_mock().await;
    publish_policy(&mock, "v5").await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let agent = FakeAgent::up(&socket, accepted());
    let sender = Sender::start(dir.path(), addr);
    assert!(eventually(|| async { agent.offers_of(APPLY_POLICY) == 1 }).await);
    agent.down().await;

    publish_policy(&mock, "v6").await;
    let_polls_pass(&mock, 3).await;
    sender.stop().await;
    assert_eq!(
        persisted(dir.path(), "policy-etag.txt").as_deref(),
        Some("v5")
    );

    let agent = FakeAgent::up(&socket, accepted());
    let sender = Sender::start(dir.path(), addr);
    assert!(eventually(|| async { agent.offers_of(APPLY_POLICY) == 1 }).await);
    sender.stop().await;
    assert_eq!(
        persisted(dir.path(), "policy-etag.txt").as_deref(),
        Some("v6")
    );
}

#[tokio::test]
async fn rule_packs_stay_on_offer_and_resume_on_their_own_etag() {
    let (addr, mock) = common::spawn_mock().await;
    publish_policy(&mock, "v5").await;
    publish_rule_packs(&mock, "packs-1").await;
    let dir = tempfile::tempdir().unwrap();
    let sender = Sender::start(dir.path(), addr);
    let_polls_pass(&mock, 3).await;

    let agent = FakeAgent::up(&dir.path().join("control.sock"), accepted());
    let arrived = eventually(|| async { agent.offers_of(APPLY_RULE_PACKS) > 0 }).await;
    assert!(
        arrived,
        "the agent got no rule packs after {} polls",
        mock.lock().await.rule_pack_polls
    );
    let_polls_pass(&mock, 3).await;
    sender.stop().await;

    let sender = Sender::start(dir.path(), addr);
    let_polls_pass(&mock, 5).await;
    sender.stop().await;

    assert_eq!(agent.offers_of(APPLY_RULE_PACKS), 1);
    assert_eq!(
        persisted(dir.path(), "rule-packs-etag.txt").as_deref(),
        Some("packs-1")
    );
    let bodies_after_the_outage = mock.lock().await.rule_pack_bodies;
    assert!(bodies_after_the_outage >= 2, "{bodies_after_the_outage}");
}

#[tokio::test]
async fn an_agent_outage_is_not_a_failing_link_to_the_server() {
    let (addr, mock) = common::spawn_mock().await;
    publish_policy(&mock, "v5").await;
    let dir = tempfile::tempdir().unwrap();
    let sender = Sender::start(dir.path(), addr);

    let reached =
        eventually(|| async { matches!(contact(dir.path()), Some(Contact::Reached { .. })) }).await;
    assert!(reached, "{:?}", contact(dir.path()));
    sender.stop().await;
}
