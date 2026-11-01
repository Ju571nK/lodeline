#![cfg(unix)]
//! The running sender against a mock server and a fake agent on the real control
//! socket: a signed document stays on offer until the agent settles it.

mod common;

use common::SharedMock;
use lodeline_core::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const POLL: Duration = Duration::from_millis(20);
const APPLY_POLICY: &str = "apply_policy";
const APPLY_RULE_PACKS: &str = "apply_rule_packs";

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
        let listener = UnixListener::bind(socket).unwrap();
        let offers = Arc::new(Mutex::new(Vec::new()));
        let answer = Arc::new(Mutex::new(answer));
        let task = tokio::spawn({
            let offers = offers.clone();
            let answer = answer.clone();
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
                    let mut reply = serde_json::to_vec(&*answer.lock().unwrap()).unwrap();
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
    for reason in ["version_regression", "signature_invalid", "parse_failed"] {
        let (addr, mock) = common::spawn_mock().await;
        publish_policy(&mock, "v5").await;
        let dir = tempfile::tempdir().unwrap();
        let agent = FakeAgent::up(&dir.path().join("control.sock"), refused(reason));

        let sender = Sender::start(dir.path(), addr);
        let_polls_pass(&mock, 5).await;
        sender.stop().await;
        let sender = Sender::start(dir.path(), addr);
        let_polls_pass(&mock, 5).await;
        sender.stop().await;

        assert_eq!(policy_bodies(&mock).await, 1, "{reason}");
        assert_eq!(agent.offers_of(APPLY_POLICY), 1, "{reason}");
    }
}

#[tokio::test]
async fn a_refusal_the_host_can_fix_is_offered_slowly_until_the_agent_takes_it() {
    let (addr, mock) = common::spawn_mock().await;
    publish_policy(&mock, "v5").await;
    let dir = tempfile::tempdir().unwrap();
    let agent = FakeAgent::up(&dir.path().join("control.sock"), refused("pubkey_unknown"));
    let sender = Sender::start(dir.path(), addr);

    let offered_twice = eventually(|| async { agent.offers_of(APPLY_POLICY) >= 2 }).await;
    assert!(offered_twice, "the refusal was never rechecked");
    let polls = policy_polls(&mock).await;
    assert!(polls >= 6, "offered twice in {polls} polls");
    assert_eq!(persisted(dir.path(), "policy-etag.txt"), None);

    agent.answer_with(accepted());
    assert!(eventually(|| async { persisted(dir.path(), "policy-etag.txt").is_some() }).await);
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
    {
        let mut s = mock.lock().await;
        s.rule_packs_etag = "packs-1".into();
        s.rule_packs_response = Some(signed("packs-1"));
    }
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
    let status = status_path_for(&dir.path().join("sender-offset.json"));
    let sender = Sender::start(dir.path(), addr);

    let contact = || {
        std::fs::read(&status)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<SenderReport>(&bytes).ok())
            .map(|report| report.contact)
    };
    let reached = eventually(|| async { matches!(contact(), Some(Contact::Reached { .. })) }).await;
    assert!(reached, "{:?}", contact());
    sender.stop().await;
}
