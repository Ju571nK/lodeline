//! The status file as the running sender leaves it, read the way `lodeline status`
//! reads it.

mod common;

use lodeline_core::sender_status::{
    status_path_for, LinkFailure, SenderReport, MAX_REPORT_BYTES, STALE_AFTER,
};
use lodeline_diag::{collect, FleetLink, LinkState, Probe};
use lodeline_sender::config::SenderConfig;
use lodeline_sender::runtime::{run, RuntimeCtx};
use std::path::{Path, PathBuf};
use std::time::Duration;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

const HOST_ID: &str = "host-id-marker";

struct Sender {
    dir: tempfile::TempDir,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    config_path: PathBuf,
    status_path: PathBuf,
}

impl Sender {
    fn start(server_base_url: String) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let events = dir.path().join("events");
        std::fs::create_dir(&events).unwrap();
        let id = uuid::Uuid::from_u128(1);
        std::fs::write(
            events.join("events-1.jsonl"),
            format!("{{\"event_id\":\"{id}\",\"payload\":\"a\"}}\n"),
        )
        .unwrap();
        let offset_path = dir.path().join("state/sender-offset.json");
        let config = SenderConfig {
            server_base_url,
            client_cert_path: None,
            client_key_path: None,
            server_ca_path: None,
            events_dir: events,
            offset_path: offset_path.clone(),
            agent_control: dir.path().join("control.sock"),
            dead_letter_dir: dir.path().join("dead-letter"),
            max_batch_events: 256,
            max_batch_bytes: 1024 * 1024,
            policy_poll_interval: Duration::from_secs(600),
            host_id: None,
        };
        let config_path = dir.path().join("sender.yaml");
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run(RuntimeCtx {
            config,
            host_id: HOST_ID.into(),
            agent_version: "1".into(),
            sender_version: "1".into(),
            shutdown: shutdown.clone(),
        }));
        Self {
            dir,
            shutdown,
            task,
            config_path,
            status_path: status_path_for(&offset_path),
        }
    }

    async fn link_at(&self, now: OffsetDateTime) -> LinkState {
        link_from(&self.config_path, now).await
    }

    async fn wait_for(&self, wanted: impl Fn(&LinkState) -> bool) -> LinkState {
        for _ in 0..200 {
            let link = self.link_at(OffsetDateTime::now_utc()).await;
            if wanted(&link) {
                return link;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!(
            "state never arrived, last: {:?}",
            self.link_at(OffsetDateTime::now_utc()).await
        );
    }

    async fn stop(self) -> tempfile::TempDir {
        self.shutdown.cancel();
        self.task.await.unwrap().unwrap();
        self.dir
    }
}

async fn link_from(config: &Path, now: OffsetDateTime) -> LinkState {
    let probe = Probe {
        search_dirs: Vec::new(),
        control_endpoints: Vec::new(),
        sender_configs: vec![config.to_path_buf()],
        ..Probe::detect()
    };
    match collect(&probe, now).await.fleet {
        FleetLink::Configured { link, .. } => link,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_running_sender_reports_connected_then_stale_once_it_stops() {
    let (addr, _mock) = common::spawn_mock().await;
    let sender = Sender::start(format!("http://u:s3cret@{addr}"));
    sender
        .wait_for(|l| matches!(l, LinkState::Connected { .. }))
        .await;

    let bytes = std::fs::read(&sender.status_path).unwrap();
    assert!(bytes.len() as u64 <= MAX_REPORT_BYTES);
    let text = String::from_utf8(bytes.clone()).unwrap();
    for secret in ["s3cret", "http", "127.0.0.1", HOST_ID, "events-1"] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&sender.status_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777 & !0o640, 0, "mode {mode:o}");
    }

    let written_at = serde_json::from_slice::<SenderReport>(&bytes)
        .unwrap()
        .written_at;
    let config = sender.config_path.clone();
    let _dir = sender.stop().await;
    let limit = time::Duration::try_from(STALE_AFTER).unwrap();
    let past_the_limit = written_at + limit + time::Duration::seconds(30);
    assert!(matches!(
        link_from(&config, past_the_limit).await,
        LinkState::Stale {
            last_ok_at: Some(_),
            ..
        }
    ));
}

#[tokio::test]
async fn a_server_that_refuses_batches_reads_as_failing_with_its_code() {
    let (addr, mock) = common::spawn_mock().await;
    mock.lock().await.next_status = 503;
    let sender = Sender::start(format!("http://{addr}"));
    let link = sender
        .wait_for(|l| matches!(l, LinkState::Failing { .. }))
        .await;
    assert!(
        matches!(
            link,
            LinkState::Failing {
                failure: LinkFailure::Response {
                    last_response_code: 503
                },
                last_ok_at: None,
                ..
            }
        ),
        "{link:?}"
    );
    sender.stop().await;
}

#[tokio::test]
async fn a_server_that_is_down_reads_as_a_network_failure() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let sender = Sender::start(format!("http://{addr}"));
    let link = sender
        .wait_for(|l| matches!(l, LinkState::Failing { .. }))
        .await;
    assert!(
        matches!(
            link,
            LinkState::Failing {
                failure: LinkFailure::Network,
                ..
            }
        ),
        "{link:?}"
    );
    sender.stop().await;
}
