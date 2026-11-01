//! What a failing sender leaves in the dead-letter directory, which has no rotation.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use lodeline_sender::config::SenderConfig;
use lodeline_sender::data_task::{self, DataTaskCtx};
use lodeline_sender::heartbeat;
use lodeline_sender::runtime::{run, RuntimeCtx};
use lodeline_sender::wire::{EventsAccepted, EventsRequest};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(30);

/// Speaks plain HTTP, so a TLS client fails on a real rustls error.
async fn listener_without_tls() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            stream.write_all(b"HTTP/1.1 400 not tls\r\n\r\n").await.ok();
        }
    });
    addr
}

/// A plain-HTTP server that fails the numbered requests `plan` picks with a real TLS
/// failure, by redirecting them to `listener_without_tls`. One run can then go from
/// failing to working and back, which needs no certificate.
#[derive(Clone)]
struct Scripted {
    plan: fn(usize) -> bool,
    tls_target: std::net::SocketAddr,
    requests: Arc<AtomicUsize>,
}

impl Scripted {
    async fn start(plan: fn(usize) -> bool) -> (String, Arc<AtomicUsize>) {
        let requests = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/v1/events", post(accept_batch))
            .route("/v1/policy", get(no_policy))
            .route("/v1/rule-packs", get(no_policy))
            .with_state(Self {
                plan,
                tls_target: listener_without_tls().await,
                requests: requests.clone(),
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), requests)
    }

    fn tls_failure(&self) -> Option<Response> {
        let request = self.requests.fetch_add(1, Ordering::SeqCst);
        (self.plan)(request).then(|| {
            let target = format!("https://{}/", self.tls_target);
            (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, target)]).into_response()
        })
    }
}

async fn no_policy(State(server): State<Scripted>) -> Response {
    server.tls_failure().unwrap_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no_policy"})),
        )
            .into_response()
    })
}

async fn accept_batch(
    State(server): State<Scripted>,
    Json(batch): Json<EventsRequest>,
) -> Response {
    server.tls_failure().unwrap_or_else(|| {
        let ids: Vec<_> = batch.events.iter().map(|e| e.event_id).collect();
        Json(EventsAccepted {
            high_water_event_id: *ids.last().unwrap(),
            accepted: ids,
            rejected: Vec::new(),
        })
        .into_response()
    })
}

fn config(dir: &Path, server_base_url: String) -> SenderConfig {
    let events = dir.join("events");
    std::fs::create_dir(&events).unwrap();
    SenderConfig {
        server_base_url,
        client_cert_path: None,
        client_key_path: None,
        server_ca_path: None,
        events_dir: events,
        offset_path: dir.join("sender-offset.json"),
        agent_control: dir.join("control.sock"),
        dead_letter_dir: dir.join("dead-letter"),
        max_batch_events: 1,
        max_batch_bytes: 1024 * 1024,
        policy_poll_interval: Duration::from_millis(20),
        host_id: None,
    }
}

fn write_events(dir: &Path, count: u128) {
    let lines: String = (1..=count)
        .map(|n| {
            let id = uuid::Uuid::from_u128(n);
            format!("{{\"event_id\":\"{id}\",\"payload\":\"a\"}}\n")
        })
        .collect();
    std::fs::write(dir.join("events/events-1.jsonl"), lines).unwrap();
}

/// Every dead-letter event on disk, from every day's file.
fn dead_letters(dir: &Path) -> Vec<serde_json::Value> {
    let Ok(files) = std::fs::read_dir(dir.join("dead-letter")) else {
        return Vec::new();
    };
    files
        .map(|file| std::fs::read_to_string(file.unwrap().path()).unwrap())
        .flat_map(|text| {
            text.lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect::<Vec<_>>()
        })
        .collect()
}

async fn until(what: &str, done: impl Fn() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

fn start_sender(
    config: SenderConfig,
    shutdown: &CancellationToken,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    tokio::spawn(run(RuntimeCtx {
        config,
        host_id: "h".into(),
        agent_version: "1".into(),
        sender_version: "1".into(),
        shutdown: shutdown.clone(),
    }))
}

#[tokio::test]
async fn a_tls_failure_on_each_plane_stores_its_cause_and_no_part_of_the_url() {
    let addr = listener_without_tls().await;
    let dir = tempfile::tempdir().unwrap();
    let config = config(
        dir.path(),
        format!("https://u:s3cret@{addr}/base?token=t0ken"),
    );
    write_events(dir.path(), 1);
    let shutdown = CancellationToken::new();
    let sender = start_sender(config, &shutdown);
    until("one event from each plane", || {
        dead_letters(dir.path()).len() >= 2
    })
    .await;
    shutdown.cancel();
    sender.await.unwrap().unwrap();

    for letter in dead_letters(dir.path()) {
        let text = letter.to_string();
        for leak in ["s3cret", "t0ken", "/base", "/v1/", "127.0.0.1", "https"] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
        let reason = letter.pointer("/evidence/reason");
        assert!(
            reason.is_some_and(|r| r.as_str().unwrap().contains("InvalidContentType")),
            "no cause in {text}"
        );
    }
}

#[tokio::test]
async fn policy_tls_failures_write_one_event_per_streak() {
    let (url, requests) = Scripted::start(|n| !(40..50).contains(&n)).await;
    let dir = tempfile::tempdir().unwrap();
    let shutdown = CancellationToken::new();
    let sender = start_sender(config(dir.path(), url), &shutdown);

    until("a long first streak", || {
        requests.load(Ordering::SeqCst) >= 40
    })
    .await;
    assert_eq!(dead_letters(dir.path()).len(), 1);

    until("a success and a long second streak", || {
        requests.load(Ordering::SeqCst) >= 90
    })
    .await;
    shutdown.cancel();
    sender.await.unwrap().unwrap();
    assert_eq!(dead_letters(dir.path()).len(), 2);
}

/// Real backoff, so it takes 15 seconds: failures at 0s and 5s, a success at 15s, then
/// the next batch fails at once.
#[tokio::test]
async fn event_tls_failures_write_one_event_per_streak() {
    let (url, requests) = Scripted::start(|n| n != 2).await;
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path(), url);
    write_events(dir.path(), 2);
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(data_task::run(DataTaskCtx {
        client: reqwest::Client::new(),
        config,
        host_id: "h".into(),
        agent_version: "1".into(),
        sender_version: "1".into(),
        stats: heartbeat::shared(),
        shutdown: shutdown.clone(),
    }));

    until("the failure after the success", || {
        requests.load(Ordering::SeqCst) >= 4 && !dead_letters(dir.path()).is_empty()
    })
    .await;
    shutdown.cancel();
    task.await.unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 4);
    assert_eq!(dead_letters(dir.path()).len(), 2);
}
