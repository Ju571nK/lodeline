//! What a failing sender leaves in the dead-letter directory, which has no rotation.

use lodeline_sender::config::SenderConfig;
use lodeline_sender::runtime::{run, RuntimeCtx};
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(10);

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

fn config(dir: &Path, server_base_url: String) -> SenderConfig {
    let events = dir.join("events");
    std::fs::create_dir(&events).unwrap();
    let id = uuid::Uuid::from_u128(1);
    std::fs::write(
        events.join("events-1.jsonl"),
        format!("{{\"event_id\":\"{id}\",\"payload\":\"a\"}}\n"),
    )
    .unwrap();
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

#[tokio::test]
async fn a_tls_failure_on_each_plane_stores_its_cause_and_no_part_of_the_url() {
    let addr = listener_without_tls().await;
    let dir = tempfile::tempdir().unwrap();
    let shutdown = CancellationToken::new();
    let sender = tokio::spawn(run(RuntimeCtx {
        config: config(
            dir.path(),
            format!("https://u:s3cret@{addr}/base?token=t0ken"),
        ),
        host_id: "h".into(),
        agent_version: "1".into(),
        sender_version: "1".into(),
        shutdown: shutdown.clone(),
    }));
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
