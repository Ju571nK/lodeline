//! E2E for `data_task::run` (B11.x wiring): the loop reads JSONL,
//! ships, applies the ack to disk, dead-letters per-event rejections,
//! and updates SharedStats.

mod common;

use lodeline_core::sender_status::{Contact, LinkFailure};
use lodeline_sender::config::SenderConfig;
use lodeline_sender::data_task::{self, DataTaskCtx};
use lodeline_sender::heartbeat;
use lodeline_sender::state::{self, SenderState};
use lodeline_sender::wire::EventRejection;
use std::io::Write;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn write_jsonl(dir: &std::path::Path, name: &str, lines: &[(Uuid, &str)]) {
    let mut f = std::fs::File::create(dir.join(name)).unwrap();
    for (id, body) in lines {
        let line = format!(r#"{{"event_id":"{id}","payload":{body}}}"#);
        writeln!(f, "{line}").unwrap();
    }
}

fn cfg(events_dir: &std::path::Path, state_dir: &std::path::Path, addr: &str) -> SenderConfig {
    SenderConfig {
        server_base_url: format!("http://{addr}"),
        client_cert_path: Some(state_dir.join("client.crt")),
        client_key_path: Some(state_dir.join("client.key")),
        server_ca_path: Some(state_dir.join("server-ca.pem")),
        events_dir: events_dir.to_path_buf(),
        offset_path: state_dir.join("sender-offset.json"),
        agent_control: state_dir.join("control.sock"),
        dead_letter_dir: state_dir.join("dead-letter"),
        max_batch_events: 256,
        max_batch_bytes: 1024 * 1024,
        policy_poll_interval: Duration::from_secs(60),
        host_id: None,
    }
}

async fn wait_until_offset_at_least(
    offset_path: &std::path::Path,
    target_seq: u64,
    timeout: Duration,
) -> Option<SenderState> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(Some(s)) = state::load(offset_path) {
            if s.last_acked_sequence >= target_seq {
                return Some(s);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

#[tokio::test]
async fn happy_path_advances_offset_and_updates_stats() {
    let (addr, _mock) = common::spawn_mock().await;
    let events = tempfile::tempdir().unwrap();
    let state_dir = tempfile::tempdir().unwrap();
    let id_a = Uuid::from_u128(1);
    let id_b = Uuid::from_u128(2);
    write_jsonl(
        events.path(),
        "events-1.jsonl",
        &[(id_a, r#""a""#), (id_b, r#""b""#)],
    );

    let stats = heartbeat::shared();
    let cancel = CancellationToken::new();
    let ctx = DataTaskCtx {
        client: reqwest::Client::new(),
        config: cfg(events.path(), state_dir.path(), &addr.to_string()),
        host_id: "h-1".into(),
        agent_version: "0.2.0".into(),
        sender_version: "0.2.0".into(),
        stats: stats.clone(),
        shutdown: cancel.clone(),
    };
    let handle = tokio::spawn(data_task::run(ctx));

    let final_state = wait_until_offset_at_least(
        &state_dir.path().join("sender-offset.json"),
        2,
        Duration::from_secs(5),
    )
    .await
    .expect("offset never advanced to seq 2");
    cancel.cancel();
    let _ = handle.await;

    assert_eq!(final_state.last_acked_sequence, 2);
    let bytes_on_disk = std::fs::metadata(events.path().join("events-1.jsonl"))
        .unwrap()
        .len();
    assert_eq!(final_state.byte_offset, bytes_on_disk);
    assert_eq!(final_state.current_file, "events-1.jsonl");

    assert!(matches!(
        stats.read().contact(),
        lodeline_core::sender_status::Contact::Reached { .. }
    ));
}

#[tokio::test]
async fn rejected_events_go_to_dead_letter_and_offset_still_advances() {
    let (addr, mock) = common::spawn_mock().await;
    let events = tempfile::tempdir().unwrap();
    let state_dir = tempfile::tempdir().unwrap();
    let id_a = Uuid::from_u128(11);
    let id_b = Uuid::from_u128(22);
    write_jsonl(
        events.path(),
        "events-1.jsonl",
        &[(id_a, r#""a""#), (id_b, r#""b""#)],
    );
    // Mock rejects id_b for next batch.
    {
        let mut s = mock.lock().await;
        s.next_rejected = vec![EventRejection {
            event_id: id_b,
            reason: "schema_mismatch".into(),
            detail: None,
        }];
    }

    let stats = heartbeat::shared();
    let cancel = CancellationToken::new();
    let dead_letter_dir = state_dir.path().join("dead-letter");
    let ctx = DataTaskCtx {
        client: reqwest::Client::new(),
        config: cfg(events.path(), state_dir.path(), &addr.to_string()),
        host_id: "h-1".into(),
        agent_version: "0.2.0".into(),
        sender_version: "0.2.0".into(),
        stats: stats.clone(),
        shutdown: cancel.clone(),
    };
    let handle = tokio::spawn(data_task::run(ctx));

    let final_state = wait_until_offset_at_least(
        &state_dir.path().join("sender-offset.json"),
        2,
        Duration::from_secs(5),
    )
    .await
    .expect("offset never advanced");
    cancel.cancel();
    let _ = handle.await;

    // High-water is id_b regardless of rejection — sequence still advances to 2.
    assert_eq!(final_state.last_acked_sequence, 2);

    // Dead-letter should contain exactly one EventUnprocessableLocal entry.
    let dl_files: Vec<_> = std::fs::read_dir(&dead_letter_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("sender-dead-letter-")
        })
        .collect();
    assert_eq!(dl_files.len(), 1);
    let body = std::fs::read_to_string(dl_files[0].path()).unwrap();
    assert_eq!(body.matches('\n').count(), 1);
    assert!(body.contains("event_unprocessable_local"));
    assert!(body.contains("schema_mismatch"));
    assert!(body.contains(&id_b.to_string()));
}

/// Real backoff, so it takes 5 seconds.
#[tokio::test]
async fn an_ack_outside_the_batch_is_a_failure_that_keeps_its_start_and_waits() {
    let (addr, mock) = common::spawn_mock().await;
    mock.lock().await.foreign_high_water = true;
    let events = tempfile::tempdir().unwrap();
    let state_dir = tempfile::tempdir().unwrap();
    write_jsonl(
        events.path(),
        "events-1.jsonl",
        &[(Uuid::from_u128(1), r#""a""#)],
    );

    let stats = heartbeat::shared();
    let cancel = CancellationToken::new();
    let ctx = DataTaskCtx {
        client: reqwest::Client::new(),
        config: cfg(events.path(), state_dir.path(), &addr.to_string()),
        host_id: "h-1".into(),
        agent_version: "0.2.0".into(),
        sender_version: "0.2.0".into(),
        stats: stats.clone(),
        shutdown: cancel.clone(),
    };
    let handle = tokio::spawn(data_task::run(ctx));

    let failing_since = || match stats.read().contact() {
        Contact::Failing {
            since,
            failure: LinkFailure::Protocol,
            last_ok_at,
        } => Some((since, last_ok_at)),
        _ => None,
    };
    let start = Instant::now();
    while failing_since().is_none() || mock.lock().await.received_batches.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "never failed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let first = Instant::now();
    let (since, last_ok_at) = failing_since().unwrap();
    // The backoff is 5s, so no second batch may arrive in the next second.
    while first.elapsed() < Duration::from_secs(1) {
        assert_eq!(
            mock.lock().await.received_batches.len(),
            1,
            "retried at once"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    while mock.lock().await.received_batches.len() < 2 {
        assert!(first.elapsed() < Duration::from_secs(10), "never retried");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel.cancel();
    let _ = handle.await;

    assert_eq!(last_ok_at, None);
    assert_eq!(failing_since(), Some((since, None)));
}

#[tokio::test]
async fn discovers_first_segment_when_state_empty() {
    let (addr, _mock) = common::spawn_mock().await;
    let events = tempfile::tempdir().unwrap();
    let state_dir = tempfile::tempdir().unwrap();
    // No prior state; agent has produced one segment.
    write_jsonl(
        events.path(),
        "events-2026-05-11-001.jsonl",
        &[(Uuid::from_u128(7), r#""x""#)],
    );

    let stats = heartbeat::shared();
    let cancel = CancellationToken::new();
    let ctx = DataTaskCtx {
        client: reqwest::Client::new(),
        config: cfg(events.path(), state_dir.path(), &addr.to_string()),
        host_id: "h-1".into(),
        agent_version: "0.2.0".into(),
        sender_version: "0.2.0".into(),
        stats: stats.clone(),
        shutdown: cancel.clone(),
    };
    let handle = tokio::spawn(data_task::run(ctx));

    let s = wait_until_offset_at_least(
        &state_dir.path().join("sender-offset.json"),
        1,
        Duration::from_secs(5),
    )
    .await
    .expect("never advanced past discovered segment");
    cancel.cancel();
    let _ = handle.await;
    assert_eq!(s.current_file, "events-2026-05-11-001.jsonl");
}
