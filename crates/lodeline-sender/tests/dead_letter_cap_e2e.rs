//! A server controls the text that lands in the dead-letter directory, so that text has a cap.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use lodeline_sender::config::SenderConfig;
use lodeline_sender::runtime::{run, RuntimeCtx};
use lodeline_sender::transport::MAX_STORED_SERVER_TEXT;
use lodeline_sender::wire::{EventRejection, EventsAccepted, EventsRequest};
use std::path::Path;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(30);
/// Server text of 100 KiB, in two-byte characters so a cut can land inside one.
fn huge() -> String {
    "é".repeat(50 * 1024)
}

#[derive(Clone, Copy)]
enum Events {
    Status(StatusCode),
    RejectsOne,
}

async fn events(State(mode): State<Events>, Json(batch): Json<EventsRequest>) -> Response {
    match mode {
        Events::Status(status) => (status, huge()).into_response(),
        Events::RejectsOne => {
            let id = batch.events[0].event_id;
            Json(EventsAccepted {
                accepted: Vec::new(),
                rejected: vec![EventRejection {
                    event_id: id,
                    reason: huge(),
                    detail: None,
                }],
                high_water_event_id: id,
            })
            .into_response()
        }
    }
}

async fn policy() -> Response {
    (StatusCode::IM_A_TEAPOT, huge()).into_response()
}

fn dead_letters(dir: &Path) -> Vec<String> {
    let Ok(files) = std::fs::read_dir(dir.join("dead-letter")) else {
        return Vec::new();
    };
    files
        .flat_map(|f| {
            let text = std::fs::read_to_string(f.unwrap().path()).unwrap();
            text.lines().map(str::to_owned).collect::<Vec<_>>()
        })
        .collect()
}

/// Runs a sender until `done` holds for the dead letters, and returns them.
async fn sender_against(
    mode: Events,
    done: impl Fn(&[String]) -> bool,
    policy_status_is_error: bool,
) -> Vec<String> {
    let mut app = Router::new()
        .route("/v1/events", post(events))
        .route("/v1/rule-packs", get(|| async { StatusCode::NOT_FOUND }));
    app = if policy_status_is_error {
        app.route("/v1/policy", get(policy))
    } else {
        app.route("/v1/policy", get(|| async { StatusCode::NOT_MODIFIED }))
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app.with_state(mode)).await.unwrap() });

    let dir = tempfile::tempdir().unwrap();
    let events_dir = dir.path().join("events");
    std::fs::create_dir(&events_dir).unwrap();
    let id = uuid::Uuid::from_u128(1);
    std::fs::write(
        events_dir.join("events-1.jsonl"),
        format!("{{\"event_id\":\"{id}\",\"payload\":\"a\"}}\n"),
    )
    .unwrap();
    let config = SenderConfig {
        server_base_url: format!("http://{addr}"),
        client_cert_path: None,
        client_key_path: None,
        server_ca_path: None,
        events_dir,
        offset_path: dir.path().join("sender-offset.json"),
        agent_control: dir.path().join("control.sock"),
        dead_letter_dir: dir.path().join("dead-letter"),
        max_batch_events: 1,
        max_batch_bytes: 1024 * 1024,
        policy_poll_interval: Duration::from_millis(50),
        host_id: None,
    };
    let shutdown = CancellationToken::new();
    let sender = tokio::spawn(run(RuntimeCtx {
        config,
        host_id: "h".into(),
        agent_version: "1".into(),
        sender_version: "1".into(),
        shutdown: shutdown.clone(),
    }));
    tokio::time::timeout(WAIT, async {
        while !done(&dead_letters(dir.path())) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the expected dead letter never arrived");
    shutdown.cancel();
    sender.await.unwrap().unwrap();
    dead_letters(dir.path())
}

fn assert_capped(letters: &[String]) {
    for letter in letters {
        // The cap, its marker, and the event around the text.
        assert!(
            letter.len() < MAX_STORED_SERVER_TEXT + 1024,
            "{}",
            letter.len()
        );
    }
}

fn detail_starts_with(letter: &str, prefix: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(letter)
        .unwrap()
        .pointer("/evidence/detail")
        .and_then(|d| d.as_str())
        .is_some_and(|d| d.starts_with(prefix))
}

#[tokio::test]
async fn an_unexpected_status_on_each_plane_stores_capped_text() {
    let letters = sender_against(
        Events::Status(StatusCode::IM_A_TEAPOT),
        |l| {
            l.iter()
                .any(|x| detail_starts_with(x, "unexpected status 418"))
                && l.iter().any(|x| detail_starts_with(x, "status 418"))
        },
        true,
    )
    .await;
    assert_capped(&letters);
}

#[tokio::test]
async fn a_2xx_without_a_parseable_body_stores_capped_text() {
    let letters = sender_against(
        Events::Status(StatusCode::OK),
        |l| {
            l.iter()
                .any(|x| detail_starts_with(x, "2xx without parseable body"))
        },
        false,
    )
    .await;
    assert_capped(&letters);
}

#[tokio::test]
async fn a_permanent_reject_stores_capped_text() {
    let letters = sender_against(
        Events::Status(StatusCode::CONFLICT),
        |l| {
            l.iter()
                .any(|x| detail_starts_with(x, "batch rejected status=409"))
        },
        false,
    )
    .await;
    assert_capped(&letters);
}

#[tokio::test]
async fn a_per_event_rejection_reason_is_capped() {
    let letters = sender_against(
        Events::RejectsOne,
        |l| l.iter().any(|x| x.contains("event_unprocessable_local")),
        false,
    )
    .await;
    assert_capped(&letters);
}
