//! A transport error while reading a response body is a network failure, whether the
//! server stalls or drops the connection. A body that arrives but does not parse is a
//! protocol violation.

use lodeline_sender::control_task::{poll_policy, poll_rule_packs, PollOutcome};
use lodeline_sender::data_task::{send_one_batch, BatchOutcome, BatchSendCtx};
use lodeline_sender::transport::build_client_with_timeouts;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy)]
enum Body {
    /// Headers promise 1000 bytes, 10 arrive, then the server holds the connection.
    Stalls,
    /// Headers promise 1000 bytes, 10 arrive, then the server closes.
    Drops,
    /// A complete body that is not valid JSON.
    NotJson,
}

/// Serves every request with `status` and `body`, and returns the base URL.
async fn serve(status: &str, body: Body) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let status = status.to_owned();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0; 64 * 1024];
            let _ = stream.read(&mut buf).await;
            let reply = match body {
                Body::NotJson => format!(
                    "HTTP/1.1 {status}\r\ncontent-length: 8\r\nconnection: close\r\n\r\nnot json"
                ),
                Body::Stalls | Body::Drops => format!(
                    "HTTP/1.1 {status}\r\ncontent-length: 1000\r\nconnection: close\r\n\r\n0123456789"
                ),
            };
            stream.write_all(reply.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            if matches!(body, Body::Stalls) {
                held.push(stream);
            }
        }
    });
    format!("http://{addr}")
}

fn client() -> reqwest::Client {
    let short = Duration::from_millis(300);
    build_client_with_timeouts(short, short, None, None, None).unwrap()
}

async fn events(status: &str, body: Body) -> BatchOutcome {
    let url = serve(status, body).await;
    let client = client();
    tokio::time::timeout(
        Duration::from_secs(5),
        send_one_batch(BatchSendCtx {
            client: &client,
            server_base_url: &url,
            host_id: "h",
            agent_version: "1",
            sender_version: "1",
            events: Vec::new(),
        }),
    )
    .await
    .expect("the request was still open after 5 seconds")
}

async fn policy(status: &str, body: Body) -> PollOutcome {
    let url = serve(status, body).await;
    tokio::time::timeout(
        Duration::from_secs(5),
        poll_policy(&client(), &url, "h", None),
    )
    .await
    .expect("the request was still open after 5 seconds")
}

async fn rule_packs(status: &str, body: Body) -> PollOutcome {
    let url = serve(status, body).await;
    tokio::time::timeout(
        Duration::from_secs(5),
        poll_rule_packs(&client(), &url, "h", None),
    )
    .await
    .expect("the request was still open after 5 seconds")
}

#[tokio::test]
async fn events_body_that_stalls_or_drops_is_a_network_failure() {
    for body in [Body::Stalls, Body::Drops] {
        for status in ["200 OK", "503 Service Unavailable", "418 I'm a teapot"] {
            let outcome = events(status, body).await;
            assert!(
                matches!(outcome, BatchOutcome::Network(_)),
                "{status}: {outcome:?}"
            );
        }
    }
}

#[tokio::test]
async fn policy_body_that_stalls_or_drops_is_a_network_failure() {
    for body in [Body::Stalls, Body::Drops] {
        for status in ["200 OK", "404 Not Found", "418 I'm a teapot"] {
            let outcome = policy(status, body).await;
            assert!(
                matches!(outcome, PollOutcome::Network(_)),
                "{status}: {outcome:?}"
            );
        }
    }
}

#[tokio::test]
async fn rule_packs_body_that_stalls_or_drops_is_a_network_failure() {
    for body in [Body::Stalls, Body::Drops] {
        for status in ["200 OK", "418 I'm a teapot"] {
            let outcome = rule_packs(status, body).await;
            assert!(
                matches!(outcome, PollOutcome::Network(_)),
                "{status}: {outcome:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_body_that_arrives_and_does_not_parse_is_a_protocol_violation() {
    let outcome = events("200 OK", Body::NotJson).await;
    assert!(
        matches!(
            outcome,
            BatchOutcome::ProtocolViolation { status: None, .. }
        ),
        "{outcome:?}"
    );
    let outcome = policy("200 OK", Body::NotJson).await;
    assert!(
        matches!(outcome, PollOutcome::ProtocolViolation { status: None, .. }),
        "{outcome:?}"
    );
    let outcome = rule_packs("200 OK", Body::NotJson).await;
    assert!(
        matches!(outcome, PollOutcome::ProtocolViolation { status: None, .. }),
        "{outcome:?}"
    );
}
