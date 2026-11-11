//! `lodeline-sender start` logs to stderr, at `info` unless `RUST_LOG` sets another level (#560).

use lodeline_sender::config::SenderConfig;
use lodeline_sender::dead_letter::MAX_FILES;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const INFO_LINE: &str = "pruned old dead-letter files";
const WARN_LINE: &str = "no client_cert_path configured";

/// Answers every request with a bare 404, which the policy poll reads as an
/// unknown host and records in a new dead-letter file.
fn spawn_unknown_host_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
            }
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            );
        }
    });
    url
}

fn oldest_seeded(dead_letter: &Path) -> std::path::PathBuf {
    dead_letter.join("sender-dead-letter-2000-01-01.jsonl")
}

/// Runs `start` until the first new dead-letter file makes it prune the oldest
/// of `MAX_FILES` seeded ones, which it logs at `info`. Returns its stderr.
fn log_through_prune(server_base_url: &str, rust_log: Option<&str>) -> String {
    let dir = tempfile::tempdir().unwrap();
    let events = dir.path().join("events");
    let dead_letter = dir.path().join("dead-letter");
    std::fs::create_dir(&events).unwrap();
    std::fs::create_dir(&dead_letter).unwrap();
    for day in 1..=MAX_FILES {
        std::fs::write(
            dead_letter.join(format!("sender-dead-letter-2000-01-{day:02}.jsonl")),
            "",
        )
        .unwrap();
    }
    let config = SenderConfig {
        server_base_url: server_base_url.to_owned(),
        client_cert_path: None,
        client_key_path: None,
        server_ca_path: None,
        events_dir: events,
        offset_path: dir.path().join("state/sender-offset.json"),
        agent_control: dir.path().join("control.sock"),
        dead_letter_dir: dead_letter.clone(),
        max_batch_events: 256,
        max_batch_bytes: 1024 * 1024,
        policy_poll_interval: Duration::from_secs(1),
        host_id: Some(uuid::Uuid::from_u128(1).to_string()),
        renew_client_cert: false,
    };
    let config_path = dir.path().join("sender.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lodeline-sender"));
    cmd.arg("--config")
        .arg(&config_path)
        .arg("start")
        .env_remove("RUST_LOG")
        .env_remove("LODELINE_HOST_ID")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(level) = rust_log {
        cmd.env("RUST_LOG", level);
    }
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while oldest_seeded(&dead_letter).exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    // The log line follows the removal in the same call.
    std::thread::sleep(Duration::from_millis(500));
    child.kill().unwrap();
    child.wait().unwrap();
    let mut log = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();
    assert!(
        !oldest_seeded(&dead_letter).exists(),
        "RUST_LOG={rust_log:?}: the sender never pruned a dead-letter file:\n{log}"
    );
    assert!(
        log.contains(WARN_LINE),
        "RUST_LOG={rust_log:?}: no startup warning on stderr:\n{log}"
    );
    log
}

#[test]
fn start_logs_info_by_default_and_rust_log_overrides_it() {
    let url = spawn_unknown_host_server();

    let default = log_through_prune(&url, None);
    assert!(
        default.contains(INFO_LINE),
        "no info line without RUST_LOG:\n{default}"
    );

    let warn = log_through_prune(&url, Some("warn"));
    assert!(
        !warn.contains(INFO_LINE),
        "RUST_LOG=warn kept an info line:\n{warn}"
    );
}
