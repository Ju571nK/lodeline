//! Crash test for the durable spool (T-14a): a child process appends in a loop
//! and prints each sequence only after `append` returned. The parent SIGKILLs it
//! mid-append, reopens the database and checks that no acknowledged event is
//! lost and no partial row exists.
//!
//! Scope: SIGKILL of a process proves atomic commit and sequence continuity
//! across a crash. It does NOT prove power-loss durability (the OS page cache
//! survives a process kill); that needs hardware verification.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use lodeline_proxy::ingest_client::EventSource;
use lodeline_proxy::limits::Limits;
use lodeline_proxy::spool::{Spool, SpoolConfig};
use lodeline_proxy_api::ProxyEvent;
use serde_json::json;

const EPOCH: &str = "00000000-0000-4000-8000-000000005000";
const DIR_ENV: &str = "LODELINE_SPOOL_CRASH_DIR";

fn uid(n: u64) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

fn event(n: u64) -> ProxyEvent {
    serde_json::from_value(json!({
        "schema_version": 1, "event_id": uid(n), "proxy_id": "px-1",
        "epoch_id": EPOCH, "sequence": 1,
        "occurred_at": "2026-10-14T00:00:00Z",
        "event_type": "invocation.started",
        "payload": {"invocation_id": uid(900_000 + n), "upstream_id": "up-1",
            "route_revision": 1, "protocol_version": "2025-11-25", "method": "ping",
            "actor": {"actor_id": "a1", "actor_kind": "non_human",
                "authentication_method": "bearer",
                "evidence_source": "proxy_credential_mapping"}}
    }))
    .unwrap()
}

fn open(dir: &std::path::Path) -> Spool {
    Spool::open(SpoolConfig::new(
        dir,
        "px-1",
        EPOCH,
        true,
        &Limits::default(),
    ))
    .unwrap()
}

/// Runs only as the child of `kill_mid_append_loses_no_acked_event`.
#[test]
fn crash_child() {
    let Ok(dir) = std::env::var(DIR_ENV) else {
        return;
    };
    let s = open(std::path::Path::new(&dir));
    let start = s.snapshot().last_assigned_sequence as u64;
    let out = std::io::stdout();
    for n in (start + 1)..(start + 100_000) {
        let a = s.append(event(n)).expect("append");
        let mut o = out.lock();
        writeln!(o, "ACK {}", a.sequence).unwrap();
        o.flush().unwrap();
    }
}

#[test]
fn kill_mid_append_loses_no_acked_event() {
    let dir = tempfile::tempdir().unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut max_acked = 0i64;
    for round in 0..3usize {
        let mut child = Command::new(&exe)
            .args(["--exact", "crash_child", "--nocapture", "--test-threads=1"])
            .env(DIR_ENV, dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut acked: Vec<i64> = Vec::new();
        let rd = BufReader::new(child.stdout.take().unwrap());
        for line in rd.lines() {
            let line = line.unwrap();
            // The harness prints "test name ... " without a newline first.
            if let Some(i) = line.find("ACK ") {
                acked.push(line[i + 4..].trim().parse().unwrap());
                if acked.len() >= 40 + round * 10 {
                    break;
                }
            }
        }
        // SIGKILL while the child is inside its append loop.
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(acked.len() >= 40, "child produced too few acks");
        assert!(acked.windows(2).all(|w| w[1] == w[0] + 1));
        assert_eq!(acked[0], max_acked + 1, "round continues the sequence");
        max_acked = *acked.last().unwrap();

        let mut s = open(dir.path());
        let snap = s.snapshot();
        // Every acked event is durable; the one in flight at the kill (and a few
        // more printed-but-unread lines) may or may not be.
        assert!(snap.last_assigned_sequence >= max_acked);
        let mut all: Vec<ProxyEvent> = Vec::new();
        loop {
            let skip: HashSet<String> = all
                .iter()
                .map(|e| e.event_id.as_str().to_string())
                .collect();
            let batch = s.next_events(500, &skip);
            if batch.is_empty() {
                break;
            }
            all.extend(batch);
        }
        // No gap and no partial row: exactly 1..=last, every row parses.
        let seqs: Vec<i64> = all.iter().map(|e| e.sequence.get()).collect();
        let want: Vec<i64> = (1..=snap.last_assigned_sequence).collect();
        assert_eq!(seqs, want);
        // The next round continues after everything that survived.
        max_acked = snap.last_assigned_sequence;
    }
}
