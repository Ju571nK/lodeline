//! APFS keeps a name in the normalization form it was created with and
//! FSEvents reports those bytes, while policy templates are usually NFC (#388).
#![cfg(target_os = "macos")]

mod common;
use common::{policy_for_paths, TestAgentBuilder};
use std::path::{Path, PathBuf};
use std::time::Duration;

const HAN_NFC: &str = "\u{D55C}\u{AE00}";
const HAN_NFD: &str = "\u{1112}\u{1161}\u{11AB}\u{1100}\u{1173}\u{11AF}";

/// The first `file_change` event for `stored` under a policy on `template`.
async fn first_change(stored: &Path, template: &Path) -> serde_json::Value {
    let policy = policy_for_paths(&[template.to_str().unwrap()], "critical");
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    // A write in the watcher's startup gap is lost for good, so keep writing
    // until one is seen (#108). Only the first event proves the warmup
    // baseline: each later one reads the baseline the event before committed.
    let target = stored.to_path_buf();
    let writer = tokio::spawn(async move {
        let mut n: u64 = 0;
        loop {
            n += 1;
            let _ = std::fs::write(&target, n.to_string());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let observed = agent
        .wait_for_event(
            |v| v["evidence"]["kind"] == "file_change",
            common::fs_event_timeout(),
        )
        .await;
    writer.abort();
    agent.join.abort();
    observed.expect("a write to the NFD-stored path was not reported")
}

fn canonical_dir(dir: &tempfile::TempDir) -> PathBuf {
    std::fs::canonicalize(dir.path()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nfd_stored_file_keeps_its_baseline_under_an_nfc_policy_path() {
    let dir = tempfile::tempdir().unwrap();
    let stored = dir.path().join(format!("{HAN_NFD}.json"));
    std::fs::write(&stored, b"before").unwrap();
    let event = first_change(&stored, &dir.path().join(format!("{HAN_NFC}.json"))).await;
    assert!(
        event["evidence"]["before_hash"].is_string(),
        "warmup baseline not found for the event path: {event}"
    );
    let nfc = canonical_dir(&dir).join(format!("{HAN_NFC}.json"));
    assert_eq!(event["subject"]["value"], nfc.to_str().unwrap(), "{event}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nfd_stored_directory_keeps_its_baseline_under_an_nfc_policy_path() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(HAN_NFD)).unwrap();
    let stored = dir.path().join(HAN_NFD).join("config.json");
    std::fs::write(&stored, b"before").unwrap();
    let event = first_change(&stored, &dir.path().join(HAN_NFC).join("config.json")).await;
    assert!(
        event["evidence"]["before_hash"].is_string(),
        "warmup baseline not found for the event path: {event}"
    );
    let nfc = canonical_dir(&dir).join(HAN_NFC).join("config.json");
    assert_eq!(event["subject"]["value"], nfc.to_str().unwrap(), "{event}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nfc_glob_matches_an_nfd_stored_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let stored = dir.path().join(format!("{HAN_NFD}.json"));
    std::fs::write(&stored, b"before").unwrap();
    let event = first_change(&stored, &dir.path().join("\u{D55C}*.json")).await;
    let nfc = canonical_dir(&dir).join(format!("{HAN_NFC}.json"));
    assert_eq!(event["subject"]["value"], nfc.to_str().unwrap(), "{event}");
}
