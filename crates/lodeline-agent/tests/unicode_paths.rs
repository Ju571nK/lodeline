//! APFS keeps a name in the normalization form it was created with and
//! FSEvents reports those bytes, while policy templates are usually NFC (#388).
#![cfg(target_os = "macos")]

mod common;
use common::{policy_for_paths, TestAgentBuilder};

const HAN_NFC: &str = "\u{D55C}\u{AE00}";
const HAN_NFD: &str = "\u{1112}\u{1161}\u{11AB}\u{1100}\u{1173}\u{11AF}";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nfd_stored_file_keeps_its_baseline_under_an_nfc_policy_path() {
    let dir = tempfile::tempdir().unwrap();
    let stored = dir.path().join(format!("{HAN_NFD}.json"));
    std::fs::write(&stored, b"before").unwrap();
    let template = dir.path().join(format!("{HAN_NFC}.json"));
    let policy = policy_for_paths(&[template.to_str().unwrap()], "critical");
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    std::fs::write(&stored, b"after").unwrap();
    let observed = agent
        .wait_for_event(
            |v| v["evidence"]["kind"] == "file_change",
            common::fs_event_timeout(),
        )
        .await;
    agent.join.abort();
    let event = observed.expect("modify on the NFD-stored file was not reported");
    assert!(
        event["evidence"]["before_hash"].is_string(),
        "warmup baseline not found for the event path: {event}"
    );
}
