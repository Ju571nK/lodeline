#![cfg(unix)]

mod common;
use common::{fs_event_timeout, policy_for_paths, TestAgent, TestAgentBuilder};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn isolated_policy(file: &Path) -> String {
    let mut yaml = policy_for_paths(&[file.to_str().unwrap()], "standard");
    yaml.push_str("overrides:\n");
    for target in lodeline_core::policy::defaults().unwrap().targets {
        yaml.push_str(&format!("  - id: {}\n    disabled: true\n", target.id));
    }
    yaml
}

/// `home/.claude/settings.json` linked to `dotfiles/settings.json`. Returns the
/// link, the target, and the link as the agent spells it.
fn linked_settings(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let dotfiles = root.join("dotfiles");
    let claude = root.join("home/.claude");
    std::fs::create_dir_all(&dotfiles).unwrap();
    std::fs::create_dir_all(&claude).unwrap();
    let target = dotfiles.join("settings.json");
    std::fs::write(&target, b"initial").unwrap();
    let link = claude.join("settings.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let spelled = dunce::canonicalize(&claude).unwrap().join("settings.json");
    (link, target, spelled)
}

fn changes_at(agent: &TestAgent, path: &Path) -> Vec<serde_json::Value> {
    agent
        .read_all_events()
        .into_iter()
        .filter(|e| {
            e["evidence"]["kind"] == "file_change"
                && e["subject"]["value"]
                    .as_str()
                    .is_some_and(|p| Path::new(p) == path)
        })
        .collect()
}

async fn wait_for_change(agent: &TestAgent, path: &Path, after_hash_not: Option<&str>) -> bool {
    agent
        .wait_for_event(
            |e| {
                e["evidence"]["kind"] == "file_change"
                    && e["subject"]["value"]
                        .as_str()
                        .is_some_and(|p| Path::new(p) == path)
                    && after_hash_not.is_none_or(|h| e["evidence"]["after_hash"] != h)
            },
            fs_event_timeout(),
        )
        .await
        .is_some()
}

/// Rewrite `file` until the test aborts the writer: a write that lands in the
/// watcher's startup gap is never replayed, so one write can be lost.
fn keep_writing(file: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut n = 0u64;
        loop {
            n += 1;
            let _ = std::fs::write(&file, format!("change-{n}"));
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
}

async fn writing_the_target_records_the_link_path(poll: bool) {
    let td = tempfile::tempdir().unwrap();
    let (link, target, spelled) = linked_settings(td.path());
    let agent = TestAgentBuilder::new()
        .policy(&isolated_policy(&link))
        .poll_watcher(poll)
        .start()
        .await;
    let writer = keep_writing(target);
    let seen = wait_for_change(&agent, &spelled, None).await;
    writer.abort();
    assert!(seen, "no file_change for {}", spelled.display());
    agent.join.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_write_to_the_target_records_the_link_path() {
    writing_the_target_records_the_link_path(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn polling_write_to_the_target_records_the_link_path() {
    writing_the_target_records_the_link_path(true).await;
}

async fn retarget_records_one_current_state_event(poll: bool) {
    let td = tempfile::tempdir().unwrap();
    let (link, target, spelled) = linked_settings(td.path());
    let agent = TestAgentBuilder::new()
        .policy(&isolated_policy(&link))
        .poll_watcher(poll)
        .start()
        .await;
    let writer = keep_writing(target);
    assert!(wait_for_change(&agent, &spelled, None).await);
    writer.abort();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let before = changes_at(&agent, &spelled);
    let old_hash = before.last().unwrap()["evidence"]["after_hash"]
        .as_str()
        .unwrap()
        .to_owned();

    let other = td.path().join("dotfiles/other.json");
    std::fs::write(&other, b"the second file").unwrap();
    let swap = link.with_file_name("swap");
    std::os::unix::fs::symlink(&other, &swap).unwrap();
    std::fs::rename(&swap, &link).unwrap();

    assert!(wait_for_change(&agent, &spelled, Some(&old_hash)).await);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(changes_at(&agent, &spelled).len(), before.len() + 1);
    agent.join.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_retarget_records_one_current_state_event() {
    retarget_records_one_current_state_event(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn polling_retarget_records_one_current_state_event() {
    retarget_records_one_current_state_event(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dangling_link_is_followed_once_its_target_exists() {
    let td = tempfile::tempdir().unwrap();
    let (link, target, spelled) = linked_settings(td.path());
    std::fs::remove_file(&target).unwrap();
    let agent = TestAgentBuilder::new()
        .policy(&isolated_policy(&link))
        .start()
        .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    std::fs::write(&target, b"now it exists").unwrap();
    assert!(wait_for_change(&agent, &spelled, None).await);
    assert!(!agent.join.is_finished(), "the agent stopped");
    agent.join.abort();
}

#[cfg(feature = "operator-cli")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_that_adds_a_linked_file_follows_it() {
    let td = tempfile::tempdir().unwrap();
    let (link, target, spelled) = linked_settings(td.path());
    let agent = TestAgentBuilder::new()
        .policy(&isolated_policy(&td.path().join("elsewhere/settings.json")))
        .start()
        .await;
    std::fs::write(&agent.policy_file, isolated_policy(&link)).unwrap();
    assert_eq!(
        agent
            .control(&serde_json::json!({"cmd":"reload_policy"}))
            .await["ok"],
        true
    );
    let writer = keep_writing(target);
    let seen = wait_for_change(&agent, &spelled, None).await;
    writer.abort();
    assert!(seen, "no file_change for {}", spelled.display());
    agent.join.abort();
}
