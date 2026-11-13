#![cfg(unix)]

mod common;
use common::{fs_event_timeout, policy_for_paths, TestAgent, TestAgentBuilder};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn isolated_policy(pattern: &Path) -> String {
    let mut yaml = policy_for_paths(&[pattern.to_str().unwrap()], "standard")
        .replace("recursive: false", "recursive: true");
    yaml.push_str("overrides:\n");
    for target in lodeline_core::policy::defaults().unwrap().targets {
        yaml.push_str(&format!("  - id: {}\n    disabled: true\n", target.id));
    }
    yaml
}

fn changes_at(agent: &TestAgent, path: &Path) -> usize {
    agent
        .read_all_events()
        .into_iter()
        .filter(|e| {
            e["evidence"]["kind"] == "file_change"
                && e["subject"]["value"]
                    .as_str()
                    .is_some_and(|p| Path::new(p) == path)
        })
        .count()
}

/// Rewrite `file` until the test aborts the writer: a write that lands in the
/// watcher's startup gap is never scanned, so one write can be lost.
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

async fn change_is_recorded_at(agent: &TestAgent, spelled: &Path, target: PathBuf) {
    let writer = keep_writing(target);
    let deadline = std::time::Instant::now() + fs_event_timeout();
    let mut seen = false;
    while std::time::Instant::now() < deadline && !seen {
        seen = changes_at(agent, spelled) > 0;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    writer.abort();
    assert!(seen, "no file_change for {}", spelled.display());
}

async fn a_linked_skill_folder_records_under_the_link_path(poll: bool) {
    let td = tempfile::tempdir().unwrap();
    let home = dunce::canonicalize(td.path()).unwrap();
    let outside = home.join("dotfiles/foo");
    let skills = home.join("repo/.claude/skills");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(skills.join("real")).unwrap();
    std::fs::write(outside.join("SKILL.md"), b"initial").unwrap();
    std::os::unix::fs::symlink(&outside, skills.join("foo")).unwrap();
    let agent = TestAgentBuilder::new()
        .policy(&isolated_policy(&skills.join("*/SKILL.md")))
        .poll_watcher(poll)
        .start()
        .await;
    change_is_recorded_at(
        &agent,
        &skills.join("foo/SKILL.md"),
        outside.join("SKILL.md"),
    )
    .await;
    assert!(!agent.join.is_finished(), "the agent stopped");
    agent.join.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_a_linked_skill_folder_records_under_the_link_path() {
    a_linked_skill_folder_records_under_the_link_path(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn polling_a_linked_skill_folder_records_under_the_link_path() {
    a_linked_skill_folder_records_under_the_link_path(true).await;
}

async fn a_linked_subagent_file_records_under_the_link_path(poll: bool) {
    let td = tempfile::tempdir().unwrap();
    let home = dunce::canonicalize(td.path()).unwrap();
    let agents = home.join("repo/.claude/agents");
    std::fs::create_dir_all(&agents).unwrap();
    std::fs::create_dir_all(home.join("dotfiles")).unwrap();
    let target = home.join("dotfiles/a.md");
    std::fs::write(&target, b"initial").unwrap();
    std::os::unix::fs::symlink(&target, agents.join("a.md")).unwrap();
    let agent = TestAgentBuilder::new()
        .policy(&isolated_policy(&agents.join("*.md")))
        .poll_watcher(poll)
        .start()
        .await;
    change_is_recorded_at(&agent, &agents.join("a.md"), target).await;
    agent.join.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_a_linked_subagent_file_records_under_the_link_path() {
    a_linked_subagent_file_records_under_the_link_path(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn polling_a_linked_subagent_file_records_under_the_link_path() {
    a_linked_subagent_file_records_under_the_link_path(true).await;
}

/// `skills/loop` links to the folder that holds `skills`, so a followed link
/// would record `skills/loop/SKILL.md` for the file next to `skills`.
async fn a_loop_link_is_not_followed_and_a_real_skill_still_records(poll: bool) {
    let td = tempfile::tempdir().unwrap();
    let home = dunce::canonicalize(td.path()).unwrap();
    let skills = home.join("skills");
    std::fs::create_dir_all(skills.join("a")).unwrap();
    std::fs::write(home.join("SKILL.md"), b"initial").unwrap();
    std::os::unix::fs::symlink(&home, skills.join("loop")).unwrap();
    let agent = TestAgentBuilder::new()
        .policy(&isolated_policy(&skills.join("*/SKILL.md")))
        .poll_watcher(poll)
        .start()
        .await;
    let behind_the_loop = keep_writing(home.join("SKILL.md"));
    change_is_recorded_at(
        &agent,
        &skills.join("a/SKILL.md"),
        skills.join("a/SKILL.md"),
    )
    .await;
    // The edits to the file behind the link ran for as long as the real edit took.
    tokio::time::sleep(Duration::from_millis(500)).await;
    behind_the_loop.abort();
    assert_eq!(changes_at(&agent, &skills.join("loop/SKILL.md")), 0);
    assert!(!agent.join.is_finished(), "the agent stopped");
    agent.join.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_a_loop_link_is_not_followed_and_a_real_skill_still_records() {
    a_loop_link_is_not_followed_and_a_real_skill_still_records(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn polling_a_loop_link_is_not_followed_and_a_real_skill_still_records() {
    a_loop_link_is_not_followed_and_a_real_skill_still_records(true).await;
}
