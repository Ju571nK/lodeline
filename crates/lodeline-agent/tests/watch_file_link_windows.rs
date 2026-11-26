#![cfg(windows)]

mod common;
use common::{
    fs_event_timeout, policy_for_paths, run_bounded, Steps, TestAgent, TestAgentBuilder, WAIT_BOUND,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Well under the 40 minute job limit, over the sum of the step bounds below.
const TEST_BOUND: Duration = Duration::from_secs(300);

fn isolated_policy(pattern: &Path, recursive: bool) -> String {
    let mut yaml = policy_for_paths(&[pattern.to_str().unwrap()], "standard");
    if recursive {
        yaml = yaml.replace("recursive: false", "recursive: true");
    }
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

/// The `file_change` count and the kinds of the last few events in `events_dir`,
/// for the message of a test that was cut off.
fn events_seen(events_dir: &Path) -> String {
    let mut kinds = Vec::new();
    let mut changes = 0;
    if let Ok(entries) = std::fs::read_dir(events_dir) {
        let mut files: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        files.sort();
        for file in files {
            for line in std::fs::read_to_string(file).unwrap_or_default().lines() {
                let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let kind = event["evidence"]["kind"]
                    .as_str()
                    .unwrap_or("?")
                    .to_string();
                if kind == "file_change" {
                    changes += 1;
                }
                kinds.push(kind);
            }
        }
    }
    let tail = kinds.len().saturating_sub(5);
    format!(
        "{changes} file_change events, {} events in all, last kinds {:?}",
        kinds.len(),
        &kinds[tail..]
    )
}

/// Start the agent with every await bounded: `start` waits on the control IPC
/// and the settle delay, so a wedged start fails by name instead of at the job limit.
async fn start_agent(steps: &Steps, policy: &str) -> TestAgent {
    steps.at("start the agent");
    let agent = tokio::time::timeout(WAIT_BOUND, TestAgentBuilder::new().policy(policy).start())
        .await
        .unwrap_or_else(|_| panic!("the agent did not start within {WAIT_BOUND:?}"));
    let events_dir = agent.events_dir.clone();
    steps.context(move || events_seen(&events_dir));
    agent
}

/// Stop the agent and wait, bounded, for its task to end.
async fn stop_agent(steps: &Steps, agent: TestAgent) {
    steps.at("stop the agent");
    agent.join.abort();
    let ended = tokio::time::timeout(WAIT_BOUND, agent.join).await;
    assert!(
        ended.is_ok(),
        "the agent task did not end within {WAIT_BOUND:?}"
    );
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

/// A junction needs no privilege. No crate in the lockfile creates one, so this
/// runs `mklink /J`.
fn make_junction(link: &Path, target: &Path) {
    let status = std::process::Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(link)
        .arg(target)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "mklink /J failed");
}

#[test]
fn native_write_to_a_file_link_target_records_the_link_path() {
    run_bounded(
        "native_write_to_a_file_link_target_records_the_link_path",
        TEST_BOUND,
        |steps| async move { file_link_body(steps).await },
    );
}

async fn file_link_body(steps: Arc<Steps>) {
    steps.at("set up the files");
    let td = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(td.path()).unwrap();
    let dotfiles = root.join("dotfiles");
    let claude = root.join("home").join(".claude");
    std::fs::create_dir_all(&dotfiles).unwrap();
    std::fs::create_dir_all(&claude).unwrap();
    let target = dotfiles.join("settings.json");
    std::fs::write(&target, b"initial").unwrap();
    let link = claude.join("settings.json");
    if let Err(error) = std::os::windows::fs::symlink_file(&target, &link) {
        println!("skipped: cannot create a file symlink here ({error})");
        return;
    }
    let agent = start_agent(&steps, &isolated_policy(&link, false)).await;
    steps.at("wait for the file_change");
    change_is_recorded_at(&agent, &link, target).await;
    assert!(!agent.join.is_finished(), "the agent stopped");
    stop_agent(&steps, agent).await;
}

#[test]
fn native_write_through_a_skill_folder_junction_records_the_link_path() {
    run_bounded(
        "native_write_through_a_skill_folder_junction_records_the_link_path",
        TEST_BOUND,
        |steps| async move { junction_body(steps).await },
    );
}

async fn junction_body(steps: Arc<Steps>) {
    steps.at("set up the files");
    let td = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(td.path()).unwrap();
    let outside = root.join("dotfiles").join("foo");
    let skills = root.join("repo").join(".claude").join("skills");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(skills.join("real")).unwrap();
    std::fs::write(outside.join("SKILL.md"), b"initial").unwrap();
    make_junction(&skills.join("foo"), &outside);
    let agent = start_agent(
        &steps,
        &isolated_policy(&skills.join("*").join("SKILL.md"), true),
    )
    .await;
    steps.at("wait for the file_change");
    change_is_recorded_at(
        &agent,
        &skills.join("foo").join("SKILL.md"),
        outside.join("SKILL.md"),
    )
    .await;
    assert!(!agent.join.is_finished(), "the agent stopped");
    stop_agent(&steps, agent).await;
}
