#![cfg(windows)]

mod common;
use common::{fs_event_timeout, policy_for_paths, TestAgent, TestAgentBuilder};
use std::path::{Path, PathBuf};
use std::time::Duration;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_write_to_a_file_link_target_records_the_link_path() {
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
    let agent = TestAgentBuilder::new()
        .policy(&isolated_policy(&link, false))
        .start()
        .await;
    change_is_recorded_at(&agent, &link, target).await;
    assert!(!agent.join.is_finished(), "the agent stopped");
    agent.join.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_write_through_a_skill_folder_junction_records_the_link_path() {
    let td = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(td.path()).unwrap();
    let outside = root.join("dotfiles").join("foo");
    let skills = root.join("repo").join(".claude").join("skills");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(skills.join("real")).unwrap();
    std::fs::write(outside.join("SKILL.md"), b"initial").unwrap();
    make_junction(&skills.join("foo"), &outside);
    let agent = TestAgentBuilder::new()
        .policy(&isolated_policy(&skills.join("*").join("SKILL.md"), true))
        .start()
        .await;
    change_is_recorded_at(
        &agent,
        &skills.join("foo").join("SKILL.md"),
        outside.join("SKILL.md"),
    )
    .await;
    assert!(!agent.join.is_finished(), "the agent stopped");
    agent.join.abort();
}
