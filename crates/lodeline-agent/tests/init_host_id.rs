//! `lodeline init-host-id` on the real binary, against a scratch `--state-db`.

mod common;
use common::{fs_event_timeout, TestAgentBuilder};
use std::path::Path;
use std::process::{Command, Output};

const X: &str = "5a7c3e91-1f2b-4c3d-8e4f-0a1b2c3d4e5f";
const Y: &str = "9d8c7b6a-5f4e-4d3c-9b2a-1f0e9d8c7b6a";

fn lodeline(state_db: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lodeline"))
        .arg("--state-db")
        .arg(state_db)
        .args(args)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn claims_once_keeps_the_id_and_refuses_another() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("not-yet").join("state.db");
    let path = db.display().to_string();

    let first = lodeline(&db, &["init-host-id", X]);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first.stderr));
    let out = text(&first.stdout);
    assert!(out.contains(X) && out.contains(&path), "{out}");

    let again = lodeline(&db, &["init-host-id", X]);
    assert_eq!(again.status.code(), Some(0), "{}", text(&again.stderr));
    assert!(
        text(&again.stdout).contains("already set"),
        "{}",
        text(&again.stdout)
    );

    let other = lodeline(&db, &["init-host-id", Y]);
    assert_eq!(other.status.code(), Some(3), "{}", text(&other.stderr));
    let err = text(&other.stderr);
    assert!(err.contains(X) && err.contains(&path), "{err}");
    assert!(!err.contains("delete") && !err.contains("remove"), "{err}");

    let show = lodeline(&db, &["show", "host-id"]);
    assert_eq!(text(&show.stdout).trim(), X);
}

#[test]
fn an_uppercase_uuid_is_a_usage_error_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");

    let out = lodeline(&db, &["init-host-id", &X.to_uppercase()]);

    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(!db.exists(), "a refused id must not create state.db");
}

#[test]
fn a_relative_state_db_is_refused() {
    let dir = tempfile::tempdir().unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_lodeline"))
        .current_dir(dir.path())
        .args(["--state-db", "state.db", "init-host-id", X])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("not absolute"),
        "{}",
        text(&out.stderr)
    );
    assert!(!dir.path().join("state.db").exists());
}

/// Racing writers on a fresh state.db agree on one host_id: exactly one wins,
/// and every other one exits 3 and names the winner.
#[test]
fn concurrent_claims_on_a_fresh_state_db_elect_one_host_id() {
    const WRITERS: usize = 8;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let ids: Vec<String> = (0..WRITERS)
        .map(|_| uuid::Uuid::new_v4().to_string())
        .collect();

    let children: Vec<_> = ids
        .iter()
        .map(|id| {
            Command::new(env!("CARGO_BIN_EXE_lodeline"))
                .arg("--state-db")
                .arg(&db)
                .args(["init-host-id", id])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let outputs: Vec<Output> = children
        .into_iter()
        .map(|c| c.wait_with_output().unwrap())
        .collect();

    let stored = text(&lodeline(&db, &["show", "host-id"]).stdout)
        .trim()
        .to_string();
    let winners: Vec<_> = ids
        .iter()
        .zip(&outputs)
        .filter(|(_, o)| o.status.code() == Some(0))
        .map(|(id, _)| id.as_str())
        .collect();
    assert_eq!(winners, [stored.as_str()], "exactly one writer wins");
    for (id, out) in ids.iter().zip(&outputs) {
        if *id != stored {
            assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
            assert!(text(&out.stderr).contains(&stored), "{}", text(&out.stderr));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_agent_adopts_a_preassigned_host_id_on_its_first_run() {
    let agent = TestAgentBuilder::new()
        .policy("version: 1\ntargets: []\n")
        .host_id(X)
        .start()
        .await;

    let ev = agent
        .wait_for_event(|v| v["host_id"].is_string(), fs_event_timeout())
        .await
        .expect("the agent emits an event after boot");

    assert_eq!(ev["host_id"], X);
    agent.join.abort();
}
