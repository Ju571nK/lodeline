mod common;
use common::{
    policy_for_paths, run_bounded, start_bounded, stop_bounded, Steps, TestAgentBuilder, TEST_BOUND,
};
use std::sync::Arc;

async fn observes_late_directory(steps: Arc<Steps>, recursive: bool) {
    steps.at("set up the files");
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("not-yet-created/cache/tools");
    let file = if recursive {
        root.join("nested/snapshot.json")
    } else {
        root.join("settings.json")
    };
    let target = if recursive {
        root.join("*")
    } else {
        file.clone()
    };
    let policy = policy_for_paths(&[target.to_str().unwrap()], "standard")
        .replace("recursive: false", &format!("recursive: {recursive}"));
    lodeline_core::policy::parse(&policy).expect("valid integration-test policy");
    let mut agent = start_bounded(&steps, TestAgentBuilder::new().policy(&policy)).await;
    assert!(!root.exists());
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    // A single write, before reconciliation: repeated writes would hide the gap.
    std::fs::write(&file, b"first snapshot").unwrap();
    let expected = dunce::canonicalize(&file).unwrap();
    steps.at("wait for the file_change");
    let observed = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "file_change"
                    && v["subject"]["value"]
                        .as_str()
                        .is_some_and(|p| std::path::Path::new(p) == expected)
            },
            common::fs_event_timeout(),
        )
        .await;
    let seen = common::events_seen(&agent.events_dir);
    stop_bounded(&steps, &mut agent).await;
    assert!(
        observed.is_some(),
        "one-shot file creation in a late directory was lost. {seen}"
    );
}

#[test]
fn recursive_directory_created_after_startup_is_observed() {
    run_bounded(
        "recursive_directory_created_after_startup_is_observed",
        TEST_BOUND,
        |steps| async move { observes_late_directory(steps, true).await },
    );
}

#[test]
fn missing_parent_of_literal_target_is_recovered() {
    run_bounded(
        "missing_parent_of_literal_target_is_recovered",
        TEST_BOUND,
        |steps| async move { observes_late_directory(steps, false).await },
    );
}
