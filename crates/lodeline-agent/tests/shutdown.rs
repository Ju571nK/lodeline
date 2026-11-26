mod common;
use common::{
    policy_for_paths, run_bounded, start_bounded, stop_bounded, TestAgentBuilder, TEST_BOUND,
};
use std::time::Duration;

#[test]
fn it_graceful_shutdown_drains_queue() {
    run_bounded(
        "it_graceful_shutdown_drains_queue",
        TEST_BOUND,
        |steps| async move {
            steps.at("set up the files");
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("x.json");
            let policy = policy_for_paths(&[target.to_str().unwrap()], "standard");
            let mut agent = start_bounded(&steps, TestAgentBuilder::new().policy(&policy)).await;
            steps.at("write the file");
            for i in 0..5 {
                std::fs::write(&target, format!("v{i}").as_bytes()).unwrap();
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            stop_bounded(&steps, &mut agent).await;
            tokio::time::sleep(Duration::from_millis(500)).await;
            let events = agent.read_all_events();
            assert!(!events.is_empty(), "expected at least one drained event");
        },
    );
}
