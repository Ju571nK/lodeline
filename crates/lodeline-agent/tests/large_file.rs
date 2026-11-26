mod common;
use common::{
    fs_event_timeout, policy_for_paths, run_bounded, start_bounded, stop_bounded, TestAgentBuilder,
    TEST_BOUND,
};
use std::time::Duration;

#[test]
fn it_large_file_emits_incomplete() {
    run_bounded(
        "it_large_file_emits_incomplete",
        TEST_BOUND,
        |steps| async move {
            steps.at("set up the files");
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("big.bin");
            let policy = policy_for_paths(&[target.to_str().unwrap()], "standard");
            let mut agent = start_bounded(&steps, TestAgentBuilder::new().policy(&policy)).await;

            // 11 MB file (> MAX_HASH_BYTES=10 MB → TooLarge → Incomplete quality).
            let bytes = vec![0u8; 11 * 1024 * 1024];

            // Re-write the oversized file until the watcher observes it. A single write
            // landing in the watcher's startup gap is lost forever (FSEvents/inotify
            // deliver from "now", no earlier events sent again), hard-failing under load (#108 family).
            // Rewrites are paced wider than the small-file tests since each is 11 MB;
            // every rewrite is the full size, so any observed event satisfies the
            // size_after assertion. The writer is aborted once the event arrives.
            let writer_target = target.clone();
            let writer = tokio::spawn(async move {
                loop {
                    let _ = std::fs::write(&writer_target, &bytes);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            });

            steps.at("wait for the incomplete file_change");
            let event = agent
                .wait_for_event(
                    |v| {
                        v["evidence"]["kind"] == "file_change"
                            && v["evidence"]["evidence_quality"] == "incomplete"
                            && v["evidence"]["size_after"] == 11 * 1024 * 1024
                    },
                    fs_event_timeout(),
                )
                .await;

            writer.abort();
            let event = event.expect("expected incomplete-quality file_change");
            assert!(event["evidence"]["after_hash"].is_null());
            stop_bounded(&steps, &mut agent).await;
        },
    );
}
