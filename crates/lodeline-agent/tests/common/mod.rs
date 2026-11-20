//! Shared test fixtures.

#![allow(dead_code)]

pub use lodeline_agent::test_support::*;

pub fn policy_for_paths(paths: &[&str], tier: &str) -> String {
    let id = format!("test-target-{}", uuid::Uuid::new_v4().simple());
    let mut yaml = String::new();
    yaml.push_str("version: 1\n");
    yaml.push_str("targets:\n");
    yaml.push_str(&format!("  - id: {id}\n"));
    yaml.push_str("    description: integration-test target\n");
    yaml.push_str(&format!("    tier: {tier}\n"));
    yaml.push_str("    platform: any\n");
    yaml.push_str("    paths:\n");
    for p in paths {
        // Single-quoted so backslashes (Windows paths) aren't treated as YAML
        // escapes. (Temp paths never contain `'`.)
        yaml.push_str(&format!("      - '{p}'\n"));
    }
    yaml.push_str("    recursive: false\n");
    yaml.push_str("    follow_symlinks: false\n");
    yaml
}

/// Wait budget for OS-watcher-driven (`wait_for_event` and equivalent poll
/// loops) assertions. `wait_for_event` returns as soon as the event arrives, so
/// a generous budget is free on success and only bounds the *failure* deadline.
/// OS watcher delivery (FSEvents, inotify) lags badly under the heavy
/// cross-process parallelism of `cargo test --workspace` (issues #25, #66), so
/// keep ample headroom — and let a loaded host raise it further without a
/// rebuild via `LODELINE_TEST_FS_TIMEOUT_SECS`.
pub fn fs_event_timeout() -> std::time::Duration {
    let base = if cfg!(target_os = "macos") { 30 } else { 15 };
    let secs = std::env::var("LODELINE_TEST_FS_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(base);
    std::time::Duration::from_secs(secs)
}

/// Bound for waits on a child process or a channel event. Generous, since it only
/// bounds the failure: a wait that succeeds returns as soon as the thing arrives.
pub const WAIT_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

fn drain<R: std::io::Read + Send + 'static>(
    pipe: Option<R>,
) -> Option<std::thread::JoinHandle<Vec<u8>>> {
    pipe.map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    })
}

fn collect(reader: Option<std::thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    reader.map(|r| r.join().unwrap()).unwrap_or_default()
}

/// `wait_with_output` with a deadline. Closes the child's stdin first, as
/// `wait_with_output` does. On timeout the child is killed and reaped, then the
/// test panics naming `what`.
pub fn wait_bounded(
    mut child: std::process::Child,
    bound: std::time::Duration,
    what: &str,
) -> std::process::Output {
    drop(child.stdin.take());
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > bound {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what}: still running after {bound:?}, killed");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    std::process::Output {
        status,
        stdout: collect(stdout),
        stderr: collect(stderr),
    }
}

/// `recv` with a deadline, failing by name when nothing arrives or the sender is gone.
pub async fn recv_bounded<T>(
    rx: &mut tokio::sync::mpsc::Receiver<T>,
    bound: std::time::Duration,
    what: &str,
) -> T {
    tokio::time::timeout(bound, rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{what}: nothing within {bound:?}"))
        .unwrap_or_else(|| panic!("{what}: channel closed"))
}
