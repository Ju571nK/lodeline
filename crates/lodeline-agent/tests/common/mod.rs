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

/// Where a bounded test is, for the failure message when it is cut off.
#[derive(Default)]
pub struct Steps {
    step: std::sync::Mutex<&'static str>,
    context: std::sync::Mutex<Option<Box<dyn Fn() -> String + Send>>>,
}

impl Steps {
    /// Name the step the test is about to run.
    pub fn at(&self, step: &'static str) {
        *self.step.lock().unwrap() = step;
    }

    /// Text added to the failure message, for example the events seen so far.
    pub fn context(&self, f: impl Fn() -> String + Send + 'static) {
        *self.context.lock().unwrap() = Some(Box::new(f));
    }

    fn describe(&self) -> String {
        let step = *self.step.lock().unwrap();
        let context = self.context.lock().unwrap();
        let extra = context.as_ref().map(|f| f()).unwrap_or_default();
        format!("stuck at step {step:?}. {extra}")
    }
}

/// Run an async test body on its own thread and runtime, and fail by name when
/// the body, or the runtime shutdown after it, takes longer than `bound`. The
/// bound is enforced from outside, so a blocking call or a runtime drop that
/// waits on a native watcher thread cannot hold the test past it. On timeout the
/// worker thread is left behind and the test process ends when the tests finish.
pub fn run_bounded<F, Fut>(name: &str, bound: std::time::Duration, body: F)
where
    F: FnOnce(std::sync::Arc<Steps>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()>,
{
    let steps = std::sync::Arc::new(Steps::default());
    let (tx, rx) = std::sync::mpsc::channel();
    let worker_steps = steps.clone();
    std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(body(worker_steps));
            drop(rt);
        }));
        let _ = tx.send(outcome);
    });
    match rx.recv_timeout(bound) {
        Ok(Ok(())) => {}
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => panic!(
            "{name}: not finished within {bound:?}, {}",
            steps.describe()
        ),
    }
}

/// Outer bound for one bounded test: well under the 40 minute job limit, over
/// the sum of the step bounds inside it.
pub const TEST_BOUND: std::time::Duration = std::time::Duration::from_secs(300);

/// The `file_change` count and the kinds of the last few events in `events_dir`,
/// for the message of a test that was cut off.
pub fn events_seen(events_dir: &std::path::Path) -> String {
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

/// Start the agent with the await bounded: `start` waits on the control IPC and
/// the settle delay, so a wedged start fails by name instead of at the job limit.
pub async fn start_bounded(steps: &Steps, builder: TestAgentBuilder) -> TestAgent {
    steps.at("start the agent");
    let agent = tokio::time::timeout(WAIT_BOUND, builder.start())
        .await
        .unwrap_or_else(|_| panic!("the agent did not start within {WAIT_BOUND:?}"));
    let events_dir = agent.events_dir.clone();
    steps.context(move || events_seen(&events_dir));
    agent
}

/// Abort the agent task and wait, bounded, for it to end. The caller drops the
/// agent afterwards, which is the last step before the runtime drop.
pub async fn stop_bounded(steps: &Steps, agent: &mut TestAgent) {
    steps.at("stop the agent");
    agent.join.abort();
    let ended = tokio::time::timeout(WAIT_BOUND, &mut agent.join).await;
    assert!(
        ended.is_ok(),
        "the agent task did not end within {WAIT_BOUND:?}. {}",
        events_seen(&agent.events_dir)
    );
    steps.at("drop the agent and the runtime");
}
