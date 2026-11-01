//! e2e: the agent keeps the applied version and expiry across a restart, and across
//! a later apply in the same process, wherever an apply stopped.
//!
//! The agent has no test hook. A SQL trigger stops the write of the recorded version,
//! a directory at the temp path stops the file write, and a directory mode stops the
//! directory sync. The child process tests hold the agent inside that SQL write, or
//! in the open of a FIFO at the temp path, and send it SIGKILL. Unix only, because
//! the requests go over the control socket.
#![cfg(all(unix, feature = "operator-cli"))]

#[path = "common/signed_host.rs"]
mod signed_host;

use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};
use signed_host::{Host, STOP_DEADLINE};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const CHILD_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
struct Artifact {
    file: &'static str,
    apply: &'static str,
    column: &'static str,
    kind: &'static str,
}

const POLICY: Artifact = Artifact {
    file: "policy.yaml",
    apply: "apply_policy",
    column: "last_applied_policy_version",
    kind: "policy",
};

const RULE_PACKS: Artifact = Artifact {
    file: "rule-packs.yaml",
    apply: "apply_rule_packs",
    column: "last_applied_rule_packs_version",
    kind: "rule_packs",
};

fn doc(version: i64) -> String {
    format!("version: 1\n# envelope {version}\n")
}

impl Host {
    fn apply(&self, artifact: Artifact, version: i64) -> Value {
        let response = self.signed(version, &doc(version));
        self.control(&json!({"cmd": artifact.apply, "response": response}))
    }

    fn file(&self, artifact: Artifact) -> String {
        String::from_utf8(self.read(artifact.file)).unwrap()
    }

    fn sql(&self, statements: &str) {
        Connection::open(self.path("state.db"))
            .unwrap()
            .execute_batch(statements)
            .unwrap();
    }

    fn recorded(&self, artifact: Artifact) -> i64 {
        Connection::open(self.path("state.db"))
            .unwrap()
            .query_row(
                &format!("SELECT {} FROM host_meta", artifact.column),
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn pending(&self, artifact: Artifact) -> Option<i64> {
        Connection::open(self.path("state.db"))
            .unwrap()
            .query_row(
                "SELECT version FROM pending_envelope WHERE kind = ?1",
                [artifact.kind],
                |row| row.get(0),
            )
            .optional()
            .unwrap()
    }

    fn status(&self) -> Value {
        self.control(&json!({"cmd": "policy_status"}))["policy_status"].clone()
    }

    fn set_directory_mode(&self, mode: u32) {
        let mode = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(self.path("."), mode).unwrap();
    }

    fn stop_the_record_write(&self, artifact: Artifact) {
        self.sql(&format!(
            "CREATE TRIGGER stop_here BEFORE UPDATE OF {} ON host_meta
             BEGIN SELECT RAISE(ABORT, 'stopped'); END;",
            artifact.column
        ));
    }

    /// Leaves `doc(5)` on disk and the record at 2, the state of a process that
    /// stopped after the rename.
    fn apply_stopped_after_the_rename(&self, artifact: Artifact) -> tokio::runtime::Runtime {
        let rt = self.boot().expect("first boot");
        assert_accepted(&self.apply(artifact, 2), 2);
        self.stop_the_record_write(artifact);

        let reply = self.apply(artifact, 5);

        assert_eq!(reply["ok"], false, "{reply}");
        assert_eq!(self.file(artifact), doc(5), "the rename happened");
        assert_eq!(self.recorded(artifact), 2, "the record did not move");
        rt
    }

    #[track_caller]
    fn assert_older_envelope_is_refused(&self, artifact: Artifact) {
        assert_eq!(self.recorded(artifact), 5, "record after boot");
        self.assert_apply_finishes_the_newest_and_refuses_an_older_one(artifact);
    }

    #[track_caller]
    fn assert_apply_finishes_the_newest_and_refuses_an_older_one(&self, artifact: Artifact) {
        let reply = self.apply(artifact, 3);

        assert_refused_as_older(&reply);
        assert_eq!(self.file(artifact), doc(5), "newest stays on disk");
        assert_eq!(self.recorded(artifact), 5);
    }
}

#[track_caller]
fn wait_until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "never: {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[track_caller]
fn assert_accepted(reply: &Value, version: i64) {
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["apply_policy"]["outcome"], "accepted", "{reply}");
    assert_eq!(reply["apply_policy"]["applied_policy_version"], version);
}

#[track_caller]
fn assert_refused_as_older(reply: &Value) {
    assert_eq!(reply["apply_policy"]["outcome"], "rejected", "{reply}");
    assert_eq!(
        reply["apply_policy"]["reason"], "version_regression",
        "{reply}"
    );
}

fn stop_after_the_rename_keeps_the_newest_version(artifact: Artifact) {
    let host = Host::new("version: 1\n");
    let rt = host.apply_stopped_after_the_rename(artifact);
    rt.shutdown_timeout(STOP_DEADLINE);
    host.sql("DROP TRIGGER stop_here;");

    let rt = host.boot().expect("restart");

    host.assert_older_envelope_is_refused(artifact);
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn stop_after_the_policy_rename_keeps_the_newest_version() {
    stop_after_the_rename_keeps_the_newest_version(POLICY);
}

#[test]
fn stop_after_the_rule_pack_rename_keeps_the_newest_version() {
    stop_after_the_rename_keeps_the_newest_version(RULE_PACKS);
}

fn stop_during_boot_repair_is_repaired_by_the_next_boot(artifact: Artifact) {
    let host = Host::new("version: 1\n");
    let rt = host.apply_stopped_after_the_rename(artifact);
    rt.shutdown_timeout(STOP_DEADLINE);

    let stopped = host.boot();

    assert!(stopped.is_err(), "boot must not serve an unrepaired record");
    assert_eq!(host.recorded(artifact), 2, "repair did not commit");
    host.sql("DROP TRIGGER stop_here;");
    let rt = host.boot().expect("second restart");
    host.assert_older_envelope_is_refused(artifact);
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn stop_during_boot_repair_of_a_policy_is_repaired_by_the_next_boot() {
    stop_during_boot_repair_is_repaired_by_the_next_boot(POLICY);
}

#[test]
fn stop_during_boot_repair_of_a_rule_pack_is_repaired_by_the_next_boot() {
    stop_during_boot_repair_is_repaired_by_the_next_boot(RULE_PACKS);
}

fn stop_before_the_rename_leaves_the_host_unchanged_and_a_retry_applies(artifact: Artifact) {
    let host = Host::new("version: 1\n");
    let rt = host.boot().expect("first boot");
    assert_accepted(&host.apply(artifact, 2), 2);
    let temp = host.path(&format!(".{}.{}.tmp", artifact.file, std::process::id()));
    std::fs::create_dir(&temp).unwrap();

    let reply = host.apply(artifact, 5);

    assert_eq!(reply["ok"], false, "{reply}");
    rt.shutdown_timeout(STOP_DEADLINE);
    std::fs::remove_dir(&temp).unwrap();
    let rt = host.boot().expect("restart");
    assert_eq!(host.file(artifact), doc(2), "file after boot");
    assert_eq!(host.recorded(artifact), 2, "record after boot");
    assert_accepted(&host.apply(artifact, 5), 5);
    assert_eq!(host.file(artifact), doc(5), "file after the retry");
    assert_eq!(host.recorded(artifact), 5, "record after the retry");
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn stop_before_the_policy_rename_leaves_the_host_unchanged_and_a_retry_applies() {
    stop_before_the_rename_leaves_the_host_unchanged_and_a_retry_applies(POLICY);
}

#[test]
fn stop_before_the_rule_pack_rename_leaves_the_host_unchanged_and_a_retry_applies() {
    stop_before_the_rename_leaves_the_host_unchanged_and_a_retry_applies(RULE_PACKS);
}

fn failed_record_write_keeps_the_newest_version_without_a_restart(artifact: Artifact) {
    let host = Host::new("version: 1\n");
    let rt = host.apply_stopped_after_the_rename(artifact);
    host.sql("DROP TRIGGER stop_here;");

    host.assert_apply_finishes_the_newest_and_refuses_an_older_one(artifact);
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn failed_policy_record_write_keeps_the_newest_version_without_a_restart() {
    failed_record_write_keeps_the_newest_version_without_a_restart(POLICY);
}

#[test]
fn failed_rule_pack_record_write_keeps_the_newest_version_without_a_restart() {
    failed_record_write_keeps_the_newest_version_without_a_restart(RULE_PACKS);
}

fn failed_directory_sync_keeps_the_newest_version_without_a_restart(artifact: Artifact) {
    let host = Host::new("version: 1\n");
    let rt = host.boot().expect("boot");
    assert_accepted(&host.apply(artifact, 2), 2);
    host.set_directory_mode(0o300);
    if std::fs::File::open(host.path(".")).is_ok() {
        eprintln!("skipped: root ignores directory modes");
        host.set_directory_mode(0o700);
        rt.shutdown_timeout(STOP_DEADLINE);
        return;
    }

    let reply = host.apply(artifact, 5);
    host.set_directory_mode(0o700);

    assert_eq!(reply["ok"], false, "{reply}");
    assert_eq!(host.file(artifact), doc(5), "the rename happened");
    assert_eq!(host.recorded(artifact), 2, "the record did not move");
    host.assert_apply_finishes_the_newest_and_refuses_an_older_one(artifact);
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn failed_policy_directory_sync_keeps_the_newest_version_without_a_restart() {
    failed_directory_sync_keeps_the_newest_version_without_a_restart(POLICY);
}

#[test]
fn failed_rule_pack_directory_sync_keeps_the_newest_version_without_a_restart() {
    failed_directory_sync_keeps_the_newest_version_without_a_restart(RULE_PACKS);
}

fn failed_repair_refuses_the_apply_and_a_later_apply_recovers(artifact: Artifact) {
    let host = Host::new("version: 1\n");
    let rt = host.apply_stopped_after_the_rename(artifact);

    let reply = host.apply(artifact, 6);

    assert_eq!(reply["ok"], false, "{reply}");
    assert_eq!(
        host.file(artifact),
        doc(5),
        "the refused apply wrote nothing"
    );
    assert_eq!(host.recorded(artifact), 2);
    host.sql("DROP TRIGGER stop_here;");
    assert_accepted(&host.apply(artifact, 6), 6);
    assert_eq!(host.file(artifact), doc(6), "file after recovery");
    assert_eq!(host.recorded(artifact), 6, "record after recovery");
    assert_eq!(host.pending(artifact), None);
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn failed_policy_repair_refuses_the_apply_and_a_later_apply_recovers() {
    failed_repair_refuses_the_apply_and_a_later_apply_recovers(POLICY);
}

#[test]
fn failed_rule_pack_repair_refuses_the_apply_and_a_later_apply_recovers() {
    failed_repair_refuses_the_apply_and_a_later_apply_recovers(RULE_PACKS);
}

fn retry_of_the_same_document_leaves_it_applied(artifact: Artifact) {
    let host = Host::new("version: 1\n");
    let rt = host.apply_stopped_after_the_rename(artifact);
    host.sql("DROP TRIGGER stop_here;");

    host.apply(artifact, 5);

    assert_eq!(host.file(artifact), doc(5));
    assert_eq!(host.recorded(artifact), 5);
    assert_eq!(host.pending(artifact), None);
    assert_accepted(&host.apply(artifact, 6), 6);
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn retry_of_the_same_policy_leaves_it_applied() {
    retry_of_the_same_document_leaves_it_applied(POLICY);
}

#[test]
fn retry_of_the_same_rule_pack_leaves_it_applied() {
    retry_of_the_same_document_leaves_it_applied(RULE_PACKS);
}

fn retry_after_a_failure_before_the_rename_applies_without_a_restart(artifact: Artifact) {
    let host = Host::new("version: 1\n");
    let rt = host.boot().expect("boot");
    assert_accepted(&host.apply(artifact, 2), 2);
    let temp = host.path(&format!(".{}.{}.tmp", artifact.file, std::process::id()));
    std::fs::create_dir(&temp).unwrap();
    assert_eq!(host.apply(artifact, 5)["ok"], false);
    std::fs::remove_dir(&temp).unwrap();

    assert_accepted(&host.apply(artifact, 5), 5);

    assert_eq!(host.file(artifact), doc(5));
    assert_eq!(host.recorded(artifact), 5);
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn retry_after_a_policy_failure_before_the_rename_applies_without_a_restart() {
    retry_after_a_failure_before_the_rename_applies_without_a_restart(POLICY);
}

#[test]
fn retry_after_a_rule_pack_failure_before_the_rename_applies_without_a_restart() {
    retry_after_a_failure_before_the_rename_applies_without_a_restart(RULE_PACKS);
}

#[test]
fn status_after_a_repair_without_a_restart_shows_the_true_version_and_expiry() {
    let host = Host::new("version: 1\n");
    let rt = host.boot().expect("boot");
    assert_accepted(&host.apply(POLICY, 2), 2);
    host.stop_the_record_write(POLICY);
    let in_two_hours = OffsetDateTime::now_utc() + time::Duration::hours(2);
    let response = host.signed_until(5, &doc(5), in_two_hours);
    let reply = host.control(&json!({"cmd": "apply_policy", "response": response}));
    assert_eq!(reply["ok"], false, "{reply}");
    host.sql("DROP TRIGGER stop_here;");

    assert_refused_as_older(&host.apply(POLICY, 3));

    let status = host.status();
    assert_eq!(status["last_applied_policy_version"], 5, "{status}");
    assert_eq!(
        status["active_envelope_valid_until"],
        in_two_hours.format(&Rfc3339).unwrap(),
        "{status}"
    );
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn repair_without_a_restart_loads_the_policy_it_finished() {
    let yaml = "version: 1\ntargets:\n  - id: extra\n    description: extra\n    tier: standard\n    platform: any\n    paths: ['/tmp/lodeline-repair-*.json']\n";
    let host = Host::new("version: 1\n");
    let rt = host.boot().expect("boot");
    assert_accepted(&host.apply(POLICY, 2), 2);
    host.stop_the_record_write(POLICY);
    assert_eq!(host.apply_policy(5, yaml)["ok"], false);
    host.sql("DROP TRIGGER stop_here;");

    assert_refused_as_older(&host.apply(POLICY, 3));

    // A polling host also reloads when the directory changes, so the version watch
    // itself is pinned by the policy_apply unit tests.
    wait_until("the finished policy loaded", || host.has_target("extra"));
    wait_until("the finished policy was reported", || {
        host.events().iter().any(|event| {
            event["evidence"]["kind"] == "policy_reloaded"
                && event["evidence"]["policy_version"] == 5
        })
    });
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn first_envelope_v1_applies_over_a_local_policy() {
    let host = Host::new("version: 1\n");
    let rt = host.boot().expect("boot");
    let status = host.status();
    assert_eq!(status["last_applied_policy_version"], 0, "{status}");
    assert!(status["active_envelope_valid_until"].is_null(), "{status}");

    assert_accepted(&host.apply(POLICY, 1), 1);

    assert_eq!(host.file(POLICY), doc(1));
    assert_eq!(host.status()["last_applied_policy_version"], 1);
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn first_envelope_v1_applies_over_a_local_rule_pack_file() {
    let host = Host::new("version: 1\n");
    std::fs::write(host.path(RULE_PACKS.file), "version: 1\n").unwrap();
    let rt = host.boot().expect("boot");

    assert_accepted(&host.apply(RULE_PACKS, 1), 1);

    assert_eq!(host.file(RULE_PACKS), doc(1));
    assert_eq!(host.recorded(RULE_PACKS), 1);
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn status_after_a_restart_shows_the_real_expiry_of_a_valid_policy() {
    let host = Host::new("version: 1\n");
    let rt = host.boot().expect("boot");
    let response = host.signed(2, &doc(2));
    let valid_until = response.signed_envelope.valid_until.format(&Rfc3339);
    let reply = host.control(&json!({"cmd": "apply_policy", "response": response}));
    assert_accepted(&reply, 2);
    rt.shutdown_timeout(STOP_DEADLINE);

    let rt = host.boot().expect("restart");

    let status = host.status();
    assert_eq!(status["last_applied_policy_version"], 2, "{status}");
    assert_eq!(
        status["active_envelope_valid_until"],
        valid_until.unwrap(),
        "{status}"
    );
    assert_eq!(status["policy_expired_active"], false, "{status}");
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn status_after_a_restart_shows_an_expired_policy_and_the_monitor_reports_it() {
    let host = Host::new("version: 1\n");
    let rt = host.boot().expect("boot");
    let valid_until = OffsetDateTime::now_utc() + time::Duration::seconds(3);
    let response = host.signed_until(2, &doc(2), valid_until);
    let reply = host.control(&json!({"cmd": "apply_policy", "response": response}));
    assert_accepted(&reply, 2);
    rt.shutdown_timeout(STOP_DEADLINE);
    let time_left = valid_until - OffsetDateTime::now_utc();
    std::thread::sleep(time_left.unsigned_abs());

    let rt = host.boot().expect("restart");

    let status = host.status();
    assert_eq!(status["last_applied_policy_version"], 2, "{status}");
    assert_eq!(
        status["active_envelope_valid_until"],
        valid_until.format(&Rfc3339).unwrap(),
        "{status}"
    );
    assert_eq!(status["policy_expired_active"], true, "{status}");
    assert_eq!(host.file(POLICY), doc(2), "the expired policy stays loaded");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !host.events().iter().any(|event| {
        event["evidence"]["kind"] == "policy_expired_active"
            && event["evidence"]["policy_version"] == 2
    }) {
        assert!(Instant::now() < deadline, "the monitor reported no expiry");
        std::thread::sleep(Duration::from_millis(50));
    }
    rt.shutdown_timeout(STOP_DEADLINE);
}

impl Host {
    fn has_target(&self, id: &str) -> bool {
        let reply = self.control(&json!({"cmd": "targets"}));
        reply["targets"]["targets"]
            .as_array()
            .is_some_and(|all| all.iter().any(|target| target["id"] == id))
    }

    fn events(&self) -> Vec<Value> {
        std::fs::read_dir(self.path("events"))
            .unwrap()
            .flatten()
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "jsonl"))
            .flat_map(|entry| {
                std::fs::read_to_string(entry.path())
                    .unwrap()
                    .lines()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The tables exactly as v0.12.0 created them.
    fn seed_old_state_db(&self, policy_version: i64, rule_packs_version: i64) {
        self.sql(&format!(
            "CREATE TABLE baseline (
                path TEXT PRIMARY KEY,
                hash_hex TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                target_id TEXT NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE host_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                host_id TEXT,
                hw_fingerprint TEXT,
                last_applied_policy_version INTEGER NOT NULL DEFAULT 0,
                last_applied_rule_packs_version INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO host_meta VALUES (1, NULL, NULL, {policy_version}, {rule_packs_version});"
        ));
    }
}

#[test]
fn upgraded_host_keeps_its_recorded_version_with_expiry_unknown() {
    let host = Host::new("version: 1\n");
    host.seed_old_state_db(7, 3);

    let rt = host.boot().expect("boot");

    let status = host.status();
    assert_eq!(status["last_applied_policy_version"], 7, "{status}");
    assert!(status["active_envelope_valid_until"].is_null(), "{status}");
    assert_eq!(status["policy_expired_active"], false, "{status}");
    assert_refused_as_older(&host.apply(POLICY, 6));
    assert_refused_as_older(&host.apply(RULE_PACKS, 2));
    assert_accepted(&host.apply(POLICY, 8), 8);
    assert!(host.status()["active_envelope_valid_until"].is_string());
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn upgraded_host_that_recorded_one_for_a_local_policy_accepts_envelope_v1() {
    let host = Host::new("version: 1\n");
    host.seed_old_state_db(1, 0);

    let rt = host.boot().expect("boot");

    let status = host.status();
    assert_eq!(status["last_applied_policy_version"], 0, "{status}");
    assert_accepted(&host.apply(POLICY, 1), 1);
    assert_eq!(host.file(POLICY), doc(1));
    rt.shutdown_timeout(STOP_DEADLINE);
    let rt = host.boot().expect("restart");
    assert_refused_as_older(&host.apply(POLICY, 1));
    assert!(host.status()["active_envelope_valid_until"].is_string());
    rt.shutdown_timeout(STOP_DEADLINE);
}

struct ChildAgent(Child);

impl Drop for ChildAgent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_agent(mut agent: Command) -> ChildAgent {
    let child = agent
        .arg("run")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    ChildAgent(child)
}

impl Host {
    fn agent_command(&self) -> Command {
        let mut agent = Command::new(env!("CARGO_BIN_EXE_lodeline"));
        agent
            .env("HOME", self.path("."))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .arg("--state-db")
            .arg(self.path("state.db"))
            .arg("--events-dir")
            .arg(self.path("events"))
            .arg("--control-socket")
            .arg(self.path("c.sock"))
            .arg("--keystore")
            .arg(self.path("keystore.json"))
            .arg("--poll");
        agent
    }

    fn spawn_child(&self) -> ChildAgent {
        let mut agent = self.agent_command();
        agent.arg("--policy").arg(self.path("policy.yaml"));
        spawn_agent(agent)
    }

    fn wait_until_serving(&self) {
        let deadline = Instant::now() + CHILD_DEADLINE;
        while !self
            .try_control(&json!({"cmd": "stats"}))
            .is_ok_and(|r| r["ok"] == true)
        {
            assert!(Instant::now() < deadline, "child agent never served");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Runs a query long enough to outlast the test whenever the agent writes the
    /// record, and leaves the agent inside that transaction until it is killed.
    fn hold_the_record_write(&self, artifact: Artifact) {
        self.sql(&format!(
            "CREATE TABLE spin (x INTEGER);
             WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 1000)
             INSERT INTO spin SELECT x FROM n;
             CREATE TRIGGER stop_here BEFORE UPDATE OF {} ON host_meta
             BEGIN SELECT count(*) FROM spin a, spin b, spin c, spin d; END;",
            artifact.column
        ));
    }

    /// Sends an apply and leaves it unanswered, for an agent that will not answer.
    fn send_apply(&self, artifact: Artifact, version: i64) -> UnixStream {
        let response = self.signed(version, &doc(version));
        let mut stream = UnixStream::connect(self.path("c.sock")).unwrap();
        let mut request = json!({"cmd": artifact.apply, "response": response}).to_string();
        request.push('\n');
        stream.write_all(request.as_bytes()).unwrap();
        stream
    }

    /// The agent blocks in the open of its temp file until the FIFO has a reader,
    /// which is after it recorded the apply and before the rename.
    fn hold_the_file_write(&self, artifact: Artifact, agent: &ChildAgent) {
        let temp = self.path(&format!(".{}.{}.tmp", artifact.file, agent.0.id()));
        let made = Command::new("mkfifo").arg(temp).status().unwrap();
        assert!(made.success(), "mkfifo");
    }

    fn wait_for_the_pending_record(&self, artifact: Artifact, version: i64) {
        let deadline = Instant::now() + CHILD_DEADLINE;
        while self.pending(artifact) != Some(version) {
            assert!(Instant::now() < deadline, "the apply was never recorded");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_for_the_file(&self, artifact: Artifact, version: i64) {
        let deadline = Instant::now() + CHILD_DEADLINE;
        while std::fs::read(self.path(artifact.file)).unwrap() != doc(version).as_bytes() {
            assert!(Instant::now() < deadline, "the rename never happened");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Returns once the child holds the write lock across several probes, which
    /// outlasts the short writes of its startup, or after a bounded wait when the child
    /// has nothing to repair.
    fn wait_for_the_held_write(&self) {
        let probe = Connection::open(self.path("state.db")).unwrap();
        probe.busy_timeout(Duration::ZERO).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut held = 0;
        while held < 5 && Instant::now() < deadline {
            let idle = probe.execute_batch("BEGIN IMMEDIATE; ROLLBACK;").is_ok();
            held = if idle { 0 } else { held + 1 };
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn sigkill_after_the_rename_and_during_repair_keeps_the_newest_version(artifact: Artifact) {
    let host = Host::new("version: 1\n");
    let mut agent = host.spawn_child();
    host.wait_until_serving();
    assert_accepted(&host.apply(artifact, 2), 2);
    host.hold_the_record_write(artifact);
    let _held_request = host.send_apply(artifact, 5);

    host.wait_for_the_file(artifact, 5);
    agent.0.kill().unwrap();
    agent.0.wait().unwrap();

    assert_eq!(host.file(artifact), doc(5), "the rename happened");
    assert_eq!(host.recorded(artifact), 2, "the record did not move");
    drop(agent);
    let mut agent = host.spawn_child();
    host.wait_for_the_held_write();
    agent.0.kill().unwrap();
    agent.0.wait().unwrap();
    assert_eq!(host.recorded(artifact), 2, "repair did not commit");
    drop(agent);
    host.sql("DROP TRIGGER stop_here; DROP TABLE spin;");

    let _agent = host.spawn_child();
    host.wait_until_serving();

    host.assert_older_envelope_is_refused(artifact);
}

#[test]
fn sigkill_after_the_policy_rename_and_during_repair_keeps_the_newest_version() {
    sigkill_after_the_rename_and_during_repair_keeps_the_newest_version(POLICY);
}

#[test]
fn sigkill_after_the_rule_pack_rename_and_during_repair_keeps_the_newest_version() {
    sigkill_after_the_rename_and_during_repair_keeps_the_newest_version(RULE_PACKS);
}

fn sigkill_between_the_record_and_the_rename_leaves_the_host_unchanged(artifact: Artifact) {
    let host = Host::new("version: 1\n");
    let mut agent = host.spawn_child();
    host.wait_until_serving();
    assert_accepted(&host.apply(artifact, 2), 2);
    host.hold_the_file_write(artifact, &agent);
    let _held_request = host.send_apply(artifact, 5);

    host.wait_for_the_pending_record(artifact, 5);
    agent.0.kill().unwrap();
    agent.0.wait().unwrap();

    assert_eq!(host.file(artifact), doc(2), "the rename did not happen");
    assert_eq!(host.recorded(artifact), 2, "the record did not move");
    assert_eq!(host.pending(artifact), Some(5), "the record stayed behind");
    drop(agent);
    let _agent = host.spawn_child();
    host.wait_until_serving();

    assert_eq!(host.pending(artifact), None, "boot dropped the record");
    assert_eq!(host.file(artifact), doc(2), "file after boot");
    assert_eq!(host.recorded(artifact), 2, "record after boot");
    assert_accepted(&host.apply(artifact, 5), 5);
    assert_eq!(host.file(artifact), doc(5), "file after the retry");
}

#[test]
fn sigkill_between_the_policy_record_and_the_rename_leaves_the_host_unchanged() {
    sigkill_between_the_record_and_the_rename_leaves_the_host_unchanged(POLICY);
}

#[test]
fn sigkill_between_the_rule_pack_record_and_the_rename_leaves_the_host_unchanged() {
    sigkill_between_the_record_and_the_rename_leaves_the_host_unchanged(RULE_PACKS);
}

const DENY_RULE_AND_TARGET: &str = "version: 1
hook_deny_rules:
  - id: blocked
    match:
      kind: bash
      command:
        kind: regex
        pattern: 'forbidden-command'
targets:
  - id: extra
    description: extra
    tier: standard
    platform: any
    paths: ['/tmp/lodeline-default-path-*.json']
";

const NOT_A_POLICY: &str = ": this is not : valid : yaml :::\n";

/// Under root the default policy path is the real `/etc/lodeline`.
fn default_path_is_real() -> bool {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    if root {
        eprintln!("skipped: the default policy path of root is outside the test");
    }
    root
}

#[track_caller]
fn assert_stops_at_boot(mut agent: ChildAgent, what: &str) {
    let deadline = Instant::now() + CHILD_DEADLINE;
    loop {
        if let Some(status) = agent.0.try_wait().unwrap() {
            assert!(!status.success(), "{what}: {status}");
            return;
        }
        assert!(Instant::now() < deadline, "{what}: the agent kept running");
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl Host {
    fn default_policy_file(&self) -> std::path::PathBuf {
        self.path("config/lodeline/policy.yaml")
    }

    fn write_default_policy(&self, yaml: &str) {
        std::fs::create_dir_all(self.path("config/lodeline")).unwrap();
        std::fs::write(self.default_policy_file(), yaml).unwrap();
    }

    fn denies(&self, command: &str) -> bool {
        let input = json!({"kind": "command", "command": command, "args": []});
        let reply = self.control(&json!({"cmd": "assess", "input": input}));
        assert_eq!(reply["ok"], true, "{reply}");
        !reply["assess_verdict"]["deny_match"].is_null()
    }
}

#[test]
fn restart_without_the_policy_flag_keeps_the_applied_policy_in_force() {
    if default_path_is_real() {
        return;
    }
    let host = Host::new("version: 1\n");
    let mut agent = spawn_agent(host.agent_command());
    host.wait_until_serving();
    assert!(!host.denies("forbidden-command"), "before the apply");
    assert_accepted(&host.apply_policy(5, DENY_RULE_AND_TARGET), 5);
    wait_until("the applied policy loaded", || {
        host.denies("forbidden-command")
    });
    agent.0.kill().unwrap();
    agent.0.wait().unwrap();
    drop(agent);

    let _agent = spawn_agent(host.agent_command());
    host.wait_until_serving();

    assert_eq!(host.status()["last_applied_policy_version"], 5);
    assert!(host.denies("forbidden-command"), "deny rule after restart");
    assert!(host.has_target("extra"), "target after restart");
}

#[test]
fn boot_without_the_policy_flag_loads_a_hand_written_policy() {
    if default_path_is_real() {
        return;
    }
    let host = Host::new("version: 1\n");
    host.write_default_policy(DENY_RULE_AND_TARGET);

    let _agent = spawn_agent(host.agent_command());
    host.wait_until_serving();

    assert!(host.denies("forbidden-command"), "deny rule");
    assert!(host.has_target("extra"), "target");
    assert_eq!(host.status()["last_applied_policy_version"], 0);
}

#[test]
fn a_policy_that_cannot_load_stops_the_boot_with_or_without_the_policy_flag() {
    if default_path_is_real() {
        return;
    }
    let host = Host::new(NOT_A_POLICY);
    host.write_default_policy(NOT_A_POLICY);
    assert_stops_at_boot(host.spawn_child(), "malformed with the flag");
    assert_stops_at_boot(
        spawn_agent(host.agent_command()),
        "malformed without the flag",
    );

    let unreadable = std::fs::Permissions::from_mode(0o000);
    std::fs::set_permissions(host.path("policy.yaml"), unreadable.clone()).unwrap();
    std::fs::set_permissions(host.default_policy_file(), unreadable).unwrap();
    assert_stops_at_boot(host.spawn_child(), "unreadable with the flag");
    assert_stops_at_boot(
        spawn_agent(host.agent_command()),
        "unreadable without the flag",
    );
}

#[test]
fn show_assess_and_doctor_read_the_default_policy_without_the_flag() {
    if default_path_is_real() {
        return;
    }
    let host = Host::new("version: 1\n");
    host.write_default_policy(DENY_RULE_AND_TARGET);
    let stdout = |args: &[&str]| {
        let run = host.agent_command().args(args).output().unwrap();
        String::from_utf8(run.stdout).unwrap()
    };

    assert!(stdout(&["show", "config"]).contains("id: extra"));
    assert!(stdout(&["assess", "--command", "forbidden-command"]).contains("blocked"));

    host.write_default_policy(NOT_A_POLICY);
    assert!(stdout(&["doctor"]).contains("[ERROR] policy parse failed"));
}

#[test]
fn a_policy_path_with_no_directory_applies_and_survives_a_restart() {
    let host = Host::new("version: 1\n");
    let bare_name = || {
        let mut agent = host.agent_command();
        agent
            .current_dir(host.path("."))
            .arg("--policy")
            .arg("policy.yaml");
        agent
    };
    let mut agent = spawn_agent(bare_name());
    host.wait_until_serving();
    let reply = host.apply(POLICY, 2);
    agent.0.kill().unwrap();
    agent.0.wait().unwrap();
    drop(agent);
    assert_accepted(&reply, 2);

    let _agent = spawn_agent(bare_name());
    host.wait_until_serving();

    assert_eq!(host.status()["last_applied_policy_version"], 2);
}
