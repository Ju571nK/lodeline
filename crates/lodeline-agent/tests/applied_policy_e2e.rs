//! e2e: with a local file and a separate apply target, the layout of a root agent
//! with no `--policy`, a signed apply replaces the local file's content without
//! writing it. A host that an older agent applied into keeps working. Unix only,
//! because the requests go over the control socket.
#![cfg(all(unix, feature = "operator-cli"))]

#[path = "common/signed_host.rs"]
mod signed_host;

use lodeline_core::policy::deployment::ArtifactKind;
use lodeline_core::state::HashCache;
use lodeline_core::PendingEnvelope;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};
use signed_host::{Host, STOP_DEADLINE};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

/// Two poll cycles of the agent's 5 s watcher, plus room for a loaded machine.
const RELOAD_DEADLINE: Duration = Duration::from_secs(30);

/// A policy whose deny rule and target name `marker`.
fn policy(marker: &str) -> String {
    format!(
        "version: 1\n\
         targets:\n  - id: {marker}\n    description: x\n    tier: standard\n    platform: any\n    \
         paths:\n      - '/tmp/{marker}'\n    recursive: false\n    follow_symlinks: false\n\
         hook_deny_rules:\n  - id: {marker}\n    match:\n      kind: bash\n      command:\n        \
         kind: equals\n        value: {marker}\n"
    )
}

fn wait_for(host: &Host, what: &str, deadline: Duration, done: impl Fn(&Host) -> bool) {
    let until = Instant::now() + deadline;
    while !done(host) {
        assert!(Instant::now() < until, "never: {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn assert_accepted(reply: &Value, version: i64) {
    assert_eq!(reply["apply_policy"]["outcome"], "accepted", "{reply}");
    assert_eq!(reply["apply_policy"]["applied_policy_version"], version);
}

impl Host {
    fn denies(&self, command: &str) -> bool {
        let reply = self.control(&json!({
            "cmd": "assess",
            "input": {"kind": "command", "command": command, "args": []}
        }));
        !reply["assess_verdict"]["deny_match"].is_null()
    }

    fn reload(&self) {
        assert_eq!(self.control(&json!({"cmd": "reload_policy"}))["ok"], true);
    }

    fn text(&self, name: &str) -> String {
        String::from_utf8(self.read(name)).unwrap()
    }

    fn pending_policy(&self) -> Option<i64> {
        Connection::open(self.path("state.db"))
            .unwrap()
            .query_row(
                "SELECT version FROM pending_envelope WHERE kind = 'policy'",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap()
    }

    fn record_pending(&self, kind: ArtifactKind, version: i64, bytes: &[u8]) {
        HashCache::open(&self.path("state.db"))
            .unwrap()
            .record_pending(
                kind,
                &PendingEnvelope {
                    version,
                    hash_hex: blake3::hash(bytes).to_hex().to_string(),
                    valid_until: OffsetDateTime::now_utc() + time::Duration::hours(1),
                },
            )
            .unwrap();
    }

    /// Leaves `policy.yaml` at the top of the temp dir at `version`, applied there
    /// the way an older agent did.
    fn applied_by_an_older_agent(&self, version: i64, marker: &str) {
        let rt = self.boot().expect("boot without a local layer");
        assert_accepted(&self.apply_policy(version, &policy(marker)), version);
        rt.shutdown_timeout(STOP_DEADLINE);
    }
}

#[test]
fn apply_replaces_the_local_policy_without_writing_it_and_survives_a_restart() {
    let host = Host::new(&policy("local-rule"));
    let rt = host.boot_layered().expect("boot");
    assert!(host.denies("local-rule"));

    assert_accepted(&host.apply_policy(1, &policy("signed-rule")), 1);

    wait_for(&host, "signed rule live", RELOAD_DEADLINE, |h| {
        h.denies("signed-rule")
    });
    assert!(!host.denies("local-rule"), "the signed policy replaces it");
    assert_eq!(host.text("policy.yaml"), policy("local-rule"));
    assert_eq!(host.text("applied/policy.yaml"), policy("signed-rule"));

    rt.shutdown_timeout(STOP_DEADLINE);
    let rt = host.boot_layered().expect("restart");
    assert!(host.denies("signed-rule"));
    assert!(!host.denies("local-rule"));
    assert_eq!(host.watermark(), 1);

    assert_accepted(&host.apply_policy(2, &policy("second-rule")), 2);
    wait_for(&host, "second rule live", RELOAD_DEADLINE, |h| {
        h.denies("second-rule")
    });
    assert_eq!(host.text("policy.yaml"), policy("local-rule"));
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn a_policy_an_older_agent_applied_keeps_loading_and_the_next_apply_moves_on() {
    let host = Host::new(&policy("first-rule"));
    host.applied_by_an_older_agent(3, "older-rule");

    let rt = host.boot_layered().expect("upgrade boot");

    assert!(host.denies("older-rule"));
    assert_eq!(host.watermark(), 3);
    let older = host.apply_policy(2, &policy("stale-rule"));
    assert_eq!(older["apply_policy"]["reason"], "version_regression");

    assert_accepted(&host.apply_policy(4, &policy("newer-rule")), 4);
    wait_for(&host, "newer rule live", RELOAD_DEADLINE, |h| {
        h.denies("newer-rule")
    });
    assert_eq!(host.text("policy.yaml"), policy("older-rule"));
    assert_eq!(host.text("applied/policy.yaml"), policy("newer-rule"));
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn a_rename_an_older_agent_finished_is_settled_against_the_local_file() {
    let host = Host::new(&policy("first-rule"));
    host.applied_by_an_older_agent(2, "older-rule");
    std::fs::write(host.path("policy.yaml"), policy("renamed-rule")).unwrap();
    host.record_pending(ArtifactKind::Policy, 5, policy("renamed-rule").as_bytes());

    let rt = host.boot_layered().expect("upgrade boot");

    assert_eq!(host.pending_policy(), None);
    assert_eq!(host.watermark(), 5, "the apply had finished");
    assert!(host.denies("renamed-rule"));
    assert_accepted(&host.apply_policy(6, &policy("newer-rule")), 6);
    assert_eq!(host.text("applied/policy.yaml"), policy("newer-rule"));
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn an_older_agent_apply_that_never_renamed_is_dropped_and_a_retry_applies() {
    let host = Host::new(&policy("first-rule"));
    host.applied_by_an_older_agent(2, "older-rule");
    host.record_pending(ArtifactKind::Policy, 5, policy("never-written").as_bytes());

    let rt = host.boot_layered().expect("upgrade boot");

    assert_eq!(host.pending_policy(), None);
    assert_eq!(host.watermark(), 2, "the apply did not happen");
    assert!(host.denies("older-rule"));
    assert_accepted(&host.apply_policy(5, &policy("never-written")), 5);
    assert_eq!(host.text("applied/policy.yaml"), policy("never-written"));
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn a_bundle_an_older_agent_applied_keeps_loading_and_its_unfinished_apply_settles() {
    let host = Host::new("version: 1\n");
    let rt = host.boot().expect("boot without a local layer");
    assert_accepted(&host.apply_rule_packs(2, &policy("older-pack")), 2);
    rt.shutdown_timeout(STOP_DEADLINE);
    std::fs::write(host.path("rule-packs.yaml"), policy("renamed-pack")).unwrap();
    host.record_pending(
        ArtifactKind::RulePacks,
        5,
        policy("renamed-pack").as_bytes(),
    );

    let rt = host.boot_layered().expect("upgrade boot");

    assert!(host.denies("renamed-pack"));
    let older = host.apply_rule_packs(4, &policy("stale-pack"));
    assert_eq!(older["apply_policy"]["reason"], "version_regression");
    assert_accepted(&host.apply_rule_packs(6, &policy("newer-pack")), 6);
    assert_eq!(host.text("applied/rule-packs.yaml"), policy("newer-pack"));
    assert_eq!(host.text("rule-packs.yaml"), policy("renamed-pack"));
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn reload_reads_the_file_in_force() {
    let host = Host::new(&policy("local-rule"));
    let rt = host.boot_layered().expect("boot");

    std::fs::write(host.path("policy.yaml"), policy("edited-rule")).unwrap();
    host.reload();
    wait_for(&host, "local edit live", RELOAD_DEADLINE, |h| {
        h.denies("edited-rule")
    });

    assert_accepted(&host.apply_policy(1, &policy("signed-rule")), 1);
    wait_for(&host, "signed rule live", RELOAD_DEADLINE, |h| {
        h.denies("signed-rule")
    });

    std::fs::write(host.path("policy.yaml"), policy("shadowed-rule")).unwrap();
    host.reload();
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        host.denies("signed-rule"),
        "the applied file stays in force"
    );
    assert!(!host.denies("shadowed-rule"));

    std::fs::remove_file(host.path("applied/policy.yaml")).unwrap();
    host.reload();
    wait_for(&host, "local file back in force", RELOAD_DEADLINE, |h| {
        h.denies("shadowed-rule")
    });
    assert!(!host.denies("signed-rule"));
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn each_file_resolves_on_its_own() {
    let host = Host::new(&policy("local-rule"));
    let rt = host.boot_layered().expect("boot");

    assert_accepted(&host.apply_rule_packs(1, &policy("signed-pack")), 1);

    wait_for(&host, "signed pack live", RELOAD_DEADLINE, |h| {
        h.denies("signed-pack")
    });
    assert!(host.denies("local-rule"), "the local policy stays in force");
    assert!(!host.path("applied/policy.yaml").exists());
    assert!(!host.path("rule-packs.yaml").exists());
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn a_rule_pack_change_reloads_the_file_in_force() {
    let host = Host::new("version: 1\n");
    let rt = host.boot_layered().expect("boot");

    // Keep changing the file: a write before the watcher's first scan is no change.
    let writes = std::cell::Cell::new(0);
    wait_for(&host, "local pack live", RELOAD_DEADLINE, |h| {
        writes.set(writes.get() + 1);
        let yaml = format!("{}# write {}\n", policy("local-pack"), writes.get());
        std::fs::write(h.path("rule-packs.yaml"), yaml).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        h.denies("local-pack")
    });

    assert_accepted(&host.apply_rule_packs(1, &policy("signed-pack")), 1);
    wait_for(&host, "signed pack live", RELOAD_DEADLINE, |h| {
        h.denies("signed-pack")
    });
    assert!(
        !host.denies("local-pack"),
        "the bundle replaces the local file"
    );

    std::fs::remove_file(host.path("applied/rule-packs.yaml")).unwrap();
    wait_for(&host, "local pack back in force", RELOAD_DEADLINE, |h| {
        h.denies("local-pack")
    });
    assert!(!host.denies("signed-pack"));
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn a_bundle_goes_live_on_a_host_with_no_policy_file() {
    let host = Host::new("version: 1\n");
    std::fs::remove_file(host.path("policy.yaml")).unwrap();
    let rt = host.boot_layered().expect("boot");

    assert_accepted(&host.apply_rule_packs(1, &policy("signed-pack")), 1);

    wait_for(&host, "signed pack live", RELOAD_DEADLINE, |h| {
        h.denies("signed-pack")
    });
    rt.shutdown_timeout(STOP_DEADLINE);
}
