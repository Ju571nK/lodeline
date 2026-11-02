//! e2e: with a local file and a separate apply target, the layout of a root agent
//! with no `--policy`, a signed apply replaces the local file's content without
//! writing it. A host that an older agent applied into keeps working. Unix only,
//! because the requests go over the control socket.
#![cfg(all(unix, feature = "operator-cli"))]

#[path = "common/signed_host.rs"]
mod signed_host;

use lodeline_agent::runtime::{PolicyPaths, SignedFile};
use lodeline_core::policy::deployment::ArtifactKind;
use lodeline_core::state::HashCache;
use lodeline_core::PendingEnvelope;
use serde_json::{json, Value};
use signed_host::{policy, Artifact, Host, POLICY, RULE_PACKS, STOP_DEADLINE};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::runtime::Runtime;

/// Two poll cycles of the agent's 5 s watcher, plus room for a loaded machine.
const RELOAD_DEADLINE: Duration = Duration::from_secs(30);

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
    fn apply(&self, artifact: Artifact, version: i64, yaml: &str) -> Value {
        let response = self.signed(version, yaml);
        self.control(&json!({"cmd": artifact.apply, "response": response}))
    }

    fn applied_file(&self, artifact: Artifact) -> String {
        self.text(&format!("applied/{}", artifact.file))
    }

    fn reload(&self) {
        assert_eq!(self.control(&json!({"cmd": "reload_policy"}))["ok"], true);
    }

    fn text(&self, name: &str) -> String {
        String::from_utf8(self.read(name)).unwrap()
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

    assert_eq!(host.pending(POLICY), None);
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

    assert_eq!(host.pending(POLICY), None);
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

fn a_bundle_goes_live_with_no_restart_on_a_host_with_no_policy_file(
    boot: fn(&Host) -> Result<Runtime, String>,
) {
    let host = Host::new("version: 1\n");
    std::fs::remove_file(host.path("policy.yaml")).unwrap();
    let rt = boot(&host).expect("boot");

    assert_accepted(&host.apply_rule_packs(1, &policy("signed-pack")), 1);

    wait_for(&host, "signed pack live", RELOAD_DEADLINE, |h| {
        h.denies("signed-pack")
    });
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn a_bundle_goes_live_on_a_layered_host_with_no_policy_file() {
    a_bundle_goes_live_with_no_restart_on_a_host_with_no_policy_file(Host::boot_layered);
}

#[test]
fn a_bundle_goes_live_with_a_policy_path_that_has_no_file() {
    a_bundle_goes_live_with_no_restart_on_a_host_with_no_policy_file(Host::boot);
}

#[test]
fn deleting_the_applied_policy_with_no_local_file_keeps_it_until_a_restart() {
    let host = Host::new("version: 1\n");
    std::fs::remove_file(host.path("policy.yaml")).unwrap();
    let rt = host.boot_layered().expect("boot");
    assert_accepted(&host.apply_policy(1, &policy("signed-rule")), 1);
    wait_for(&host, "signed rule live", RELOAD_DEADLINE, |h| {
        h.denies("signed-rule")
    });

    std::fs::remove_file(host.path("applied/policy.yaml")).unwrap();
    host.reload();
    std::thread::sleep(Duration::from_millis(500));
    assert!(host.denies("signed-rule"), "kept until a restart");

    rt.shutdown_timeout(STOP_DEADLINE);
    let rt = host.boot_layered().expect("restart");
    assert!(!host.denies("signed-rule"));
    assert_eq!(host.watermark(), 1, "the signed version stays on record");
    let older = host.apply_policy(1, &policy("same-version"));
    assert_eq!(older["apply_policy"]["reason"], "version_regression");
    assert_accepted(&host.apply_policy(2, &policy("higher-rule")), 2);
    rt.shutdown_timeout(STOP_DEADLINE);
}

fn a_first_apply_stopped_after_its_rename_finishes_at_boot(artifact: Artifact) {
    let host = Host::new(&policy("local-rule"));
    let rt = host.boot_layered().expect("boot");
    host.stop_the_record_write(artifact);

    let reply = host.apply(artifact, 5, &policy("renamed-rule"));

    assert_eq!(reply["ok"], false, "{reply}");
    assert_eq!(host.pending(artifact), Some(5));
    assert_eq!(host.recorded(artifact), 0);
    rt.shutdown_timeout(STOP_DEADLINE);
    host.sql("DROP TRIGGER stop_here");

    let rt = host.boot_layered().expect("restart");

    assert_eq!(host.pending(artifact), None);
    assert_eq!(host.recorded(artifact), 5, "the apply had finished");
    assert!(host.denies("renamed-rule"));
    assert_eq!(host.applied_file(artifact), policy("renamed-rule"));
    assert_eq!(host.text("policy.yaml"), policy("local-rule"));
    let older = host.apply(artifact, 5, &policy("same-version"));
    assert_eq!(older["apply_policy"]["reason"], "version_regression");
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn a_first_policy_apply_stopped_after_its_rename_finishes_at_boot() {
    a_first_apply_stopped_after_its_rename_finishes_at_boot(POLICY);
}

#[test]
fn a_first_bundle_apply_stopped_after_its_rename_finishes_at_boot() {
    a_first_apply_stopped_after_its_rename_finishes_at_boot(RULE_PACKS);
}

fn a_first_apply_stopped_before_its_rename_is_dropped_and_a_retry_applies(artifact: Artifact) {
    let host = Host::new(&policy("local-rule"));
    let rt = host.boot_layered().expect("boot");
    let temp = format!("applied/.{}.{}.tmp", artifact.file, std::process::id());
    std::fs::create_dir(host.path(&temp)).unwrap();

    let reply = host.apply(artifact, 5, &policy("unwritten-rule"));

    assert_eq!(reply["ok"], false, "{reply}");
    assert_eq!(host.pending(artifact), Some(5));
    rt.shutdown_timeout(STOP_DEADLINE);
    std::fs::remove_dir(host.path(&temp)).unwrap();

    let rt = host.boot_layered().expect("restart");

    assert_eq!(host.pending(artifact), None);
    assert_eq!(host.recorded(artifact), 0, "the apply did not happen");
    assert!(host.denies("local-rule"));
    assert!(!host.denies("unwritten-rule"));
    assert_accepted(&host.apply(artifact, 5, &policy("unwritten-rule")), 5);
    assert_eq!(host.applied_file(artifact), policy("unwritten-rule"));
    assert_eq!(host.text("policy.yaml"), policy("local-rule"));
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn a_first_policy_apply_stopped_before_its_rename_is_dropped_and_a_retry_applies() {
    a_first_apply_stopped_before_its_rename_is_dropped_and_a_retry_applies(POLICY);
}

#[test]
fn a_first_bundle_apply_stopped_before_its_rename_is_dropped_and_a_retry_applies() {
    a_first_apply_stopped_before_its_rename_is_dropped_and_a_retry_applies(RULE_PACKS);
}

fn set_mode(dir: &Path, mode: u32) {
    let mode = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(dir, mode).unwrap();
}

#[test]
fn boot_leaves_no_apply_directory_it_could_not_sync() {
    let host = Host::new(&policy("local-rule"));
    let sealed = host.path("sealed");
    std::fs::create_dir(&sealed).unwrap();
    set_mode(&sealed, 0o300);
    if std::fs::File::open(&sealed).is_ok() {
        eprintln!("skipped: root ignores directory modes");
        return;
    }
    let file = |name: &str| SignedFile {
        applied: sealed.join("applied").join(name),
        local: Some(host.path(name)),
    };

    let rt = host
        .boot_with(PolicyPaths {
            policy: file("policy.yaml"),
            rule_packs: file("rule-packs.yaml"),
        })
        .expect("boot");

    assert!(!sealed.join("applied").exists());
    assert!(host.denies("local-rule"));
    assert_eq!(host.apply_policy(1, &policy("signed-rule"))["ok"], false);
    set_mode(&sealed, 0o700);
    assert_accepted(&host.apply_policy(1, &policy("signed-rule")), 1);
    assert_eq!(
        host.text("sealed/applied/policy.yaml"),
        policy("signed-rule")
    );
    rt.shutdown_timeout(STOP_DEADLINE);
}
