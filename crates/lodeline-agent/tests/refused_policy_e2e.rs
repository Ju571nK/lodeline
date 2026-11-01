//! e2e: a signed document the agent could not load is refused. The host keeps
//! its files, its watermark and its enforcement, and a restart still boots.
//!
//! Each boot has its own tokio runtime so that a restart really ends the first
//! agent. Unix only, because the requests go over the control socket.
#![cfg(all(unix, feature = "operator-cli"))]

use ed25519_dalek::{Signer, SigningKey};
use lodeline_agent::runtime::{self, RuntimeConfig};
use lodeline_core::policy::canonical::to_canonical_bytes;
use lodeline_core::policy::pubkeys::{Keystore, KeystoreEntry};
use lodeline_core::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::runtime::Runtime;

const BOOT_DEADLINE: Duration = Duration::from_secs(60);
const STOP_DEADLINE: Duration = Duration::from_secs(5);

fn doc_denying(rule_id: &str, pattern: &str) -> String {
    format!(
        "version: 1\nhook_deny_rules:\n  - id: {rule_id}\n    match:\n      kind: bash\n      command:\n        kind: regex\n        pattern: '{pattern}'\n"
    )
}

/// A rule pack that reports `file` when its `mode` is `off`. `tool: other` keeps
/// the report apart from what the built-in parsers say about the test user's home.
fn doc_with_pack(file: &str, pattern: &str, when_pattern: &str) -> String {
    format!(
        "version: 1\nrule_packs:\n  - id: reported\n    pack_version: 2\n    tool: other\n    tool_label: acme\n    scope: {{kind: user_global}}\n    watched_paths: ['{file}']\n    rules:\n      - id: r\n        on_file: '{file}'\n        format: json\n        selector: $.mode\n        matcher: {{kind: regex, pattern: '{pattern}'}}\n        emit: {{kind: sandbox_disabled}}\n        when:\n          - selector: $.mode\n            matcher: {{kind: regex, pattern: '{when_pattern}'}}\n"
    )
}

fn doc_with_target(glob: &str) -> String {
    format!(
        "version: 1\ntargets:\n  - id: extra\n    description: extra\n    tier: standard\n    platform: any\n    paths: ['{glob}']\n"
    )
}

struct Host {
    td: TempDir,
    sk: SigningKey,
}

impl Host {
    fn new(policy_yaml: &str) -> Self {
        let td = TempDir::new().unwrap();
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let now = OffsetDateTime::now_utc();
        let keystore = Keystore {
            pubkeys: vec![KeystoreEntry {
                id: "k1".into(),
                ed25519_pubkey_b64: data_encoding::BASE64.encode(&sk.verifying_key().to_bytes()),
                valid_from: now - time::Duration::days(1),
                valid_until: now + time::Duration::days(1),
            }],
        };
        std::fs::write(
            td.path().join("keystore.json"),
            serde_json::to_vec(&keystore).unwrap(),
        )
        .unwrap();
        std::fs::write(td.path().join("policy.yaml"), policy_yaml).unwrap();
        Self { td, sk }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.td.path().join(name)
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.path(name)).unwrap()
    }

    fn boot(&self) -> Result<Runtime, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let agent = rt.spawn(runtime::run(RuntimeConfig {
            policy_path: Some(self.path("policy.yaml")),
            state_db_path: self.path("state.db"),
            events_dir: self.path("events"),
            control_socket: self.path("c.sock"),
            control_pipe_name: String::new(),
            poll_watcher: false,
            keystore_path: Some(self.path("keystore.json")),
        }));
        let deadline = Instant::now() + BOOT_DEADLINE;
        while Instant::now() < deadline {
            if agent.is_finished() {
                let ended = rt.block_on(agent).unwrap();
                return Err(format!("agent stopped at boot: {ended:?}"));
            }
            if self
                .try_control(&json!({"cmd": "stats"}))
                .is_ok_and(|r| r["ok"] == true)
            {
                return Ok(rt);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err(format!("control socket not ready in {BOOT_DEADLINE:?}"))
    }

    fn try_control(&self, req: &Value) -> std::io::Result<Value> {
        let mut stream = UnixStream::connect(self.path("c.sock"))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut bytes = serde_json::to_vec(req).unwrap();
        bytes.push(b'\n');
        stream.write_all(&bytes)?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        Ok(serde_json::from_str(line.trim()).unwrap_or(Value::Null))
    }

    fn control(&self, req: &Value) -> Value {
        self.try_control(req).expect("control request")
    }

    fn signed(&self, version: i64, yaml: &str) -> SignedPolicyResponse {
        let now = OffsetDateTime::now_utc();
        let envelope = SignedEnvelope {
            policy_version: version,
            policy_bytes_b64: data_encoding::BASE64.encode(yaml.as_bytes()),
            valid_until: now + time::Duration::hours(1),
            issued_at: now,
        };
        let canonical = to_canonical_bytes(&envelope).unwrap();
        SignedPolicyResponse {
            etag: blake3::hash(&canonical).to_hex().to_string(),
            signed_envelope: envelope,
            signature: data_encoding::BASE64.encode(&self.sk.sign(&canonical).to_bytes()),
            signing_pubkey_id: "k1".into(),
            applied_at: now,
        }
    }

    fn apply_policy(&self, version: i64, yaml: &str) -> Value {
        self.control(&json!({"cmd": "apply_policy", "response": self.signed(version, yaml)}))
    }

    fn apply_rule_packs(&self, version: i64, yaml: &str) -> Value {
        self.control(&json!({"cmd": "apply_rule_packs", "response": self.signed(version, yaml)}))
    }

    fn watermark(&self) -> i64 {
        self.control(&json!({"cmd": "policy_status"}))["policy_status"]
            ["last_applied_policy_version"]
            .as_i64()
            .unwrap()
    }

    fn denies(&self, command: &str) -> bool {
        let reply = self.control(&json!({
            "cmd": "assess",
            "input": {"kind": "command", "command": command, "args": []},
        }));
        assert_eq!(reply["ok"], true, "assess failed: {reply}");
        !reply["assess_verdict"]["deny_match"].is_null()
    }

    fn tool_config(&self) -> String {
        let path = self.path("tool.json");
        std::fs::write(&path, r#"{"mode": "off"}"#).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn pack_reports(&self) -> bool {
        let reply = self.control(&json!({"cmd": "risk", "tool": "other"}));
        reply["risk"]["assessments"]
            .as_array()
            .is_some_and(|a| a.iter().any(|r| r["reasons_count"].as_u64() > Some(0)))
    }

    fn wait_until_pack_reports(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.pack_reports() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the rule pack never reported");
    }

    fn target_globs(&self, id: &str) -> Vec<Value> {
        let reply = self.control(&json!({"cmd": "targets"}));
        reply["targets"]["targets"]
            .as_array()
            .and_then(|all| all.iter().find(|t| t["id"] == id))
            .and_then(|t| t["globs"].as_array())
            .cloned()
            .unwrap_or_default()
    }

    fn wait_until_denied(&self, command: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.denies(command) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("{command} was never denied");
    }
}

#[track_caller]
fn assert_refused(reply: &Value) {
    assert_eq!(reply["ok"], false, "{reply}");
    assert_eq!(reply["apply_policy"]["outcome"], "rejected", "{reply}");
    assert_eq!(reply["apply_policy"]["reason"], "parse_failed", "{reply}");
}

/// Offer `refused` to a host that enforces one deny rule, then restart it.
#[track_caller]
fn host_is_unchanged_after_refusing(refused: &str) {
    let host = Host::new(&doc_denying("enforced", "marker-a"));
    let rt = host.boot().expect("first boot");
    assert!(host.denies("marker-a"), "rule enforced before the apply");
    let policy_before = host.read("policy.yaml");
    let watermark_before = host.watermark();

    assert_refused(&host.apply_policy(watermark_before + 1, refused));

    assert_eq!(host.read("policy.yaml"), policy_before, "policy on disk");
    assert_eq!(host.watermark(), watermark_before, "watermark");
    assert!(host.denies("marker-a"), "running policy keeps enforcing");

    rt.shutdown_timeout(STOP_DEADLINE);
    let rt = host.boot().expect("restart after a refused policy");
    assert_eq!(
        host.read("policy.yaml"),
        policy_before,
        "policy after restart"
    );
    assert_eq!(
        host.watermark(),
        watermark_before,
        "watermark after restart"
    );
    assert!(host.denies("marker-a"), "enforcement survives the restart");
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn unsupported_version_is_refused_and_the_host_is_unchanged() {
    host_is_unchanged_after_refusing(&doc_denying("next", "marker-b").replacen(
        "version: 1",
        "version: 2",
        1,
    ));
}

#[test]
fn deny_regex_that_does_not_compile_is_refused_and_the_host_is_unchanged() {
    host_is_unchanged_after_refusing(&doc_denying("next", "("));
}

#[test]
fn override_of_an_unknown_target_is_refused_and_the_host_is_unchanged() {
    host_is_unchanged_after_refusing(&format!(
        "{}overrides:\n  - id: no-such-target\n    disabled: true\n",
        doc_denying("next", "marker-b")
    ));
}

#[test]
fn rule_pack_regex_that_does_not_compile_is_refused_and_the_host_is_unchanged() {
    host_is_unchanged_after_refusing(&doc_with_pack("/no/such/file", "(", "off"));
}

#[test]
fn rule_pack_condition_regex_that_does_not_compile_is_refused_and_the_host_is_unchanged() {
    host_is_unchanged_after_refusing(&doc_with_pack("/no/such/file", "off", "("));
}

#[test]
fn target_glob_that_does_not_compile_is_refused_and_the_host_is_unchanged() {
    host_is_unchanged_after_refusing(&doc_with_target("/no/such/["));
}

#[test]
fn hook_silence_tick_of_zero_is_refused_and_the_host_is_unchanged() {
    host_is_unchanged_after_refusing(
        "version: 1\nhook_silence:\n  enabled_agents: [claude_code]\n  tick_secs: 0\n",
    );
}

#[test]
fn accepted_policy_takes_effect_and_survives_a_restart() {
    let host = Host::new(&doc_denying("first", "marker-a"));
    let rt = host.boot().expect("first boot");
    let next = doc_denying("second", "marker-b");
    let version = host.watermark() + 1;

    let reply = host.apply_policy(version, &next);

    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["apply_policy"]["outcome"], "accepted", "{reply}");
    assert_eq!(reply["apply_policy"]["applied_policy_version"], version);
    assert_eq!(host.read("policy.yaml"), next.as_bytes());
    host.wait_until_denied("marker-b");

    rt.shutdown_timeout(STOP_DEADLINE);
    let rt = host.boot().expect("restart after an accepted policy");
    assert_eq!(host.watermark(), version);
    assert!(host.denies("marker-b"), "new rule enforced after restart");
    assert!(!host.denies("marker-a"), "old rule gone after restart");
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn accepted_rule_pack_and_target_glob_still_load_after_a_restart() {
    let host = Host::new("version: 1\n");
    let file = host.tool_config();
    let rt = host.boot().expect("first boot");
    let target = doc_with_target("/no/such/*.json");
    let target = target.strip_prefix("version: 1\n").unwrap();
    let next = format!("{}{target}", doc_with_pack(&file, "^off$", "off"));

    let reply = host.apply_policy(host.watermark() + 1, &next);

    assert_eq!(reply["apply_policy"]["outcome"], "accepted", "{reply}");
    rt.shutdown_timeout(STOP_DEADLINE);
    let rt = host.boot().expect("restart after an accepted policy");
    host.wait_until_pack_reports();
    assert_eq!(host.target_globs("extra").len(), 1, "target glob compiled");
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn refused_bundle_keeps_the_running_rule_pack_across_a_restart() {
    let host = Host::new("version: 1\n");
    let file = host.tool_config();
    let rt = host.boot().expect("first boot");
    let reply = host.apply_rule_packs(1, &doc_with_pack(&file, "off", "off"));
    assert_eq!(reply["apply_policy"]["outcome"], "accepted", "{reply}");
    let bundle_before = host.read("rule-packs.yaml");

    assert_refused(&host.apply_rule_packs(2, &doc_with_pack(&file, "(", "off")));

    assert_eq!(
        host.read("rule-packs.yaml"),
        bundle_before,
        "bundle on disk"
    );
    rt.shutdown_timeout(STOP_DEADLINE);
    let rt = host.boot().expect("restart after a refused bundle");
    host.wait_until_pack_reports();
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn bundle_applies_whatever_its_policy_only_fields_say() {
    let host = Host::new("version: 1\n");
    let rt = host.boot().expect("first boot");
    let bundle = format!(
        "{}overrides:\n  - id: no-such-target\n    disabled: true\n",
        doc_denying("bundled", "marker-a")
    );

    let reply = host.apply_rule_packs(1, &bundle);

    assert_eq!(reply["apply_policy"]["outcome"], "accepted", "{reply}");
    host.wait_until_denied("marker-a");
    rt.shutdown_timeout(STOP_DEADLINE);
    let rt = host.boot().expect("restart after an accepted bundle");
    assert!(host.denies("marker-a"), "bundled rule survives the restart");
    rt.shutdown_timeout(STOP_DEADLINE);
}

#[test]
fn refused_bundle_keeps_the_applied_bundle_across_a_restart() {
    let host = Host::new("version: 1\n");
    let rt = host.boot().expect("first boot");
    let reply = host.apply_rule_packs(1, &doc_denying("bundled", "marker-a"));
    assert_eq!(reply["apply_policy"]["outcome"], "accepted", "{reply}");
    host.wait_until_denied("marker-a");
    let bundle_before = host.read("rule-packs.yaml");

    assert_refused(&host.apply_rule_packs(
        2,
        &doc_denying("bundled", "marker-b").replacen("version: 1", "version: 2", 1),
    ));

    assert_eq!(
        host.read("rule-packs.yaml"),
        bundle_before,
        "bundle on disk"
    );
    rt.shutdown_timeout(STOP_DEADLINE);
    let rt = host.boot().expect("restart after a refused bundle");
    assert!(host.denies("marker-a"), "bundled rule survives the restart");
    rt.shutdown_timeout(STOP_DEADLINE);
}
