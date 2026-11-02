//! A signing key and the files of one agent, for the signed-policy e2e tests.
//! Each boot has its own tokio runtime, so that a restart really ends the agent.
#![allow(dead_code)]

use ed25519_dalek::{Signer, SigningKey};
use lodeline_agent::runtime::{self, PolicyPaths, RuntimeConfig, SignedFile};
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
pub const STOP_DEADLINE: Duration = Duration::from_secs(5);

pub struct Host {
    td: TempDir,
    sk: SigningKey,
}

impl Host {
    pub fn new(policy_yaml: &str) -> Self {
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

    pub fn path(&self, name: &str) -> PathBuf {
        self.td.path().join(name)
    }

    pub fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.path(name)).unwrap()
    }

    pub fn boot(&self) -> Result<Runtime, String> {
        self.boot_with(PolicyPaths::at(self.path("policy.yaml")))
    }

    /// Boots with applies going under `applied/`, and the top of the temp dir as the
    /// local files: the layout of a root agent with no `--policy`.
    pub fn boot_layered(&self) -> Result<Runtime, String> {
        let file = |name: &str| SignedFile {
            applied: self.path("applied").join(name),
            local: Some(self.path(name)),
        };
        self.boot_with(PolicyPaths {
            policy: file("policy.yaml"),
            rule_packs: file("rule-packs.yaml"),
        })
    }

    fn boot_with(&self, policy_paths: PolicyPaths) -> Result<Runtime, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let agent = rt.spawn(runtime::run(RuntimeConfig {
            policy_paths,
            state_db_path: self.path("state.db"),
            events_dir: self.path("events"),
            control_socket: self.path("c.sock"),
            control_pipe_name: String::new(),
            // These tests use no file events, and native watch setup took 40 s per
            // boot on a developer Mac with the tests running in parallel.
            poll_watcher: true,
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

    pub fn try_control(&self, req: &Value) -> std::io::Result<Value> {
        let mut stream = UnixStream::connect(self.path("c.sock"))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut bytes = serde_json::to_vec(req).unwrap();
        bytes.push(b'\n');
        stream.write_all(&bytes)?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        Ok(serde_json::from_str(line.trim()).unwrap_or(Value::Null))
    }

    pub fn control(&self, req: &Value) -> Value {
        self.try_control(req).expect("control request")
    }

    pub fn signed(&self, version: i64, yaml: &str) -> SignedPolicyResponse {
        let in_an_hour = OffsetDateTime::now_utc() + time::Duration::hours(1);
        self.signed_until(version, yaml, in_an_hour)
    }

    pub fn signed_until(
        &self,
        version: i64,
        yaml: &str,
        valid_until: OffsetDateTime,
    ) -> SignedPolicyResponse {
        let now = OffsetDateTime::now_utc();
        let envelope = SignedEnvelope {
            policy_version: version,
            policy_bytes_b64: data_encoding::BASE64.encode(yaml.as_bytes()),
            valid_until,
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

    pub fn apply_policy(&self, version: i64, yaml: &str) -> Value {
        self.control(&json!({"cmd": "apply_policy", "response": self.signed(version, yaml)}))
    }

    pub fn apply_rule_packs(&self, version: i64, yaml: &str) -> Value {
        self.control(&json!({"cmd": "apply_rule_packs", "response": self.signed(version, yaml)}))
    }

    pub fn watermark(&self) -> i64 {
        self.control(&json!({"cmd": "policy_status"}))["policy_status"]
            ["last_applied_policy_version"]
            .as_i64()
            .unwrap()
    }
}
