//! `lodeline-sender doctor` against real files in a temp dir, with an injected clock.

use lodeline_core::sender_status::{Contact, LinkFailure, SenderReport, REPORT_SCHEMA_VERSION};
use lodeline_diag::Level;
use lodeline_sender::doctor::{self, Check};
use lodeline_sender::state;
use lodeline_sender::transport::client_cert_expiry;
use std::fs;
use std::path::PathBuf;
use time::macros::datetime;
use time::OffsetDateTime;

/// Self-signed, and its key is gone. It lives in this file because `.gitignore` drops
/// `*.crt`, so a fixture file would exist only on the machine that made it.
const CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIBdzCCAR6gAwIBAgIUOvoB9w/UTtqtZNvgsPgaUX7cE7EwCgYIKoZIzj0EAwIw
IjEgMB4GA1UEAwwXbG9kZWxpbmUtZG9jdG9yLWZpeHR1cmUwHhcNMjYxMTAxMDgw
NTI2WhcNMzYxMDI5MDgwNTI2WjAiMSAwHgYDVQQDDBdsb2RlbGluZS1kb2N0b3It
Zml4dHVyZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAlnXTs82+3WAIjg68/S
ujPp9CNLDw1P6642FRVvnOt6+l7beav88qr+NVeOyXWweWBWc93Zup5H0Rmf1nKR
FI6jMjAwMB0GA1UdDgQWBBQ/4hF13MC/sETcM/EsvFZnroimwzAPBgNVHRMBAf8E
BTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIA5IKq6JmFxaMuw3bAbNdokTDO/khlzd
+GuRyNQmgBLfAiAxAZSqCVzq/klBFBZbKO9fd9krC1gtMAs7LrNdypiZ4g==
-----END CERTIFICATE-----
";
const CERT_EXPIRES: OffsetDateTime = datetime!(2036-10-29 08:05:26 UTC);
const NOW: OffsetDateTime = datetime!(2026-11-01 12:00 UTC);
const KEY_MARKER: &str = "not-a-key-and-must-never-be-printed";

struct Host {
    dir: tempfile::TempDir,
    config: PathBuf,
}

impl Host {
    /// A healthy mTLS sender config whose agent is not running and has never reported.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        fs::create_dir(path.join("events")).unwrap();
        fs::write(path.join("client.crt"), CERT).unwrap();
        fs::write(path.join("ca.pem"), CERT).unwrap();
        fs::write(path.join("client.key"), KEY_MARKER).unwrap();
        #[cfg(unix)]
        set_mode(&path.join("client.key"), 0o640);
        let host = Self {
            config: path.join("sender.yaml"),
            dir,
        };
        let yaml = serde_json::json!({
            "server_base_url": "https://u:s3cret@server.example:8443/?token=t0ken",
            "client_cert_path": host.path("client.crt"),
            "client_key_path": host.path("client.key"),
            "server_ca_path": host.path("ca.pem"),
            "events_dir": host.path("events"),
            "offset_path": host.path("sender-offset.json"),
            "agent_control": host.path("control.sock"),
        });
        fs::write(&host.config, yaml.to_string()).unwrap();
        host
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    async fn run(&self) -> Vec<Check> {
        doctor::run(&self.config, NOW).await
    }
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn line<'a>(checks: &'a [Check], subject: &str) -> &'a Check {
    checks
        .iter()
        .find(|c| c.text.starts_with(subject))
        .unwrap_or_else(|| panic!("no {subject} line in {checks:?}"))
}

fn output(checks: &[Check]) -> String {
    checks
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn client_cert_expiry_reads_not_after() {
    let host = Host::new();
    assert_eq!(
        client_cert_expiry(&host.path("client.crt")).unwrap(),
        CERT_EXPIRES
    );
}

#[tokio::test]
async fn healthy_config_has_no_failure_and_names_what_is_not_running() {
    let host = Host::new();
    let checks = host.run().await;
    assert!(!checks.iter().any(Check::is_failure), "{checks:?}");
    assert_eq!(line(&checks, "config").level, Level::Ok);
    assert_eq!(line(&checks, "client certificate expiry").level, Level::Ok);
    assert_eq!(line(&checks, "events dir").level, Level::Ok);
    assert_eq!(line(&checks, "agent control").level, Level::Warn);
    assert_eq!(line(&checks, "status file").level, Level::Warn);
}

#[tokio::test]
async fn output_holds_no_credential_and_no_key_content() {
    let host = Host::new();
    let out = output(&host.run().await);
    assert!(out.contains("https://server.example:8443"), "{out}");
    for secret in ["s3cret", "t0ken", KEY_MARKER] {
        assert!(!out.contains(secret), "{out}");
    }
}

#[tokio::test]
async fn config_that_does_not_parse_fails_without_quoting_it() {
    let host = Host::new();
    fs::write(&host.config, "server_base_url: [hunter2\n").unwrap();
    let checks = host.run().await;
    assert_eq!(checks.len(), 1);
    assert!(checks[0].is_failure());
    assert!(!checks[0].text.contains("hunter2"), "{checks:?}");
}

#[tokio::test]
async fn missing_config_fails() {
    let host = Host::new();
    fs::remove_file(&host.config).unwrap();
    assert!(host.run().await[0].is_failure());
}

#[tokio::test]
async fn missing_cert_key_or_ca_fails() {
    for (file, subject) in [
        ("client.crt", "client certificate"),
        ("client.key", "client key"),
        ("ca.pem", "server CA"),
    ] {
        let host = Host::new();
        fs::remove_file(host.path(file)).unwrap();
        let checks = host.run().await;
        assert!(line(&checks, subject).is_failure(), "{checks:?}");
    }
}

#[tokio::test]
async fn cert_that_is_not_a_certificate_fails() {
    let host = Host::new();
    fs::write(host.path("client.crt"), "garbage").unwrap();
    let checks = host.run().await;
    assert!(
        line(&checks, "client certificate expiry").is_failure(),
        "{checks:?}"
    );
}

#[tokio::test]
async fn expired_cert_fails_and_expiring_soon_warns() {
    let host = Host::new();
    let after_expiry = CERT_EXPIRES + time::Duration::seconds(1);
    let checks = doctor::run(&host.config, after_expiry).await;
    let expiry = line(&checks, "client certificate expiry");
    assert_eq!(expiry.level, Level::Error);
    assert!(expiry.text.contains("expired"), "{expiry:?}");

    let checks = doctor::run(&host.config, CERT_EXPIRES - time::Duration::days(1)).await;
    let expiry = line(&checks, "client certificate expiry");
    assert_eq!(expiry.level, Level::Warn);
    assert!(expiry.text.contains("expires soon"), "{expiry:?}");
    assert!(!checks.iter().any(Check::is_failure), "{checks:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn key_open_to_all_users_fails_and_group_write_warns() {
    let host = Host::new();
    set_mode(&host.path("client.key"), 0o644);
    assert!(line(&host.run().await, "client key").is_failure());

    set_mode(&host.path("client.key"), 0o660);
    assert_eq!(line(&host.run().await, "client key").level, Level::Warn);
}

#[cfg(unix)]
#[tokio::test]
async fn cert_writable_by_others_warns() {
    let host = Host::new();
    set_mode(&host.path("client.crt"), 0o666);
    assert_eq!(
        line(&host.run().await, "client certificate").level,
        Level::Warn
    );
}

#[tokio::test]
async fn events_dir_that_is_missing_fails() {
    let host = Host::new();
    fs::remove_dir(host.path("events")).unwrap();
    assert!(line(&host.run().await, "events dir").is_failure());
}

#[tokio::test]
async fn half_an_identity_fails() {
    let host = Host::new();
    let yaml = serde_json::json!({
        "server_base_url": "https://s.example",
        "client_cert_path": host.path("client.crt"),
        "events_dir": host.path("events"),
        "agent_control": host.path("control.sock"),
    });
    fs::write(&host.config, yaml.to_string()).unwrap();
    assert!(line(&host.run().await, "client certificate").is_failure());
}

#[tokio::test]
async fn no_identity_warns_and_plain_http_warns() {
    let host = Host::new();
    let yaml = serde_json::json!({
        "server_base_url": "http://127.0.0.1:18443",
        "events_dir": host.path("events"),
        "agent_control": host.path("control.sock"),
        "offset_path": host.path("sender-offset.json"),
    });
    fs::write(&host.config, yaml.to_string()).unwrap();
    let checks = host.run().await;
    assert_eq!(line(&checks, "client certificate").level, Level::Warn);
    assert_eq!(line(&checks, "server_base_url").level, Level::Warn);
    assert!(!checks.iter().any(Check::is_failure), "{checks:?}");
}

#[tokio::test]
async fn failing_link_is_a_failure_and_a_fresh_connected_report_is_not() {
    let host = Host::new();
    let path = lodeline_core::sender_status::status_path_for(&host.path("sender-offset.json"));
    let report = |contact| SenderReport {
        schema_version: REPORT_SCHEMA_VERSION,
        written_at: NOW,
        contact,
        client_cert_expires_at: None,
    };
    state::store_report(
        &path,
        &report(Contact::Failing {
            since: NOW,
            failure: LinkFailure::Tls,
            last_ok_at: None,
        }),
    )
    .unwrap();
    assert!(line(&host.run().await, "status file").is_failure());

    state::store_report(&path, &report(Contact::Reached { last_ok_at: NOW })).unwrap();
    assert_eq!(line(&host.run().await, "status file").level, Level::Ok);
}

#[tokio::test]
async fn corrupt_status_file_warns() {
    let host = Host::new();
    fs::write(host.path("sender-status.json"), "garbage").unwrap();
    let checks = host.run().await;
    let status = line(&checks, "status file");
    assert_eq!(status.level, Level::Warn);
    assert!(status.text.contains("not a sender report"), "{status:?}");
}
