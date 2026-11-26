#![cfg(unix)]
//! `lodeline-proxy snippet`: prints a client config entry for one proxy route.
// home-isolation: exempt (snippet reads and writes no file; one test runs it with an empty HOME)

use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_lodeline-proxy");
const URL: &str = "https://proxy.example.internal:8480";

fn snippet(client: &str, name: &str, url: &str, route: &str, env: &str) -> Output {
    Command::new(BIN)
        .args(["snippet", "--client", client, "--name", name])
        .args(["--url", url, "--route", route, "--token-env", env])
        .output()
        .unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn has_hex_run(s: &str, n: usize) -> bool {
    let mut run = 0;
    for c in s.chars() {
        run = if c.is_ascii_hexdigit() { run + 1 } else { 0 };
        if run >= n {
            return true;
        }
    }
    false
}

/// A valid call of the same shape as a refusal test, so the refusal test cannot
/// pass only because the command does not exist.
fn assert_valid_call_works() {
    let ok = snippet("claude-code", "docs", URL, "r1", "PROXY_TOKEN_DOCS");
    assert!(ok.status.success(), "valid call failed: {}", err(&ok));
}

fn assert_refused(o: &Output, message: &str) {
    assert!(!o.status.success());
    assert!(out(o).is_empty(), "nothing on stdout for a refusal");
    assert!(err(o).contains(message), "stderr: {}", err(o));
}

#[test]
fn snippet_claude_code_prints_an_http_entry_with_the_route_url() {
    let o = snippet("claude-code", "docs", URL, "r1", "PROXY_TOKEN_DOCS");
    assert!(o.status.success(), "stderr: {}", err(&o));
    let v: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(v["type"], "http");
    assert_eq!(v["url"], "https://proxy.example.internal:8480/mcp/r1");
    let auth = v["headers"]["Authorization"].as_str().unwrap();
    assert_eq!(auth, "Bearer ${PROXY_TOKEN_DOCS}");
    assert!(!has_hex_run(auth, 64));
}

#[test]
fn snippet_cursor_prints_an_entry_with_the_route_url() {
    let o = snippet("cursor", "docs", URL, "r1", "PROXY_TOKEN_DOCS");
    assert!(o.status.success(), "stderr: {}", err(&o));
    let v: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(v["url"], "https://proxy.example.internal:8480/mcp/r1");
    assert_eq!(
        v["headers"]["Authorization"],
        "Bearer ${env:PROXY_TOKEN_DOCS}"
    );
    assert!(v.get("type").is_none());
}

#[test]
fn snippet_codex_prints_a_toml_table_with_bearer_token_env_var() {
    let o = snippet("codex", "docs", URL, "r1", "PROXY_TOKEN_DOCS");
    assert!(o.status.success(), "stderr: {}", err(&o));
    assert_eq!(
        out(&o),
        "[mcp_servers.docs]\n\
         url = \"https://proxy.example.internal:8480/mcp/r1\"\n\
         bearer_token_env_var = \"PROXY_TOKEN_DOCS\"\n"
    );
}

#[test]
fn snippet_names_the_target_file_on_stderr_only() {
    let o = snippet("codex", "docs", URL, "r1", "PROXY_TOKEN_DOCS");
    assert!(err(&o).contains("config.toml"));
    assert!(!out(&o).contains("config.toml"));
}

#[test]
fn snippet_refuses_a_plain_http_remote_url() {
    assert_valid_call_works();
    let o = snippet(
        "codex",
        "docs",
        "http://proxy.example.internal:8480",
        "r1",
        "T",
    );
    assert_refused(
        &o,
        "--url refused: http:// origins are allowed only for loopback hosts",
    );
    let loop_ok = snippet("codex", "docs", "http://127.0.0.1:8480", "r1", "T");
    assert!(loop_ok.status.success());
    assert!(out(&loop_ok).contains("http://127.0.0.1:8480/mcp/r1"));
}

#[test]
fn snippet_refuses_a_url_with_userinfo_or_path() {
    assert_valid_call_works();
    let o = snippet(
        "codex",
        "docs",
        "https://alice:secret@proxy.example.internal",
        "r1",
        "T",
    );
    assert_refused(&o, "--url refused: userinfo is not allowed");
    assert!(!err(&o).contains("secret"));
    let o = snippet(
        "codex",
        "docs",
        "https://proxy.example.internal/mcp",
        "r1",
        "T",
    );
    assert_refused(
        &o,
        "--url refused: origin must not contain a path, query or fragment",
    );
}

#[test]
fn snippet_refuses_a_dot_in_the_name() {
    assert_valid_call_works();
    let o = snippet("codex", "my.docs", URL, "r1", "T");
    assert_refused(&o, "a dot would make a nested TOML table");
    let ok = snippet("codex", "my-docs_2", URL, "r1", "T");
    assert!(ok.status.success());
}

#[test]
fn snippet_refuses_a_bad_route_id() {
    assert_valid_call_works();
    let o = snippet("codex", "docs", URL, "r 1/../x", "T");
    assert_refused(&o, "--route does not match the id pattern");
}

#[test]
fn snippet_refuses_a_bad_env_var_name() {
    assert_valid_call_works();
    let o = snippet("claude-code", "docs", URL, "r1", "1BAD-NAME");
    assert_refused(&o, "--token-env must be an environment variable name");
    let o = snippet("claude-code", "docs", URL, "r1", "A}B");
    assert_refused(&o, "--token-env must be an environment variable name");
}

#[test]
fn snippet_refuses_a_token_shaped_env_name() {
    assert_valid_call_works();
    let lower = format!("a{}", "1b2c3d4e".repeat(8).get(..63).unwrap());
    let upper = lower.to_ascii_uppercase();
    assert_eq!(lower.len(), 64);
    for v in [lower, upper] {
        for client in ["claude-code", "cursor", "codex"] {
            let o = snippet(client, "docs", URL, "r1", &v);
            assert_refused(&o, "--token-env looks like a token value");
            assert!(!err(&o).contains(&v), "the value is never echoed");
        }
    }
    // A name that merely contains 64 hex characters inside a longer name is a name.
    let longer = format!("TOKEN_{}", "A".repeat(64));
    let o = snippet("codex", "docs", URL, "r1", &longer);
    assert!(o.status.success());
}

#[test]
fn snippet_refuses_a_real_token_new_output() {
    let t = tempfile::tempdir().unwrap();
    let cfg = t.path().join("proxy.yaml");
    std::fs::write(
        &cfg,
        "proxy_id: px-1\ncontrol_plane_url: https://server.example:8443\nstate_dir: state\n\
         client_cert_file: cert.pem\nclient_key_file: key.pem\nca_file: ca.pem\nlisten: 127.0.0.1:0\n",
    )
    .unwrap();
    for f in ["cert.pem", "key.pem", "ca.pem"] {
        std::fs::write(t.path().join(f), "x").unwrap();
    }
    use std::os::unix::fs::PermissionsExt;
    for (f, m) in [("cert.pem", 0o600), ("key.pem", 0o600), ("ca.pem", 0o644)] {
        std::fs::set_permissions(t.path().join(f), std::fs::Permissions::from_mode(m)).unwrap();
    }
    let n = Command::new(BIN)
        .args(["token", "new", "--principal", "alice", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    let stdout = out(&n);
    let token = stdout
        .lines()
        .find_map(|l| l.strip_prefix("token: "))
        .unwrap();
    assert_valid_call_works();
    let o = snippet("codex", "docs", URL, "r1", token);
    assert!(!o.status.success());
    assert!(!out(&o).contains(token) && !err(&o).contains(token));
}

#[test]
fn snippet_creates_no_file() {
    assert_valid_call_works();
    let home = tempfile::tempdir().unwrap();
    for client in ["claude-code", "cursor", "codex"] {
        let o = Command::new(BIN)
            .current_dir(home.path())
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .args(["snippet", "--client", client, "--name", "docs"])
            .args(["--url", URL, "--route", "r1", "--token-env", "T"])
            .output()
            .unwrap();
        assert!(o.status.success(), "stderr: {}", err(&o));
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn snippet_usage_errors_never_echo_a_token_shaped_argument() {
    assert_valid_call_works();
    let token = format!("a{}", "1b2c3d4e".repeat(8).get(..63).unwrap());
    // The words of a `token new` result split by an unquoted shell expansion.
    let split = Command::new(BIN)
        .args(["snippet", "--client", "codex", "--name", "docs"])
        .args([
            "--url",
            URL,
            "--route",
            "r1",
            "--token-env",
            "token:",
            &token,
        ])
        .output()
        .unwrap();
    assert_eq!(split.status.code(), Some(2));
    assert!(out(&split).is_empty());
    assert!(!has_hex_run(&err(&split), 64), "stderr: {}", err(&split));
    assert!(err(&split).contains("snippet --help"));
    // A token in the place of a flag value that clap validates itself.
    let bad_client = Command::new(BIN)
        .args(["snippet", "--client", &token, "--name", "docs"])
        .output()
        .unwrap();
    assert_eq!(bad_client.status.code(), Some(2));
    assert!(!has_hex_run(&err(&bad_client), 64));
    // Help is still help.
    let help = Command::new(BIN)
        .args(["snippet", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(out(&help).contains("--token-env"));
}

#[test]
fn snippet_refuses_a_name_that_starts_with_a_hyphen() {
    assert_valid_call_works();
    for name in ["--help", "-x"] {
        let o = Command::new(BIN)
            .args(["snippet", "--client", "claude-code"])
            .arg(format!("--name={name}"))
            .args(["--url", URL, "--route", "r1", "--token-env", "T"])
            .output()
            .unwrap();
        assert_refused(&o, "--name must not start with a hyphen");
    }
    let ok = snippet("claude-code", "a-b", URL, "r1", "T");
    assert!(ok.status.success());
}
