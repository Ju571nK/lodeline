use std::process::Command;

/// A scratch home plus a control socket of its own, so the binary reads nothing of the
/// developer's and reaches no agent that the test did not start.
/// shortcut: Windows has no flag for the control pipe, so there the binary still
/// asks the default pipe; point it elsewhere when the product gains a flag.
struct Scratch(tempfile::TempDir);

impl Scratch {
    fn new() -> Self {
        Self(tempfile::tempdir().unwrap())
    }

    fn lodeline(&self) -> Command {
        let home = self.0.path();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_lodeline"));
        cmd.arg("--control-socket")
            .arg(home.join("control.sock"))
            .env("HOME", home)
            .env("USERPROFILE", home)
            .env("APPDATA", home)
            .env("LOCALAPPDATA", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_STATE_HOME", home.join("state"))
            .env("XDG_RUNTIME_DIR", home.join("run"));
        cmd
    }
}

#[test]
fn it_doctor_succeeds_on_valid_config() {
    let scratch = Scratch::new();
    let out = scratch.lodeline().arg("doctor").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Lodeline doctor"));
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "unexpected exit code {code}\n{stdout}"
    );
}

#[test]
fn it_show_paths_prints_targets() {
    let scratch = Scratch::new();
    let out = scratch.lodeline().args(["show", "paths"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("# "));
}

#[test]
fn show_paths_and_doctor_name_the_policy_file_in_force() {
    let scratch = Scratch::new();
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("policy.yaml");
    std::fs::write(&policy, "version: 1\n").unwrap();

    let show = scratch
        .lodeline()
        .args(["show", "paths", "--policy"])
        .arg(&policy)
        .output()
        .unwrap();
    let show = String::from_utf8_lossy(&show.stdout);
    assert!(
        show.contains(&format!("# policy in force: {}", policy.display())),
        "{show}"
    );
    assert!(show.contains("# rule packs in force: none ("), "{show}");

    let doctor = scratch
        .lodeline()
        .args(["doctor", "--policy"])
        .arg(&policy)
        .output()
        .unwrap();
    let doctor = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        doctor.contains(&format!("[INFO] policy in force: {}", policy.display())),
        "{doctor}"
    );
}

// #161: a missing state.db (fresh install, before the first `lodeline run`) is
// reported as INFO and does NOT emit the degradation WARN — so a clean machine
// isn't told it has a problem just because the daemon hasn't created the DB yet.
#[test]
fn doctor_absent_state_db_is_info_not_warn() {
    let scratch = Scratch::new();
    let tmp = tempfile::tempdir().unwrap();
    let missing_db = tmp.path().join("nope").join("state.db");
    assert!(!missing_db.exists());
    let out = scratch
        .lodeline()
        .arg("doctor")
        .arg("--state-db")
        .arg(&missing_db)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("state.db not yet present"),
        "doctor should report a missing state.db as INFO. Output:\n{stdout}"
    );
    assert!(
        !stdout.contains("state.db unavailable for host_id read"),
        "a missing state.db must not produce the degradation WARN. Output:\n{stdout}"
    );
}

// Phase 3b.5 Task 6: doctor AI Guard section coverage.
//
// These tests assert observable doctor output:
//   1. The AI Guard section header always appears (agent-down fallback).
//   2. The static rubric table lists all 11 known reason kinds.
//   3. An operator override in policy.yaml renders with the `*` marker.

#[test]
fn doctor_prints_ai_guard_section_when_agent_down() {
    let scratch = Scratch::new();
    // Agent isn't running in this test binary's process. doctor should
    // still print the AI Guard section header + fallback message.
    let out = scratch.lodeline().arg("doctor").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("──────────────  AI Guard  ──────────────"),
        "doctor output missing AI Guard section header. Output:\n{stdout}"
    );
    assert!(
        stdout.contains("lodeline agent not running")
            || stdout.contains("Effective Rubric (static)"),
        "doctor missing fallback indicator. Output:\n{stdout}"
    );
}

#[test]
fn doctor_static_rubric_table_includes_all_eleven_kinds() {
    let scratch = Scratch::new();
    let out = scratch.lodeline().arg("doctor").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    for kind in &[
        "destructive_in_inline_command",
        "destructive_in_hook_script",
        "sandbox_disabled",
        "no_sandbox",
        "permissions_allow_broad",
        "external_script_unscanned",
        "broad_matcher_pre_tool_use",
        "broad_matcher_other",
        "permissions_deny_empty",
        "mcp_server_remote",
        "mcp_server_local_command",
    ] {
        assert!(
            stdout.contains(kind),
            "doctor static rubric missing kind '{kind}'. Output:\n{stdout}"
        );
    }
}

#[test]
fn doctor_with_override_in_policy_shows_marker() {
    let scratch = Scratch::new();
    // Write a tempdir policy.yaml with an override; pass via --policy.
    // Verified flag: `lodeline doctor --policy <PATH>` overrides the policy file path.
    let tmp = tempfile::tempdir().unwrap();
    let policy_path = tmp.path().join("policy.yaml");
    std::fs::write(
        &policy_path,
        r#"version: 1
host_id_strategy: hostname
rubric_overrides:
  destructive_in_hook_script: 5.0
"#,
    )
    .unwrap();
    let out = scratch
        .lodeline()
        .arg("doctor")
        .arg("--policy")
        .arg(&policy_path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Find the row "destructive_in_hook_script ... 5.0 *"
    let found = stdout
        .lines()
        .any(|l| l.contains("destructive_in_hook_script") && l.contains("5.0") && l.contains('*'));
    assert!(
        found,
        "doctor missing override marker for destructive_in_hook_script. Output:\n{stdout}"
    );
}
