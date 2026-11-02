//! Handler for `lodeline assess` — cold-disk pre-flight verdict (#149 Task 6).
//!
//! Evaluates a proposed command or single MCP server definition against the
//! host's loaded policy (cold-disk, no daemon required) and prints a JSON
//! verdict on stdout.
//!
//! # Exit codes
//! | Condition                              | Code |
//! |----------------------------------------|------|
//! | `Allow`                                | 0    |
//! | `Warn` (without `--fail-on-warn`)      | 0    |
//! | `Warn` (with `--fail-on-warn`)         | 2    |
//! | `Deny`                                 | 2    |
//! | Usage / input / policy-load error      | 1    |
//!
//! # Fail-closed
//! Malformed or oversize input → exit 1. Policy-load failure → exit 1.
//! NEVER produce an Allow verdict for malformed input.

use crate::ai_guard::assess::{assess, AssessCtx};
use crate::effective_policy::load_effective_policy;
use crate::runtime::SignedFile;
use lodeline_core::assess::{AssessInput, AssessVerdict, Decision};
use std::io::Read;
use std::path::{Path, PathBuf};

// ── Input size limits (fail-closed) ──────────────────────────────────────────
const MAX_COMMAND_BYTES: usize = 16_384;
const MAX_ARG_COUNT: usize = 64;
const MAX_ARG_BYTES: usize = 8_192;
const MAX_MCP_BYTES: usize = 65_536;

/// Map a `Decision` (plus `--fail-on-warn` flag) to a process exit code.
///
/// This is a pure function — unit-tested in the `#[cfg(test)]` block below.
pub fn exit_code(decision: Decision, fail_on_warn: bool) -> i32 {
    match decision {
        Decision::Allow => 0,
        Decision::Warn => {
            if fail_on_warn {
                2
            } else {
                0
            }
        }
        Decision::Deny => 2,
    }
}

/// Arguments for the `assess` subcommand, extracted from the clap parse.
pub struct AssessArgs {
    pub command: Option<String>,
    pub args: Vec<String>,
    pub mcp_config: Option<PathBuf>,
    pub mcp_stdin: bool,
    pub mcp_name: Option<String>,
    pub fail_on_warn: bool,
    pub policy_override: Option<PathBuf>,
}

/// Entry point called from `main.rs`. Returns a process exit code (0/1/2).
pub fn run(args: AssessArgs) -> i32 {
    // ── Step 1: validate XOR — exactly one input mode ────────────────────────
    let has_command = args.command.is_some();
    let has_mcp = args.mcp_config.is_some() || args.mcp_stdin;
    match (has_command, has_mcp) {
        (false, false) => {
            eprintln!(
                "lodeline assess: one of --command or (--mcp-config | --mcp-stdin) is required"
            );
            return 1;
        }
        (true, true) => {
            eprintln!(
                "lodeline assess: --command and --mcp-config/--mcp-stdin are mutually exclusive"
            );
            return 1;
        }
        _ => {}
    }

    // ── Step 2: build AssessInput with size limits ────────────────────────────
    let input = if has_command {
        let command = args.command.unwrap();
        if command.len() > MAX_COMMAND_BYTES {
            eprintln!(
                "lodeline assess: --command exceeds {MAX_COMMAND_BYTES} byte limit ({} bytes)",
                command.len()
            );
            return 1;
        }
        if args.args.len() > MAX_ARG_COUNT {
            eprintln!(
                "lodeline assess: too many --arg values ({} > {MAX_ARG_COUNT})",
                args.args.len()
            );
            return 1;
        }
        for (i, arg) in args.args.iter().enumerate() {
            if arg.len() > MAX_ARG_BYTES {
                eprintln!(
                    "lodeline assess: --arg[{i}] exceeds {MAX_ARG_BYTES} byte limit ({} bytes)",
                    arg.len()
                );
                return 1;
            }
        }
        AssessInput::Command {
            command,
            args: args.args,
        }
    } else {
        // MCP mode
        let server_name = match args.mcp_name.as_deref() {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => {
                eprintln!("lodeline assess: --mcp-name is required with --mcp-config/--mcp-stdin");
                return 1;
            }
        };

        let json_bytes = if args.mcp_stdin {
            // Read from stdin
            let mut buf = Vec::new();
            if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
                eprintln!("lodeline assess: failed to read --mcp-stdin: {e}");
                return 1;
            }
            buf
        } else {
            // Read from file
            let path = args.mcp_config.as_ref().unwrap();
            match std::fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!(
                        "lodeline assess: cannot read --mcp-config {}: {e}",
                        path.display()
                    );
                    return 1;
                }
            }
        };

        if json_bytes.len() > MAX_MCP_BYTES {
            eprintln!(
                "lodeline assess: MCP JSON exceeds {MAX_MCP_BYTES} byte limit ({} bytes)",
                json_bytes.len()
            );
            return 1;
        }

        // Parse and validate: must be a JSON object (not array, null, string…)
        let value: serde_json::Value = match serde_json::from_slice(&json_bytes) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("lodeline assess: MCP JSON parse error: {e}");
                return 1;
            }
        };
        if !value.is_object() {
            eprintln!(
                "lodeline assess: MCP JSON must be a JSON object (got {}); \
                 rejecting to avoid producing an Allow verdict for unexpected input",
                json_type_name(&value)
            );
            return 1;
        }

        AssessInput::McpServer {
            server_name,
            definition: value,
        }
    };

    // ── Step 3: load policy (fail-loud, exit 1 on error) ─────────────────────
    let (policy_path, rule_packs_path, denied) =
        resolve_policy_paths(args.policy_override.as_deref());
    if let Some(applied) = denied {
        eprintln!(
            "lodeline assess: permission denied reading {}, so this verdict uses {} and may \
             miss signed rules. Add this user to the `lodeline` group.",
            applied.display(),
            policy_path.display()
        );
    }
    let (rubric, deny, enforce_bucket) = match load_effective_policy(&policy_path, &rule_packs_path)
    {
        Ok(triple) => triple,
        Err(e) => {
            eprintln!("lodeline assess: policy load failed: {e}");
            return 1;
        }
    };

    // ── Step 4: assess ────────────────────────────────────────────────────────
    let ctx = AssessCtx {
        rubric: &rubric,
        deny: &deny,
        enforce_bucket,
    };
    let verdict: AssessVerdict = assess(&input, &ctx);

    // ── Step 5: emit one-line JSON, then exit ─────────────────────────────────
    match serde_json::to_string(&verdict) {
        Ok(line) => println!("{line}"),
        Err(e) => {
            eprintln!("lodeline assess: failed to serialize verdict: {e}");
            return 1;
        }
    }

    exit_code(verdict.decision, args.fail_on_warn)
}

/// Return the `(policy.yaml, rule-packs.yaml)` files to load, respecting an optional
/// `--policy` override from the global CLI. Without one these are the system agent's
/// files, so an integration running as a user gets the rules of the root agent on that
/// host. The third value is the applied file this caller may not read, if any.
fn resolve_policy_paths(policy_override: Option<&Path>) -> (PathBuf, PathBuf, Option<PathBuf>) {
    let paths = policy_override
        .map(|p| crate::runtime::PolicyPaths::at(p.to_path_buf()))
        .unwrap_or_else(crate::runtime::system_policy_paths);
    let (policy, policy_denied) = readable_file(&paths.policy, paths.policy.applied.try_exists());
    let (rule_packs, packs_denied) =
        readable_file(&paths.rule_packs, paths.rule_packs.applied.try_exists());
    let denied = (policy_denied || packs_denied).then_some(paths.policy.applied.clone());
    (policy, rule_packs, denied)
}

/// The file to load given what the OS said about `file.applied`. A caller outside the
/// `lodeline` group cannot look inside the state directory, whether or not an applied
/// file is there, so denied falls back to the local file and reports `true`.
fn readable_file(file: &SignedFile, applied_exists: std::io::Result<bool>) -> (PathBuf, bool) {
    match (&file.local, applied_exists) {
        (Some(local), Ok(false)) => (local.clone(), false),
        (Some(local), Err(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            (local.clone(), true)
        }
        _ => (file.applied.clone(), false),
    }
}

/// Human-readable name of the top-level JSON type (for error messages).
fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — pure functions only, no disk access
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use lodeline_core::assess::Decision;

    // ── exit_code mapping ─────────────────────────────────────────────────────

    #[test]
    fn exit_code_allow_is_0() {
        assert_eq!(exit_code(Decision::Allow, false), 0);
        assert_eq!(exit_code(Decision::Allow, true), 0);
    }

    #[test]
    fn exit_code_deny_is_2() {
        assert_eq!(exit_code(Decision::Deny, false), 2);
        assert_eq!(exit_code(Decision::Deny, true), 2);
    }

    #[test]
    fn exit_code_warn_without_flag_is_0() {
        assert_eq!(exit_code(Decision::Warn, false), 0);
    }

    #[test]
    fn exit_code_warn_with_fail_on_warn_is_2() {
        assert_eq!(exit_code(Decision::Warn, true), 2);
    }

    // ── json_type_name ────────────────────────────────────────────────────────

    #[test]
    fn json_type_name_array() {
        let v = serde_json::json!([1, 2, 3]);
        assert_eq!(json_type_name(&v), "array");
    }

    #[test]
    fn json_type_name_null() {
        assert_eq!(json_type_name(&serde_json::Value::Null), "null");
    }

    #[test]
    fn json_type_name_object() {
        let v = serde_json::json!({"a": 1});
        assert_eq!(json_type_name(&v), "object");
    }

    // ── resolve_policy_paths ─────────────────────────────────────────────────

    #[test]
    fn resolve_policy_paths_uses_default_when_no_override() {
        let (policy, rule_packs, _) = resolve_policy_paths(None);
        // Must be something ending in policy.yaml and rule-packs.yaml
        assert!(
            policy.to_str().unwrap().ends_with("policy.yaml"),
            "default policy path should end in policy.yaml: {policy:?}"
        );
        assert!(
            rule_packs.to_str().unwrap().ends_with("rule-packs.yaml"),
            "rule-packs path should end in rule-packs.yaml: {rule_packs:?}"
        );
    }

    #[test]
    fn resolve_policy_paths_respects_override() {
        let tmp = tempfile::tempdir().unwrap();
        let custom = tmp.path().join("custom-policy.yaml");
        let (policy, rule_packs, denied) = resolve_policy_paths(Some(&custom));
        assert_eq!(policy, custom);
        assert_eq!(rule_packs, tmp.path().join("rule-packs.yaml"));
        assert_eq!(denied, None);
    }

    fn system_file() -> SignedFile {
        SignedFile {
            applied: "/var/lib/lodeline/applied/policy.yaml".into(),
            local: Some("/etc/lodeline/policy.yaml".into()),
        }
    }

    fn denied() -> std::io::Result<bool> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }

    #[test]
    fn a_readable_applied_file_wins() {
        assert_eq!(
            readable_file(&system_file(), Ok(true)),
            (system_file().applied, false)
        );
    }

    #[test]
    fn no_applied_file_reads_the_local_file_without_a_warning() {
        assert_eq!(
            readable_file(&system_file(), Ok(false)),
            (PathBuf::from("/etc/lodeline/policy.yaml"), false)
        );
    }

    #[test]
    fn a_caller_outside_the_group_reads_the_local_file_and_is_warned() {
        assert_eq!(
            readable_file(&system_file(), denied()),
            (PathBuf::from("/etc/lodeline/policy.yaml"), true)
        );
    }

    #[test]
    fn another_error_stays_on_the_applied_file_so_the_load_fails_loudly() {
        let broken = Err(std::io::ErrorKind::InvalidData.into());
        assert_eq!(
            readable_file(&system_file(), broken),
            (system_file().applied, false)
        );
    }

    #[test]
    fn override_has_no_fallback_to_take_when_denied() {
        let file = SignedFile {
            applied: "/srv/p/policy.yaml".into(),
            local: None,
        };
        assert_eq!(
            readable_file(&file, denied()),
            (file.applied.clone(), false)
        );
    }

    /// The real errno behind [`readable_file`]'s denied arm. Root reads through the
    /// mode bits, so this runs only for a non-root user.
    #[test]
    #[cfg(unix)]
    fn a_directory_without_search_permission_reports_permission_denied() {
        use std::os::unix::fs::PermissionsExt;
        if crate::control::is_root() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o000)).unwrap();

        let exists = state.join("applied/policy.yaml").try_exists();

        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            readable_file(&system_file(), exists),
            (PathBuf::from("/etc/lodeline/policy.yaml"), true)
        );
    }

    // ── fail_on_warn plumbs through assess logic ──────────────────────────────
    // This test drives the pure `exit_code` function to verify the matrix is
    // exhaustive, without spawning the binary.

    #[test]
    fn exit_code_matrix_is_complete() {
        // All 6 cells of the (Decision × fail_on_warn) matrix
        assert_eq!(exit_code(Decision::Allow, false), 0);
        assert_eq!(exit_code(Decision::Allow, true), 0);
        assert_eq!(exit_code(Decision::Warn, false), 0);
        assert_eq!(exit_code(Decision::Warn, true), 2);
        assert_eq!(exit_code(Decision::Deny, false), 2);
        assert_eq!(exit_code(Decision::Deny, true), 2);
    }
}
