//! Local policy-file observations, not effective-policy or enforcement attestations.
//! Cloud policy, MDM, parent hosts, and running-session state are not resolved here.

use super::AssessError;
use lodeline_core::event::AiGuardControl;
use serde_json::Value;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_DROP_INS: usize = 128;

pub(super) use lodeline_core::codex::system_dir as codex_system_dir;

pub(super) fn codex_requirements_path() -> PathBuf {
    codex_system_dir().join("requirements.toml")
}

pub(super) fn codex_controls(path: &Path) -> Result<Vec<AiGuardControl>, AssessError> {
    let Some(text) = read_policy(path)? else {
        return Ok(Vec::new());
    };
    let policy: toml::Value = toml::from_str(&text).map_err(|e| AssessError::Parse {
        path: path.into(),
        message: e.to_string(),
    })?;
    let mut out = Vec::new();
    for (key, expected) in [
        ("allow_managed_hooks_only", true),
        ("allow_remote_control", false),
        ("allow_login_shell", false),
        ("allow_browser_and_computer_use", false),
        ("allow_appshots", false),
    ] {
        if policy.get(key).and_then(toml::Value::as_bool) == Some(expected) {
            out.push(observation("codex", path, key, Value::Bool(expected)));
        }
    }
    // Do not infer protection from arbitrary profiles or granular approval
    // names. Only bounded, known restrictive enum lists qualify.
    for (key, allowed) in [
        (
            "allowed_approval_policies",
            &["on-request", "untrusted"][..],
        ),
        (
            "allowed_sandbox_modes",
            &["read-only", "workspace-write"][..],
        ),
        ("allowed_approvals_reviewers", &["user"][..]),
    ] {
        let Some(values) = policy.get(key).and_then(toml::Value::as_array) else {
            continue;
        };
        if values.is_empty() || values.len() > 16 {
            continue;
        }
        let Some(mut strings) = values
            .iter()
            .map(toml::Value::as_str)
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        if strings.iter().any(|value| !allowed.contains(value)) {
            continue;
        }
        strings.sort_unstable();
        strings.dedup();
        out.push(observation("codex", path, key, serde_json::json!(strings)));
    }
    Ok(out)
}

pub(super) fn claude_policy_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/ClaudeCode")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\Program Files\ClaudeCode")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from("/etc/claude-code")
    }
}

/// Cursor's enterprise (system-wide) `hooks.json`. Cursor hardcodes these
/// paths, `C:\ProgramData` included, rather than reading `%ProgramData%`
/// (cursor-agent 2026.10.22 hooks loader).
pub(super) fn cursor_enterprise_hooks_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/Cursor/hooks.json")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\Cursor\hooks.json")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from("/etc/cursor/hooks.json")
    }
}

pub(super) fn claude_paths(dir: &Path) -> Vec<PathBuf> {
    vec![
        dir.join("managed-settings.json"),
        dir.join("managed-settings.d"),
        dir.join("managed-mcp.json"),
    ]
}

/// #199 — `managed-mcp.json` under `dir`. A missing, unreadable, oversized or
/// malformed file reads as not deployed, so the user's servers stay scored.
/// The error is not logged because it can quote file content.
// shortcut: Claude Code treats an unreadable, empty or non-object file as
// present and exclusive, so the user's and project's servers over-report here;
// return a present-but-empty set if that shows up as noise.
pub(super) fn claude_managed_mcp(dir: &Path) -> Option<Value> {
    let path = dir.join("managed-mcp.json");
    let parsed = read_policy(&path).map(|text| text.map(|t| serde_json::from_str::<Value>(&t)));
    match parsed {
        Ok(None) => None,
        Ok(Some(Ok(value))) if value.is_object() => Some(value),
        _ => {
            tracing::warn!(path = %path.display(), "claude code: unreadable managed-mcp.json; treated as not deployed");
            None
        }
    }
}

fn read_policy(path: &Path) -> Result<Option<String>, AssessError> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(AssessError::Io {
                path: path.into(),
                source,
            })
        }
    };
    let mut text = String::new();
    file.take(MAX_POLICY_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|source| AssessError::Io {
            path: path.into(),
            source,
        })?;
    if text.len() as u64 > MAX_POLICY_BYTES {
        return Err(AssessError::Parse {
            path: path.into(),
            message: "policy exceeds 1 MiB limit".into(),
        });
    }
    Ok(Some(text))
}

fn dotted<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    key.split('.').try_fold(value, |v, k| v.get(k))
}

fn observation(product: &str, source: &Path, key: &str, value: Value) -> AiGuardControl {
    AiGuardControl {
        id: format!("{product}.configured.{key}"),
        source_path: source.into(),
        setting: key.into(),
        value,
    }
}

/// The managed settings files under `dir`, `managed-settings.json` first and
/// then the drop-ins in name order, so a later layer wins.
fn claude_layers(dir: &Path) -> Result<Vec<(PathBuf, Value)>, AssessError> {
    let mut paths = vec![dir.join("managed-settings.json")];
    let drop_dir = dir.join("managed-settings.d");
    match std::fs::read_dir(&drop_dir) {
        Ok(entries) => {
            let mut drops = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|source| AssessError::Io {
                    path: drop_dir.clone(),
                    source,
                })?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json")
                    && !entry.file_name().to_string_lossy().starts_with('.')
                {
                    drops.push(path);
                    if drops.len() > MAX_DROP_INS {
                        return Err(AssessError::Parse {
                            path: drop_dir,
                            message: "too many policy drop-ins".into(),
                        });
                    }
                }
            }
            drops.sort();
            paths.extend(drops);
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(source) => {
            return Err(AssessError::Io {
                path: drop_dir,
                source,
            })
        }
    }
    let mut layers = Vec::new();
    for path in paths {
        let Some(text) = read_policy(&path)? else {
            continue;
        };
        let value: Value = serde_json::from_str(&text).map_err(|e| AssessError::Parse {
            path: path.clone(),
            message: e.to_string(),
        })?;
        if !value.is_object() {
            return Err(AssessError::Parse {
                path,
                message: "policy must be an object".into(),
            });
        }
        layers.push((path, value));
    }
    Ok(layers)
}

fn merge_layers(layers: &[(PathBuf, Value)]) -> Value {
    layers
        .iter()
        .fold(Value::Object(Default::default()), |merged, (_, value)| {
            super::claude_code::merge_overlay(merged, Some(value.clone()))
        })
}

/// The managed settings from the file source, merged the way Claude Code
/// merges them.
pub(super) fn claude_managed_settings(dir: &Path) -> Result<Value, AssessError> {
    Ok(merge_layers(&claude_layers(dir)?))
}

pub(super) fn claude_controls(dir: &Path) -> Result<Vec<AiGuardControl>, AssessError> {
    let layers = claude_layers(dir)?;
    // Scalar restrictions only: last explicitly supplied value wins within
    // the local file source. A replaced parent of the wrong type invalidates it.
    let merged = merge_layers(&layers);
    let mut out = Vec::new();
    for (key, expected) in [
        ("disableAutoMode", Value::from("disable")),
        ("permissions.disableAutoMode", Value::from("disable")),
        (
            "permissions.disableBypassPermissionsMode",
            Value::from("disable"),
        ),
        (
            "permissions.blockReadsOutsideWorkingDirectories",
            Value::from(true),
        ),
        (
            "permissions.blockWritesOutsideWorkingDirectories",
            Value::from(true),
        ),
        ("allowManagedPermissionRulesOnly", Value::from(true)),
        ("allowManagedHooksOnly", Value::from(true)),
        ("allowManagedMcpServersOnly", Value::from(true)),
        ("disableSideloadFlags", Value::from(true)),
        ("disableSkillShellExecution", Value::from(true)),
        ("strictPluginOnlyCustomization", Value::from(true)),
        ("sandbox.enabled", Value::from(true)),
        ("sandbox.allowUnsandboxedCommands", Value::from(false)),
        ("sandbox.network.allowManagedDomainsOnly", Value::from(true)),
        (
            "sandbox.filesystem.allowManagedReadPathsOnly",
            Value::from(true),
        ),
    ] {
        if key.starts_with("sandbox.")
            && key != "sandbox.enabled"
            && dotted(&merged, "sandbox.enabled") != Some(&Value::Bool(true))
        {
            continue;
        }
        if dotted(&merged, key) != Some(&expected) {
            continue;
        }
        if let Some((path, _)) = layers.iter().rev().find(|(_, v)| dotted(v, key).is_some()) {
            out.push(observation("claude_code", path, key, expected));
        }
    }
    Ok(out)
}

/// `allowedHttpHookUrls` set in the user's own settings files: one control
/// that carries the number of patterns in the merged list and never a pattern,
/// because a URL can name an internal host. The managed files have no control
/// for it. Its source is the first of `settings.json` and
/// `settings.local.json` that sets the key.
pub(super) fn claude_http_hook_url_control(
    claude: &Path,
    policy_dir: &Path,
) -> Result<Vec<AiGuardControl>, AssessError> {
    let key = "allowedHttpHookUrls";
    let mut sources = Vec::new();
    for name in ["settings.json", "settings.local.json"] {
        let path = claude.join(name);
        if let Some(value) = super::read_json_optional(&path)? {
            if value.get(key).is_some() {
                sources.push((path, value));
            }
        }
    }
    let managed = claude_managed_settings(policy_dir).ok();
    let files: Vec<Option<&Value>> = std::iter::once(managed.as_ref())
        .chain(sources.iter().map(|(_, v)| Some(v)))
        .collect();
    let (Some((path, _)), Some(list)) = (
        sources.first(),
        super::claude_code::http_hook_allowlist(&files),
    ) else {
        return Ok(Vec::new());
    };
    Ok(vec![observation(
        "claude_code",
        path,
        key,
        Value::from(list.len()),
    )])
}

/// The two `permissions.block*OutsideWorkingDirectories` keys set to `true` in
/// the given non-managed settings files, one control per key. Claude Code
/// honors `true` from any scope, so the source is the first file that sets it.
/// An unreadable file is the reasons channel's to report, so it is skipped here.
pub(super) fn claude_outside_dir_controls(files: &[PathBuf]) -> Vec<AiGuardControl> {
    let settings: Vec<(&PathBuf, Value)> = files
        .iter()
        .filter_map(|path| Some((path, super::read_json_optional(path).ok()??)))
        .collect();
    [
        "blockReadsOutsideWorkingDirectories",
        "blockWritesOutsideWorkingDirectories",
    ]
    .into_iter()
    .filter_map(|name| {
        let key = format!("permissions.{name}");
        let (path, _) = settings
            .iter()
            .find(|(_, v)| dotted(v, &key) == Some(&Value::Bool(true)))?;
        Some(observation("claude_code", path, &key, Value::Bool(true)))
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_requirements_restrictions_are_explicit_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("requirements.toml");
        assert!(codex_controls(&path).unwrap().is_empty());
        std::fs::write(&path, "allow_managed_hooks_only = true\nallow_remote_control = false\nallowed_sandbox_modes = ['workspace-write', 'read-only', 'read-only']\nallowed_approval_policies = ['on-request']\nsecret = 'not-evidence'\n").unwrap();
        let controls = codex_controls(&path).unwrap();
        assert_eq!(controls.len(), 4);
        assert_eq!(
            controls
                .iter()
                .find(|c| c.setting == "allowed_sandbox_modes")
                .unwrap()
                .value,
            serde_json::json!(["read-only", "workspace-write"])
        );
        assert!(controls
            .iter()
            .all(|c| c.source_path == path && c.id.starts_with("codex.configured.")));
        assert!(!serde_json::to_string(&controls)
            .unwrap()
            .contains("not-evidence"));
        std::fs::write(&path, "allow_managed_hooks_only = false\nallow_remote_control = true\nallowed_sandbox_modes = ['danger-full-access']\nallowed_approval_policies = ['granular']\nallowed_approvals_reviewers = []\n").unwrap();
        assert!(codex_controls(&path).unwrap().is_empty());
    }

    #[test]
    fn codex_wrong_types_and_unknown_enums_never_claim_restrictions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("requirements.toml");
        std::fs::write(&path, "allow_remote_control = 'false'\nallowed_approval_policies = ['on-request', 'future']\nallowed_sandbox_modes = ['read-only', 1]\n").unwrap();
        assert!(codex_controls(&path).unwrap().is_empty());
        std::fs::write(&path, "[broken").unwrap();
        assert!(codex_controls(&path).is_err());
    }

    #[test]
    fn claude_reports_only_allowlisted_local_file_restrictions() {
        let dir = tempfile::tempdir().unwrap();
        assert!(claude_controls(dir.path()).unwrap().is_empty());
        let path = dir.path().join("managed-settings.json");
        std::fs::write(&path, r#"{"permissions":{"disableAutoMode":"disable"},"allowManagedHooksOnly":true,"disableSideloadFlags":"true","sandbox":{"enabled":true,"allowUnsandboxedCommands":false},"env":{"TOKEN":"secret"}}"#).unwrap();
        let controls = claude_controls(dir.path()).unwrap();
        assert_eq!(controls.len(), 4);
        assert!(controls
            .iter()
            .all(|c| c.source_path == path && c.id.contains(".configured.")));
        assert!(!serde_json::to_string(&controls).unwrap().contains("secret"));
    }

    #[test]
    fn claude_http_hook_url_control_holds_the_count_and_no_url() {
        let home = tempfile::tempdir().unwrap();
        let policy = tempfile::tempdir().unwrap();
        let claude = home.path().join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        let control = |claude: &Path| claude_http_hook_url_control(claude, policy.path()).unwrap();
        assert!(control(&claude).is_empty());
        std::fs::write(
            claude.join("settings.json"),
            r#"{"allowedHttpHookUrls": ["https://internal.example.test/*", "https://b.example.test/*"]}"#,
        )
        .unwrap();
        std::fs::write(
            claude.join("settings.local.json"),
            r#"{"allowedHttpHookUrls": ["https://b.example.test/*", "https://c.example.test/*"]}"#,
        )
        .unwrap();
        std::fs::write(
            policy.path().join("managed-settings.json"),
            r#"{"allowedHttpHookUrls": ["https://managed.example.test/*"]}"#,
        )
        .unwrap();
        let found = control(&claude);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "claude_code.configured.allowedHttpHookUrls");
        assert_eq!(found[0].source_path, claude.join("settings.json"));
        assert_eq!(found[0].value, Value::from(4));
        let text = serde_json::to_string(&found).unwrap();
        assert!(!text.contains("example.test"), "{text}");
    }

    #[test]
    fn claude_outside_working_directory_blocks_are_reported_only_for_true() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed-settings.json");
        for key in [
            "blockReadsOutsideWorkingDirectories",
            "blockWritesOutsideWorkingDirectories",
        ] {
            std::fs::write(&path, format!(r#"{{"permissions":{{"{key}":true}}}}"#)).unwrap();
            let controls = claude_controls(dir.path()).unwrap();
            assert_eq!(controls.len(), 1, "{key}");
            assert_eq!(
                controls[0].id,
                format!("claude_code.configured.permissions.{key}")
            );
            for off in ["false", r#""true""#] {
                std::fs::write(&path, format!(r#"{{"permissions":{{"{key}":{off}}}}}"#)).unwrap();
                assert!(
                    claude_controls(dir.path()).unwrap().is_empty(),
                    "{key} {off}"
                );
            }
        }
    }

    #[test]
    fn outside_working_directory_blocks_are_reported_from_non_managed_files() {
        let dir = tempfile::tempdir().unwrap();
        let (user, local) = (
            dir.path().join("settings.json"),
            dir.path().join("settings.local.json"),
        );
        let files = [user.clone(), local.clone()];
        assert!(claude_outside_dir_controls(&files).is_empty());
        for key in [
            "blockReadsOutsideWorkingDirectories",
            "blockWritesOutsideWorkingDirectories",
        ] {
            std::fs::write(&user, format!(r#"{{"permissions":{{"{key}":true}}}}"#)).unwrap();
            let found = claude_outside_dir_controls(&files);
            assert_eq!(found.len(), 1, "{key}");
            assert_eq!(
                found[0].id,
                format!("claude_code.configured.permissions.{key}")
            );
            assert_eq!(found[0].setting, format!("permissions.{key}"));
            assert_eq!(found[0].value, Value::Bool(true));
            assert_eq!(found[0].source_path, user);
            for off in ["false", r#""true""#, "1", "null"] {
                std::fs::write(&user, format!(r#"{{"permissions":{{"{key}":{off}}}}}"#)).unwrap();
                assert!(
                    claude_outside_dir_controls(&files).is_empty(),
                    "{key} {off}"
                );
            }
        }
        std::fs::write(
            &user,
            r#"{"permissions":{"blockReadsOutsideWorkingDirectories":false}}"#,
        )
        .unwrap();
        std::fs::write(
            &local,
            r#"{"permissions":{"blockReadsOutsideWorkingDirectories":true,"blockWritesOutsideWorkingDirectories":true}}"#,
        )
        .unwrap();
        let found = claude_outside_dir_controls(&files);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|c| c.source_path == local));
    }

    #[test]
    fn managed_and_user_outside_working_directory_blocks_are_listed_together() {
        let dir = tempfile::tempdir().unwrap();
        let managed = dir.path().join("managed-settings.json");
        let user = dir.path().join("settings.json");
        let key = "blockReadsOutsideWorkingDirectories";
        let listed = |managed_on: bool, user_on: bool| {
            std::fs::write(
                &managed,
                format!(r#"{{"permissions":{{"{key}":{managed_on}}}}}"#),
            )
            .unwrap();
            std::fs::write(&user, format!(r#"{{"permissions":{{"{key}":{user_on}}}}}"#)).unwrap();
            let mut all = claude_controls(dir.path()).unwrap();
            all.extend(claude_outside_dir_controls(std::slice::from_ref(&user)));
            all
        };

        let both = listed(true, true);
        assert_eq!(both.len(), 2);
        assert!(both
            .iter()
            .all(|c| c.id == format!("claude_code.configured.permissions.{key}")));
        let sources: Vec<_> = both.iter().map(|c| c.source_path.clone()).collect();
        assert_eq!(sources, [managed.clone(), user.clone()]);

        let user_only = listed(false, true);
        assert_eq!(user_only.len(), 1);
        assert_eq!(user_only[0].source_path, user);

        let managed_only = listed(true, false);
        assert_eq!(managed_only.len(), 1);
        assert_eq!(managed_only[0].source_path, managed);
    }

    #[test]
    fn outside_working_directory_controls_skip_missing_and_broken_files() {
        let dir = tempfile::tempdir().unwrap();
        let broken = dir.path().join("settings.json");
        std::fs::write(&broken, "{").unwrap();
        let ok = dir.path().join("settings.local.json");
        std::fs::write(
            &ok,
            r#"{"permissions":{"blockWritesOutsideWorkingDirectories":true}}"#,
        )
        .unwrap();
        let found =
            claude_outside_dir_controls(&[broken, dir.path().join("absent.json"), ok.clone()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].source_path, ok);
    }

    #[test]
    fn claude_disable_auto_mode_is_reported_top_level_or_under_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed-settings.json");
        for text in [
            r#"{"disableAutoMode":"disable"}"#,
            r#"{"permissions":{"disableAutoMode":"disable"}}"#,
        ] {
            std::fs::write(&path, text).unwrap();
            let controls = claude_controls(dir.path()).unwrap();
            assert!(
                controls
                    .iter()
                    .any(|c| c.setting.ends_with("disableAutoMode")),
                "{text}"
            );
        }
        std::fs::write(&path, r#"{"disableAutoMode":"enable"}"#).unwrap();
        assert!(claude_controls(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn claude_drop_ins_override_scalars_with_correct_provenance() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("managed-settings.json"), r#"{"allowManagedHooksOnly":true,"sandbox":{"enabled":true,"allowUnsandboxedCommands":false}}"#).unwrap();
        let drops = dir.path().join("managed-settings.d");
        std::fs::create_dir(&drops).unwrap();
        std::fs::write(
            drops.join("10-disable.json"),
            r#"{"allowManagedHooksOnly":false,"sandbox":{"enabled":false}}"#,
        )
        .unwrap();
        assert!(claude_controls(dir.path()).unwrap().is_empty());
        let last = drops.join("20-enable.json");
        std::fs::write(&last, r#"{"allowManagedHooksOnly":true}"#).unwrap();
        std::fs::write(drops.join(".hidden.json"), "broken").unwrap();
        let controls = claude_controls(dir.path()).unwrap();
        assert_eq!(controls.len(), 1);
        assert_eq!(controls[0].source_path, last);
    }

    #[test]
    fn malformed_and_oversized_policies_fail_instead_of_empty_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed-settings.json");
        for text in ["{", "[]", "", "null"] {
            std::fs::write(&path, text).unwrap();
            assert!(claude_controls(dir.path()).is_err());
        }
        std::fs::write(&path, " ".repeat(MAX_POLICY_BYTES as usize + 1)).unwrap();
        assert!(claude_controls(dir.path()).is_err());
    }
}
