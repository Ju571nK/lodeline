//! #203 — Grok Build parser. Measured with `grok inspect --json` on Grok 1.0.70
//! (folder trust off, so every source loaded):
//!
//! - user hooks: every `~/.grok/hooks/*.json`, and the `[hooks]` table of
//!   `~/.grok/config.toml`;
//! - project hooks: every `<repo>/.grok/hooks/*.json`. A project
//!   `.grok/config.toml` `[hooks]` table did not load;
//! - MCP servers: `[mcp_servers.<name>]` in the user and project
//!   `config.toml`, except one with `enabled = false`.
//!
//! - managed and requirements files: `~/.grok/managed_config.toml`,
//!   `~/.grok/requirements.toml` and the same names under `/etc/grok`. Grok 1.0.77
//!   reads the same `[[hooks.<Event>]]` and `[mcp_servers]` tables from them. A
//!   managed hook always runs; the others wait for folder trust, and a file here
//!   is scored either way. A hook group without an inner `hooks` array does not
//!   load, so it adds nothing.
//!
//! Hook files hold Claude's matcher groups and the `config.toml` table Codex's,
//! so each goes through that tool's emitter. Grok runs a hook only in a trusted
//! folder; like the other project parsers, a committed file is scored whether
//! or not this checkout is trusted. Grok also runs `~/.claude` and `.cursor`
//! hooks and MCP servers, which the Claude and Cursor parsers already score.

use crate::ai_guard::parser::{AiGuardParser, AssessError};
use lodeline_core::event::{AiGuardReason, AiGuardScope, AiTool};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

/// The hook groups of every `*.json` in `dir`, merged per event in file-name
/// order, so a host-wide reason such as `NoSandbox` is counted once.
/// A file that does not parse is skipped with a warning, as Cursor's
/// `hooks.json` is, so it does not hide the other files and the MCP servers.
fn hooks_in_dir(dir: &Path) -> Value {
    let mut files: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json") && p.is_file())
            .collect(),
        Err(_) => Vec::new(),
    };
    files.sort();
    let mut events: Map<String, Value> = Map::new();
    for file in files {
        let val = match super::read_json_optional(&file) {
            Ok(Some(val)) => val,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(path = %file.display(), %error, "grok hook file skipped");
                continue;
            }
        };
        let Some(hooks) = val.get("hooks").and_then(Value::as_object) else {
            continue;
        };
        for (event, groups) in hooks {
            let Some(groups) = groups.as_array() else {
                continue;
            };
            let slot = events
                .entry(event.clone())
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Value::Array(all) = slot {
                all.extend(groups.iter().cloned());
            }
        }
    }
    serde_json::json!({ "hooks": events })
}

fn read_config(path: &Path) -> Result<Option<toml::Value>, AssessError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(AssessError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    toml::from_str(&text)
        .map(Some)
        .map_err(|e| AssessError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
}

fn emit_mcp_reasons(config: &toml::Value, out: &mut Vec<AiGuardReason>) {
    let Some(servers) = config.get("mcp_servers").and_then(toml::Value::as_table) else {
        return;
    };
    for (name, def) in servers {
        if def.get("enabled").and_then(toml::Value::as_bool) == Some(false) {
            continue;
        }
        if let Ok(def) = serde_json::to_value(def) {
            super::mcp_scan::emit_one_server(name, &def, out);
        }
    }
}

/// Hooks and MCP servers of one Grok folder (`~/.grok` or `<repo>/.grok`).
/// `config_hooks` is false for a project, whose `config.toml` hooks Grok
/// does not load.
fn assess_dir(grok: &Path, config_hooks: bool) -> Result<Vec<AiGuardReason>, AssessError> {
    let mut out = Vec::new();
    // shortcut: the shell Grok runs hooks through is unchecked, so `~` stays as
    // written; pass the home once that is verified.
    super::claude_code::emit_hook_reasons(&hooks_in_dir(&grok.join("hooks")), None, &mut out)?;
    if let Some(config) = read_config(&grok.join("config.toml"))? {
        if config_hooks {
            super::codex::emit_hook_reasons(&config, |_, _, _| true, None, &mut out);
        }
        emit_mcp_reasons(&config, &mut out);
    }
    Ok(out)
}

/// `/etc/grok` holds the root-owned layer. Windows has no such layer.
fn system_dir() -> Option<PathBuf> {
    cfg!(not(windows)).then(|| PathBuf::from("/etc/grok"))
}

const POLICY_FILES: [&str; 2] = ["managed_config.toml", "requirements.toml"];

fn emit_policy_file(path: &Path, out: &mut Vec<AiGuardReason>) -> Result<(), AssessError> {
    if let Some(config) = read_config(path)? {
        super::codex::emit_hook_reasons(&config, |_, _, _| true, None, out);
        emit_mcp_reasons(&config, out);
    }
    Ok(())
}

/// The user folder plus the managed and requirements files of the user and
/// system layers, which Grok loads for every session.
fn assess_user(home_dir: &Path, system: Option<&Path>) -> Result<Vec<AiGuardReason>, AssessError> {
    let grok = home_dir.join(".grok");
    let mut out = assess_dir(&grok, true)?;
    for dir in system.into_iter().chain([grok.as_path()]) {
        for name in POLICY_FILES {
            emit_policy_file(&dir.join(name), &mut out)?;
        }
    }
    Ok(out)
}

fn watched(grok: &Path) -> Vec<PathBuf> {
    vec![grok.join("hooks"), grok.join("config.toml")]
}

pub struct GrokParser;

impl AiGuardParser for GrokParser {
    fn tool(&self) -> AiTool {
        AiTool::Grok
    }
    fn scope(&self) -> AiGuardScope {
        AiGuardScope::UserGlobal
    }
    // shortcut: `GROK_HOME` moves `~/.grok` and is not followed, as for the
    // installer; read it here if a host is found relying on it.
    fn watched_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        let grok = home_dir.join(".grok");
        let mut paths = watched(&grok);
        for dir in system_dir().into_iter().chain([grok]) {
            paths.extend(POLICY_FILES.map(|name| dir.join(name)));
        }
        paths
    }
    fn assess(&self, home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        assess_user(home_dir, system_dir().as_deref())
    }
}

pub struct GrokProjectParser {
    pub repo_root: PathBuf,
}

impl AiGuardParser for GrokProjectParser {
    fn tool(&self) -> AiTool {
        AiTool::Grok
    }
    fn scope(&self) -> AiGuardScope {
        AiGuardScope::Project {
            path: self.repo_root.clone(),
        }
    }
    fn watched_paths(&self, _home: &Path) -> Vec<PathBuf> {
        watched(&self.repo_root.join(".grok"))
    }
    fn assess(&self, _home: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        assess_dir(&self.repo_root.join(".grok"), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn destructive(out: &[AiGuardReason]) -> Vec<&str> {
        let mut snippets: Vec<&str> = out
            .iter()
            .filter_map(|r| match r {
                AiGuardReason::DestructiveInInlineCommand { snippet, .. } => Some(snippet.as_str()),
                _ => None,
            })
            .collect();
        snippets.sort_unstable();
        snippets
    }

    const HOOK_FILE: &str = r#"{"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "rm -rf /tmp/a"}]}
    ]}}"#;

    #[test]
    fn a_bad_hook_file_does_not_hide_the_others_or_the_mcp_servers() {
        let home = tempdir().unwrap();
        let grok = home.path().join(".grok");
        write(&grok.join("hooks").join("a.json"), "{ not json");
        write(&grok.join("hooks").join("b.json"), HOOK_FILE);
        write(
            &grok.join("config.toml"),
            "[mcp_servers.local]\ncommand = \"node\"\n",
        );
        let out = GrokParser.assess(home.path()).unwrap();
        assert_eq!(destructive(&out), ["rm -rf /tmp/a"], "{out:?}");
        assert!(out
            .iter()
            .any(|r| matches!(r, AiGuardReason::McpServerLocalCommand { .. })));
    }

    #[test]
    fn missing_grok_dir_is_clean() {
        let home = tempdir().unwrap();
        assert!(GrokParser.assess(home.path()).unwrap().is_empty());
    }

    #[test]
    fn every_user_hook_file_is_read_and_counted_once() {
        let home = tempdir().unwrap();
        let hooks = home.path().join(".grok").join("hooks");
        write(&hooks.join("a.json"), HOOK_FILE);
        write(
            &hooks.join("b.json"),
            &HOOK_FILE.replace("/tmp/a", "/tmp/b"),
        );
        write(&hooks.join("notes.txt"), "rm -rf /tmp/c");
        let out = GrokParser.assess(home.path()).unwrap();
        assert_eq!(
            destructive(&out),
            ["rm -rf /tmp/a", "rm -rf /tmp/b"],
            "{out:?}"
        );
        let sandbox = out
            .iter()
            .filter(|r| matches!(r, AiGuardReason::NoSandbox { .. }))
            .count();
        assert_eq!(sandbox, 1, "{out:?}");
    }

    #[test]
    fn user_config_toml_hooks_and_mcp_servers_are_read() {
        let home = tempdir().unwrap();
        write(
            &home.path().join(".grok").join("config.toml"),
            r#"
[mcp_servers.local]
command = "node"
args = ["server.js"]

[mcp_servers.off]
url = "https://off.example/mcp"
enabled = false

[[hooks.PreToolUse]]
matcher = ""
[[hooks.PreToolUse.hooks]]
type = "command"
command = "rm -rf /tmp/config"
"#,
        );
        let out = GrokParser.assess(home.path()).unwrap();
        assert_eq!(destructive(&out), ["rm -rf /tmp/config"], "{out:?}");
        assert!(out.iter().any(|r| matches!(
            r,
            AiGuardReason::McpServerLocalCommand { server_name, .. } if server_name == "local"
        )));
        assert!(
            !out.iter()
                .any(|r| matches!(r, AiGuardReason::McpServerRemote { .. })),
            "a disabled server does not start; got {out:?}"
        );
    }

    #[test]
    fn project_hook_files_and_mcp_are_read_but_not_config_hooks() {
        let repo = tempdir().unwrap();
        let grok = repo.path().join(".grok");
        write(&grok.join("hooks").join("guard.json"), HOOK_FILE);
        write(
            &grok.join("config.toml"),
            r#"
[mcp_servers.remote]
url = "https://mcp.example/x"

[[hooks.PreToolUse]]
[[hooks.PreToolUse.hooks]]
type = "command"
command = "rm -rf /tmp/project-config"
"#,
        );
        let p = GrokProjectParser {
            repo_root: repo.path().to_path_buf(),
        };
        let out = p.assess(Path::new("/unused")).unwrap();
        assert_eq!(destructive(&out), ["rm -rf /tmp/a"], "{out:?}");
        assert!(out
            .iter()
            .any(|r| matches!(r, AiGuardReason::McpServerRemote { .. })));
        assert_eq!(
            p.scope(),
            AiGuardScope::Project {
                path: repo.path().to_path_buf()
            }
        );
    }

    #[test]
    fn corrupt_config_toml_is_a_parse_error() {
        let home = tempdir().unwrap();
        write(
            &home.path().join(".grok").join("config.toml"),
            "[mcp_servers",
        );
        assert!(matches!(
            GrokParser.assess(home.path()).unwrap_err(),
            AssessError::Parse { .. }
        ));
    }

    #[test]
    fn own_grok_hook_file_adds_no_unscanned_script() {
        let home = tempdir().unwrap();
        write(
            &home
                .path()
                .join(".grok")
                .join("hooks")
                .join("lodeline-hook.json"),
            r#"{"hooks": {"PreToolUse": [{"matcher": "", "hooks": [
                {"type": "command", "command": "/nonexistent/lodeline-hook grok --capture redacted"}
            ]}]}}"#,
        );
        let out = GrokParser.assess(home.path()).unwrap();
        assert!(
            !out.iter()
                .any(|r| matches!(r, AiGuardReason::ExternalScriptUnscanned { .. })),
            "{out:?}"
        );
    }

    const MANAGED: &str = r#"
[[hooks.PreToolUse]]
matcher = "Bash"
hooks = [{ type = "command", command = "rm -rf /tmp/managed" }]

[mcp_servers.org]
command = "org-mcp"

[mcp_servers.off]
url = "https://off.example/mcp"
enabled = false
"#;

    fn user_assess(home: &Path, etc: &Path) -> Vec<AiGuardReason> {
        assess_user(home, Some(etc)).unwrap()
    }

    #[test]
    fn user_managed_and_requirements_files_are_read() {
        let home = tempdir().unwrap();
        let grok = home.path().join(".grok");
        write(&grok.join("managed_config.toml"), MANAGED);
        write(
            &grok.join("requirements.toml"),
            &MANAGED.replace("managed", "pinned"),
        );
        let out = GrokParser.assess(home.path()).unwrap();
        assert_eq!(
            destructive(&out),
            ["rm -rf /tmp/managed", "rm -rf /tmp/pinned"],
            "{out:?}"
        );
        assert!(out.iter().any(|r| matches!(
            r,
            AiGuardReason::McpServerLocalCommand { server_name, .. } if server_name == "org"
        )));
        assert!(
            !out.iter()
                .any(|r| matches!(r, AiGuardReason::McpServerRemote { .. })),
            "a disabled server does not start; got {out:?}"
        );
    }

    #[test]
    fn system_managed_and_requirements_files_are_read() {
        let home = tempdir().unwrap();
        let etc = tempdir().unwrap();
        write(&etc.path().join("managed_config.toml"), MANAGED);
        write(
            &etc.path().join("requirements.toml"),
            &MANAGED.replace("managed", "system"),
        );
        let out = user_assess(home.path(), etc.path());
        assert_eq!(
            destructive(&out),
            ["rm -rf /tmp/managed", "rm -rf /tmp/system"],
            "{out:?}"
        );
    }

    #[test]
    fn hook_group_without_inner_hooks_adds_nothing() {
        let home = tempdir().unwrap();
        write(
            &home.path().join(".grok").join("managed_config.toml"),
            "[[hooks.PreToolUse]]\ntype = \"command\"\ncommand = \"rm -rf /tmp/flat\"\n",
        );
        let out = GrokParser.assess(home.path()).unwrap();
        assert!(destructive(&out).is_empty(), "{out:?}");
    }

    #[test]
    fn corrupt_managed_file_is_a_parse_error() {
        let home = tempdir().unwrap();
        let etc = tempdir().unwrap();
        write(&etc.path().join("requirements.toml"), "[[hooks.PreToolUse");
        assert!(matches!(
            assess_user(home.path(), Some(etc.path())).unwrap_err(),
            AssessError::Parse { .. }
        ));
    }

    #[test]
    fn project_folder_does_not_read_managed_files() {
        let repo = tempdir().unwrap();
        write(
            &repo.path().join(".grok").join("managed_config.toml"),
            MANAGED,
        );
        let p = GrokProjectParser {
            repo_root: repo.path().to_path_buf(),
        };
        assert!(p.assess(Path::new("/unused")).unwrap().is_empty());
    }

    #[test]
    fn watched_paths_include_both_managed_files_of_each_layer() {
        let home = Path::new("/home/alice");
        let watched = GrokParser.watched_paths(home);
        for name in ["managed_config.toml", "requirements.toml"] {
            assert!(
                watched.contains(&home.join(".grok").join(name)),
                "{watched:?}"
            );
        }
        #[cfg(unix)]
        for name in ["managed_config.toml", "requirements.toml"] {
            assert!(
                watched.contains(&Path::new("/etc/grok").join(name)),
                "{watched:?}"
            );
        }
    }
}
