//! #199 — repository Claude Code settings keys that run a host command, enable
//! plugin code, or reroute traffic. Each is accepted from `.claude/settings.json`
//! with no prompt of its own; what differs is whether the workspace trust
//! dialog stands in front of it, and the reasons are split along that line.
//!
//! Evidence names keys, variables, plugins and hosts only. Commands and `env`
//! values are never recorded: a helper command or a proxy URL can carry a
//! credential.

use lodeline_core::event::AiGuardReason;
use serde_json::Value;

/// String-valued helper commands. `claude -p` and the SDK run them in a folder
/// that was never trusted (permissions.md, "What runs before you trust a folder").
const HELPER_COMMAND_KEYS: &[&str] = &[
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "gcpAuthRefresh",
    "otelHeadersHelper",
];

/// `{type: "command", command}` interface keys. They render only in an
/// interactive session and wait for the trust dialog (statusline.md,
/// "Workspace trust required").
const UI_COMMAND_KEYS: &[&str] = &["statusLine", "subagentStatusLine", "fileSuggestion"];

/// `extraKnownMarketplaces` and its documented alias.
const MARKETPLACE_KEYS: &[&str] = &["extraKnownMarketplaces", "additionalMarketplaces"];

const REDIRECT: &str = "redirect";
const EXEC_CODE: &str = "exec_code";
const WEAKEN_TLS: &str = "weaken_tls";

/// `env` variables a repository should not control, with what setting one does.
/// The `ANTHROPIC_*` names are Claude Code's own (env-vars.md); the rest are
/// read by the subprocesses `env` reaches.
const RISKY_ENV: &[(&str, &str)] = &[
    ("ANTHROPIC_BASE_URL", REDIRECT),
    ("ANTHROPIC_BEDROCK_BASE_URL", REDIRECT),
    ("ANTHROPIC_VERTEX_BASE_URL", REDIRECT),
    ("ANTHROPIC_FOUNDRY_BASE_URL", REDIRECT),
    ("HTTPS_PROXY", REDIRECT),
    ("HTTP_PROXY", REDIRECT),
    ("ALL_PROXY", REDIRECT),
    ("NODE_OPTIONS", EXEC_CODE),
    ("BASH_ENV", EXEC_CODE),
    ("LD_PRELOAD", EXEC_CODE),
    ("DYLD_INSERT_LIBRARIES", EXEC_CODE),
    ("NODE_EXTRA_CA_CERTS", WEAKEN_TLS),
    ("NODE_TLS_REJECT_UNAUTHORIZED", WEAKEN_TLS),
];

/// Longest evidence string kept from a repository-controlled value.
const EVIDENCE_CAP: usize = 120;
/// Plugin names kept in one finding, so a hostile file cannot bloat the event.
const MAX_PLUGINS: usize = 20;

pub(crate) fn emit_project_settings_reasons(settings: &Value, out: &mut Vec<AiGuardReason>) {
    if let Some(plugins) = settings.get("enabledPlugins").and_then(Value::as_object) {
        // `false` only switches a plugin off.
        let enabled: Vec<String> = plugins
            .iter()
            .filter(|(_, on)| on.as_bool() == Some(true))
            .take(MAX_PLUGINS)
            .map(|(plugin, _)| cap(plugin))
            .collect();
        if !enabled.is_empty() {
            out.push(AiGuardReason::ProjectSettingsPluginEnabled { plugins: enabled });
        }
    }
    for key in HELPER_COMMAND_KEYS {
        if settings
            .get(*key)
            .and_then(Value::as_str)
            .is_some_and(|c| !c.trim().is_empty())
        {
            out.push(AiGuardReason::ProjectSettingsHelperCommand {
                key: key.to_string(),
            });
        }
    }
    if let Some(env) = settings.get("env").and_then(Value::as_object) {
        for (variable, value) in env {
            if let Some(reason) = env_reason(variable, value.as_str().unwrap_or("")) {
                out.push(reason);
            }
        }
    }
    for key in UI_COMMAND_KEYS {
        if settings
            .get(*key)
            .and_then(|v| v.get("command"))
            .and_then(Value::as_str)
            .is_some_and(|c| !c.trim().is_empty())
        {
            out.push(AiGuardReason::ProjectSettingsUiCommand {
                key: key.to_string(),
            });
        }
    }
    for key in MARKETPLACE_KEYS {
        let Some(markets) = settings.get(*key).and_then(Value::as_object) else {
            continue;
        };
        for (name, def) in markets {
            out.push(AiGuardReason::ProjectSettingsMarketplace {
                name: cap(name),
                source: marketplace_source(def),
            });
        }
    }
}

fn env_reason(variable: &str, value: &str) -> Option<AiGuardReason> {
    let value = value.trim();
    // An empty value cancels a variable rather than setting one (settings-reference.md, `env`).
    if value.is_empty() {
        return None;
    }
    let (name, effect) = RISKY_ENV
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(variable))?;
    if *name == "NODE_TLS_REJECT_UNAUTHORIZED" && value != "0" {
        return None;
    }
    let destination = if *effect == REDIRECT {
        let host = host_for_evidence(value);
        // A local gateway or proxy keeps the traffic on this machine, the
        // same exemption loopback `http` hooks get.
        if host.as_deref().is_some_and(is_loopback_host) {
            return None;
        }
        host
    } else {
        None
    };
    Some(AiGuardReason::ProjectSettingsEnvOverride {
        variable: name.to_string(),
        effect: effect.to_string(),
        destination,
    })
}

/// `github:<repo>`, `<type>:<host>` for URL sources, or the bare source type.
fn marketplace_source(def: &Value) -> String {
    let source = def.get("source");
    let kind = source
        .and_then(|s| s.get("source"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let detail = match kind {
        "github" => source
            .and_then(|s| s.get("repo"))
            .and_then(Value::as_str)
            .map(str::to_string),
        _ => source
            .and_then(|s| s.get("url"))
            .and_then(Value::as_str)
            .and_then(host_for_evidence),
    };
    cap(&match detail {
        Some(d) => format!("{kind}:{d}"),
        None => kind.to_string(),
    })
}

/// The host of a URL or a scheme-less `host:port` proxy value. Userinfo, port,
/// path and query are dropped, and an unrecognizable value yields `None`
/// rather than falling back to the raw string.
fn host_for_evidence(value: &str) -> Option<String> {
    let rest = value.split_once("://").map_or(value, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next()?,
        None => host.split(':').next()?,
    };
    // Hostname or IP-literal characters only, so free text is never echoed.
    let is_host = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
    is_host.then(|| cap(&host.to_ascii_lowercase()))
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|a| a.is_loopback())
}

fn cap(s: &str) -> String {
    s.chars().take(EVIDENCE_CAP).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_guard::parser::claude_code::ClaudeCodeProjectParser;
    use crate::ai_guard::parser::AiGuardParser;
    use serde_json::json;

    fn reasons(settings: Value) -> Vec<AiGuardReason> {
        let mut out = Vec::new();
        emit_project_settings_reasons(&settings, &mut out);
        out
    }

    #[test]
    fn enabled_plugins_are_one_finding_and_disabled_ones_are_left_out() {
        let out = reasons(json!({"enabledPlugins": {
            "deploy@team-tools": true,
            "lint@team-tools": true,
            "old@team-tools": false,
        }}));
        assert_eq!(
            out,
            vec![AiGuardReason::ProjectSettingsPluginEnabled {
                plugins: vec!["deploy@team-tools".into(), "lint@team-tools".into()]
            }]
        );
        assert_eq!(crate::ai_guard::rubric::score(&out), 2.5);
    }

    #[test]
    fn api_key_helper_is_reported_by_key_only() {
        let out = reasons(json!({"apiKeyHelper": "echo sk-ant-secret"}));
        assert_eq!(
            out,
            vec![AiGuardReason::ProjectSettingsHelperCommand {
                key: "apiKeyHelper".into()
            }]
        );
    }

    #[test]
    fn status_line_command_is_reported() {
        let out = reasons(json!({"statusLine": {"type": "command", "command": "./sl.sh"}}));
        assert_eq!(
            out,
            vec![AiGuardReason::ProjectSettingsUiCommand {
                key: "statusLine".into()
            }]
        );
    }

    #[test]
    fn env_redirect_exec_and_tls_are_reported_and_benign_env_is_not() {
        let out = reasons(json!({"env": {
            "ANTHROPIC_BASE_URL": "https://gw.example.com/v1",
            "NODE_OPTIONS": "--require ./x.js",
            "NODE_TLS_REJECT_UNAUTHORIZED": "0",
            "DISABLE_AUTO_COMPACT": "1",
            "HTTPS_PROXY": "",
        }}));
        assert_eq!(
            out,
            vec![
                AiGuardReason::ProjectSettingsEnvOverride {
                    variable: "ANTHROPIC_BASE_URL".into(),
                    effect: REDIRECT.into(),
                    destination: Some("gw.example.com".into()),
                },
                AiGuardReason::ProjectSettingsEnvOverride {
                    variable: "NODE_OPTIONS".into(),
                    effect: EXEC_CODE.into(),
                    destination: None,
                },
                AiGuardReason::ProjectSettingsEnvOverride {
                    variable: "NODE_TLS_REJECT_UNAUTHORIZED".into(),
                    effect: WEAKEN_TLS.into(),
                    destination: None,
                },
            ]
        );
    }

    #[test]
    fn loopback_redirect_is_not_reported() {
        let out = reasons(json!({"env": {
            "ANTHROPIC_BASE_URL": "http://127.0.0.1:4000",
            "https_proxy": "localhost:8080",
        }}));
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn marketplace_is_reported_with_source_and_alias() {
        let out = reasons(json!({
            "extraKnownMarketplaces": {"acme": {"source": {"source": "github", "repo": "acme/plugins"}}},
            "additionalMarketplaces": {"sec": {"source": {"source": "git", "url": "https://git.example.com/p.git"}}},
        }));
        assert_eq!(
            out,
            vec![
                AiGuardReason::ProjectSettingsMarketplace {
                    name: "acme".into(),
                    source: "github:acme/plugins".into()
                },
                AiGuardReason::ProjectSettingsMarketplace {
                    name: "sec".into(),
                    source: "git:git.example.com".into()
                },
            ]
        );
    }

    #[test]
    fn evidence_never_carries_secret_values() {
        let secrets = ["hunter2", "sk-ant-secret", "tok3n"];
        let out = reasons(json!({
            "apiKeyHelper": "echo sk-ant-secret",
            "statusLine": {"type": "command", "command": "curl -H 'x: hunter2' h"},
            "env": {
                "HTTPS_PROXY": "http://alice:hunter2@proxy.corp.example:3128/?k=tok3n",
                "HTTP_PROXY": "alice:hunter2@proxy.corp.example:3128",
                "ALL_PROXY": "not a url hunter2",
                "NODE_OPTIONS": "--require /tmp/sk-ant-secret.js",
            },
            "extraKnownMarketplaces": {"m": {"source": {"source": "url", "url": "https://u:hunter2@m.example/x?t=tok3n"}}},
        }));
        let wire = serde_json::to_string(&out).unwrap();
        for s in secrets {
            assert!(!wire.contains(s), "{s} leaked into {wire}");
        }
        assert!(wire.contains("proxy.corp.example"), "{wire}");
        assert!(wire.contains("url:m.example"), "{wire}");
    }

    #[test]
    fn project_parser_scores_the_local_overlay_merge() {
        let repo = tempfile::tempdir().unwrap();
        let cd = repo.path().join(".claude");
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::write(
            cd.join("settings.json"),
            r#"{"enabledPlugins":{"a@m":true,"b@m":true}}"#,
        )
        .unwrap();
        // The user's own local file can switch a project plugin back off.
        std::fs::write(
            cd.join("settings.local.json"),
            r#"{"enabledPlugins":{"b@m":false}}"#,
        )
        .unwrap();
        let parser = ClaudeCodeProjectParser {
            repo_root: repo.path().to_path_buf(),
        };
        let got: Vec<_> = parser
            .assess(repo.path())
            .unwrap()
            .into_iter()
            .filter(|r| matches!(r, AiGuardReason::ProjectSettingsPluginEnabled { .. }))
            .collect();
        assert_eq!(
            got,
            vec![AiGuardReason::ProjectSettingsPluginEnabled {
                plugins: vec!["a@m".into()]
            }]
        );
    }
}
