//! Phase 3b.7 — RulePackParser: generic AiGuardParser driven by a RulePack.

use crate::ai_guard::parser::mcp_scan::url_for_evidence;
use crate::ai_guard::parser::{AiGuardParser, AssessError};
use crate::ai_guard::rule_pack::matcher::{
    compile_condition_regexes, compile_pack_regexes, matches_value, CompileError,
};
use crate::ai_guard::rule_pack::selector::{eval_json, eval_toml, MatchedValue};
use lodeline_core::event::{AiGuardReason, AiGuardScope, AiTool};
use lodeline_core::policy::{RuleFormat, RulePack, RulePackScope};
use lodeline_core::redact::{has_url_scheme, redact_url};
use std::path::{Path, PathBuf};

pub struct RulePackParser {
    pub pack: RulePack,
    /// Compiled regexes parallel to pack.rules (None when matcher != Regex).
    compiled_regexes: Vec<Option<regex::Regex>>,
    /// Compiled regexes for each rule's `when` conditions, parallel to
    /// pack.rules then to that rule's `when` (None when matcher != Regex).
    compiled_condition_regexes: Vec<Vec<Option<regex::Regex>>>,
    pub(crate) repo_root: Option<std::path::PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum PackLoadError {
    #[error("rule pack '{id}' regex compile failed: {source}")]
    Regex { id: String, source: CompileError },
}

impl RulePackParser {
    pub fn new(pack: RulePack) -> Result<Self, PackLoadError> {
        let compiled_regexes =
            compile_pack_regexes(&pack.rules).map_err(|e| PackLoadError::Regex {
                id: pack.id.clone(),
                source: e,
            })?;
        let compiled_condition_regexes =
            compile_condition_regexes(&pack.rules).map_err(|e| PackLoadError::Regex {
                id: pack.id.clone(),
                source: e,
            })?;
        Ok(Self {
            pack,
            compiled_regexes,
            compiled_condition_regexes,
            repo_root: None,
        })
    }

    /// Phase 3b.7.2 — a Project-scoped instance bound to one discovered repo.
    /// on_file / watched_paths are resolved relative to `repo_root`.
    pub fn new_project(
        pack: RulePack,
        repo_root: std::path::PathBuf,
    ) -> Result<Self, PackLoadError> {
        let mut p = Self::new(pack)?;
        p.repo_root = Some(repo_root);
        Ok(p)
    }

    /// UserGlobal: expand the raw path with `~` / `$HOME` as the assessed
    /// `home` (#333). Project: join the raw (relative) path under repo_root.
    // shortcut: other variables (`%APPDATA%`, `$XDG_CONFIG_HOME`) still come from
    // the agent's env, so another user's reading would read the agent's file.
    // Harmless while only Unix fans out and its packs use `~`; derive them per
    // home before Windows fans out to users (#333).
    fn resolve(&self, raw: &str, home: &Path) -> Option<PathBuf> {
        use lodeline_core::policy::expand::{expand, EnvLookup, PerUserLookup};
        match &self.repo_root {
            Some(root) => Some(root.join(raw)),
            None => expand(
                raw,
                &PerUserLookup {
                    user_home: home.into(),
                    inner: &EnvLookup,
                },
            )
            .ok(),
        }
    }
}

impl AiGuardParser for RulePackParser {
    fn tool(&self) -> AiTool {
        self.pack.tool
    }

    fn scope(&self) -> AiGuardScope {
        match self.pack.scope {
            RulePackScope::UserGlobal => AiGuardScope::UserGlobal,
            RulePackScope::Project => AiGuardScope::Project {
                path: self.repo_root.clone().unwrap_or_default(),
            },
        }
    }

    fn rule_pack_id(&self) -> Option<&str> {
        Some(&self.pack.id)
    }

    fn tool_label(&self) -> Option<&str> {
        self.pack.tool_label.as_deref()
    }

    fn watched_paths(&self, home: &Path) -> Vec<PathBuf> {
        self.pack
            .watched_paths
            .iter()
            .filter_map(|raw| self.resolve(raw, home))
            .collect()
    }

    fn assess(&self, home: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        let mut out = Vec::new();
        for (idx, rule) in self.pack.rules.iter().enumerate() {
            let Some(file_path) = self.resolve(&rule.on_file, home) else {
                return Err(AssessError::Parse {
                    path: PathBuf::from(&rule.on_file),
                    message: "resolve failed".into(),
                });
            };

            let text = match std::fs::read_to_string(&file_path) {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(AssessError::Io {
                        path: file_path,
                        source,
                    })
                }
            };

            // Tier-2 gates: every `when` condition must hold (its selector finds
            // >=1 value matching its matcher, XOR negate). Any failing gate skips
            // this rule's emits. Empty `when` => zero gates => Tier-1 behavior.
            let mut gates_pass = true;
            for (cidx, cond) in rule.when.iter().enumerate() {
                let cond_matches = match rule.format {
                    RuleFormat::Json => eval_json(&text, &cond.selector, &file_path)?,
                    RuleFormat::Toml => eval_toml(&text, &cond.selector, &file_path)?,
                };
                let holds = cond_matches.iter().any(|mv| {
                    matches_value(
                        &cond.matcher,
                        mv,
                        self.compiled_condition_regexes[idx][cidx].as_ref(),
                    )
                });
                // passes iff (holds XOR negate); fails iff holds == negate
                if holds == cond.negate {
                    gates_pass = false;
                    break;
                }
            }
            if !gates_pass {
                continue;
            }

            let matches = match rule.format {
                RuleFormat::Json => eval_json(&text, &rule.selector, &file_path)?,
                RuleFormat::Toml => eval_toml(&text, &rule.selector, &file_path)?,
            };

            for matched in &matches {
                if matches_value(&rule.matcher, matched, self.compiled_regexes[idx].as_ref()) {
                    out.push(interpolate_reason(&rule.emit, &rule.selector, matched));
                }
            }
        }
        Ok(out)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Interpolate `<selector-key>` and `<selector-value>` tokens in every
/// String field of the AiGuardReason by serialize → str::replace →
/// deserialize round-trip. Variants without String fields pass through.
fn interpolate_reason(
    reason: &AiGuardReason,
    selector: &str,
    matched: &MatchedValue,
) -> AiGuardReason {
    let serialized = match serde_json::to_string(reason) {
        Ok(s) => s,
        Err(_) => return reason.clone(),
    };
    if !serialized.contains("<selector-key>") && !serialized.contains("<selector-value>") {
        return reason.clone();
    }
    // Escape the matched key/value for JSON-safe embedding.
    let key_escaped = serde_json::to_string(&matched.key)
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|_| matched.key.clone());
    // #403 — a URL is redacted before it is interpolated, whatever field it lands in.
    let value = evidence_value(selector, matched);
    let value_escaped = serde_json::to_string(&value)
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or(value);
    let interpolated = serialized
        .replace("<selector-key>", &key_escaped)
        .replace("<selector-value>", &value_escaped);
    // Substitution only changes escaped string content of a known reason, so
    // `Unknown` cannot come back; the arm keeps an agent from ever emitting it.
    let mut out = match serde_json::from_str(&interpolated) {
        Ok(AiGuardReason::Unknown(_)) | Err(_) => reason.clone(),
        Ok(known) => known,
    };
    // The url field is redacted even when the pack built it from a non-URL selector.
    if let AiGuardReason::McpServerRemote { url, .. } = &mut out {
        *url = url_for_evidence(url);
    }
    out
}

const URL_KEY_WORDS: [&str; 5] = ["url", "uri", "endpoint", "address", "host"];

/// The matched value as it may be reported. A URL-keyed value, or one that
/// starts with `scheme://`, is cut to `scheme://host[:port]`; a bare
/// single-label host (`localhost`) counts as a host. Any other value is kept
/// whole except for a credential-shaped `user:password@`, so a `command` like
/// `ssh user@host:path` stays intact as evidence.
fn evidence_value(selector: &str, matched: &MatchedValue) -> String {
    let last = selector.rsplit('.').next().unwrap_or_default();
    let last = last.split('[').next().unwrap_or_default();
    if [matched.key.as_str(), last].into_iter().any(names_url) || has_url_scheme(&matched.value) {
        redact_url(matched.value.trim()).unwrap_or_else(|| "<unparseable-url>".into())
    } else {
        strip_userinfo(&matched.value)
    }
}

/// A key names a URL when its last word is `url`, `uri`, `endpoint`, `address`
/// or `host` (singular or plural): the whole key, or after `_` or a camelCase
/// boundary (`base_url`, `httpUrl`). A hyphen is not a boundary, so a server
/// named `my-host` as a map key is a name, not a URL.
fn names_url(key: &str) -> bool {
    let forms = [
        key,
        key.strip_suffix("es").unwrap_or(key),
        key.strip_suffix('s').unwrap_or(key),
    ];
    forms.iter().any(|k| {
        URL_KEY_WORDS.iter().any(|word| {
            let Some((head, tail)) = k
                .len()
                .checked_sub(word.len())
                .and_then(|n| k.split_at_checked(n))
            else {
                return false;
            };
            tail.eq_ignore_ascii_case(word)
                && (head.is_empty()
                    || head.ends_with('_')
                    || (tail.starts_with(|c: char| c.is_ascii_uppercase())
                        && head.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())))
        })
    })
}

/// Replace each `user:password@` run with `<redacted>@`, keeping the rest. The
/// password may hold a `/`; a bare `user@host` has no `:` and stays as is.
/// shortcut: a password with an unencoded `?` or `#` ends the search early and
/// is kept, upgrade if a real config shows one.
fn strip_userinfo(value: &str) -> String {
    value
        .split_inclusive(char::is_whitespace)
        .map(strip_token_userinfo)
        .collect()
}

fn strip_token_userinfo(token: &str) -> String {
    let end = token.find(['?', '#']).unwrap_or(token.len());
    // An image digest (`img:1.2@sha256:…`) is not userinfo.
    let is_digest = |i: usize| {
        ["sha256:", "sha512:"]
            .iter()
            .any(|d| token[i + 1..].starts_with(d))
    };
    let Some(at) = token[..end]
        .rmatch_indices('@')
        .map(|(i, _)| i)
        .find(|&i| !is_digest(i))
    else {
        return token.into();
    };
    let head = &token[..at];
    let start = match head.find("://") {
        Some(i) => i + 3,
        None if head.starts_with("//") => 2,
        None => 0,
    };
    if head[start..].contains(':') {
        format!("{}<redacted>{}", &token[..start], &token[at..])
    } else {
        token.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lodeline_core::event::AiGuardReason;
    use lodeline_core::policy::{
        Condition, Matcher, RuleEntry, RuleFormat, RulePack, RulePackScope,
    };
    use tempfile::tempdir;

    fn pack_with_one_rule(
        on_file_abs: &str,
        selector: &str,
        matcher: Matcher,
        emit: AiGuardReason,
    ) -> RulePack {
        RulePack {
            id: "test-pack".into(),
            pack_version: 1,
            tool: AiTool::Gemini,
            scope: RulePackScope::UserGlobal,
            watched_paths: vec![on_file_abs.into()],
            platforms: None,
            tool_label: None,
            rules: vec![RuleEntry {
                id: "r1".into(),
                on_file: on_file_abs.into(),
                format: RuleFormat::Json,
                selector: selector.into(),
                matcher,
                emit,
                when: vec![],
            }],
        }
    }

    #[test]
    fn missing_watched_file_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir
            .path()
            .join("missing.json")
            .to_string_lossy()
            .to_string();
        let pack = pack_with_one_rule(
            &path,
            "$.foo",
            Matcher::Exists,
            AiGuardReason::SandboxDisabled,
        );
        let p = RulePackParser::new(pack).unwrap();
        assert!(p.assess(Path::new("/unused")).unwrap().is_empty());
    }

    #[test]
    fn matched_rule_emits_reason() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("settings.json");
        std::fs::write(&file, r#"{"sandbox": false}"#).unwrap();
        let pack = pack_with_one_rule(
            file.to_str().unwrap(),
            "$.sandbox",
            Matcher::Equals {
                value: "false".into(),
            },
            AiGuardReason::SandboxDisabled,
        );
        let p = RulePackParser::new(pack).unwrap();
        let out = p.assess(Path::new("/unused")).unwrap();
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], AiGuardReason::SandboxDisabled));
    }

    #[test]
    fn interpolation_substitutes_selector_key_in_emit() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("mcp.json");
        std::fs::write(&file, r#"{"mcpServers": {"alpha": {"url": "https://a"}}}"#).unwrap();
        // McpServerRemote has 2 required fields: server_name + url. Use
        // distinct tokens to verify both interpolate independently.
        let pack = pack_with_one_rule(
            file.to_str().unwrap(),
            "$.mcpServers.*.url",
            Matcher::Exists,
            AiGuardReason::McpServerRemote {
                server_name: "<selector-key>".into(),
                url: "<selector-value>".into(),
            },
        );
        let p = RulePackParser::new(pack).unwrap();
        let out = p.assess(Path::new("/unused")).unwrap();
        assert_eq!(out.len(), 1);
        match &out[0] {
            AiGuardReason::McpServerRemote { server_name, url } => {
                assert_eq!(server_name, "alpha");
                assert_eq!(url, "https://a");
            }
            other => panic!("got {other:?}"),
        }
    }

    /// #403 — a URL interpolated into a non-URL field is still redacted.
    #[test]
    fn interpolated_url_is_redacted_in_any_field() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("mcp.json");
        std::fs::write(
            &file,
            r#"{"mcpServers": {"alpha": {"url": "https://u:pw@a.example/p?k=T"},
                                "beta": {"endpoint": "https://u:pw@b.example/p"},
                                "gamma": {"url": "u:pw@c.example"}}}"#,
        )
        .unwrap();
        for (selector, want) in [
            ("$.mcpServers.*.url", vec!["c.example", "https://a.example"]),
            ("$.mcpServers.*.endpoint", vec!["https://b.example"]),
        ] {
            let pack = pack_with_one_rule(
                file.to_str().unwrap(),
                selector,
                Matcher::Exists,
                AiGuardReason::McpServerLocalCommand {
                    server_name: "<selector-key>".into(),
                    command: "run <selector-value>".into(),
                },
            );
            let out = RulePackParser::new(pack)
                .unwrap()
                .assess(Path::new("/unused"))
                .unwrap();
            let mut got: Vec<_> = out
                .iter()
                .map(|r| match r {
                    AiGuardReason::McpServerLocalCommand { command, .. } => command.clone(),
                    other => panic!("got {other:?}"),
                })
                .collect();
            got.sort();
            let want: Vec<_> = want.iter().map(|w| format!("run {w}")).collect();
            assert_eq!(got, want, "{selector}");
        }
    }

    /// A scheme-less URL is detected from the matched key (`uri`, `endpoint`,
    /// `address`, `host`, an array of them); every other value is interpolated
    /// as written, minus a `user:password@` run.
    #[test]
    fn interpolation_redacts_urls_by_key() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("cfg.json");
        std::fs::write(
            &file,
            r#"{"s": {"uri": "a.example/p?k=T", "Endpoint": "b.example/p?k=T",
                       "address": "c.example/p?k=T", "host": "d.example/p?k=T",
                       "note": "u:pw@e.example", "mail": "me@f.example",
                       "path": "g/h@i:j", "cmd": "node a/b.js"},
                "urls": ["k.example/p?k=T"]}"#,
        )
        .unwrap();
        for (selector, want) in [
            ("$.s.uri", vec!["a.example"]),
            (
                "$.s.*",
                vec![
                    "a.example",
                    "b.example",
                    "c.example",
                    "d.example",
                    "<redacted>@e.example",
                    "me@f.example",
                    "g/h@i:j",
                    "node a/b.js",
                ],
            ),
            ("$.urls[*]", vec!["k.example"]),
        ] {
            let pack = pack_with_one_rule(
                file.to_str().unwrap(),
                selector,
                Matcher::Exists,
                AiGuardReason::McpServerLocalCommand {
                    server_name: "<selector-key>".into(),
                    command: "run <selector-value>".into(),
                },
            );
            let out = RulePackParser::new(pack)
                .unwrap()
                .assess(Path::new("/unused"))
                .unwrap();
            let mut got: Vec<_> = out
                .iter()
                .map(|r| match r {
                    AiGuardReason::McpServerLocalCommand { command, .. } => command.clone(),
                    other => panic!("got {other:?}"),
                })
                .collect();
            got.sort();
            let mut want: Vec<_> = want.iter().map(|w| format!("run {w}")).collect();
            want.sort();
            assert_eq!(got, want, "{selector}");
        }
    }

    /// A credential is cut out of a non-URL value and nothing else; a URL-keyed
    /// value keeps only `scheme://host[:port]`, a bare host included.
    #[test]
    fn evidence_value_removes_only_the_credential() {
        for (key, value, want) in [
            ("command", "ssh user@host:path", "ssh user@host:path"),
            (
                "command",
                "git@github.com:o/r.git",
                "git@github.com:o/r.git",
            ),
            ("command", "a@b.com:x", "a@b.com:x"),
            (
                "command",
                "curl https://u:p@h/x?t=1",
                "curl https://<redacted>@h/x?t=1",
            ),
            ("command", "u:pa/ss@h.example", "<redacted>@h.example"),
            ("command", "//u:pw@host", "//<redacted>@host"),
            (
                "command",
                "docker run ghcr.io/o/img:1.2@sha256:abc",
                "docker run ghcr.io/o/img:1.2@sha256:abc",
            ),
            (
                "command",
                "pull u:pw@reg.example/img@sha256:abc",
                "pull <redacted>@reg.example/img@sha256:abc",
            ),
            ("my-host", "node a/b.js", "node a/b.js"),
            ("host", "localhost", "localhost"),
            ("baseUrl", "https://u:p@h:8443/p?q", "https://h:8443"),
        ] {
            let matched = MatchedValue {
                key: key.into(),
                value: value.into(),
            };
            assert_eq!(evidence_value("$.s.*", &matched), want, "{key}: {value}");
        }
    }

    #[test]
    fn interpolation_draws_from_primary_not_a_gate() {
        // A holding `when` gate must NOT affect interpolation — the emitted
        // reason still interpolates from the PRIMARY selector's matched value.
        let dir = tempdir().unwrap();
        let file = dir.path().join("mcp.json");
        std::fs::write(
            &file,
            r#"{"mcpServers": {"alpha": {"url": "https://a"}}, "gate": "go"}"#,
        )
        .unwrap();
        let mut pack = pack_with_one_rule(
            file.to_str().unwrap(),
            "$.mcpServers.*.url",
            Matcher::Exists,
            AiGuardReason::McpServerRemote {
                server_name: "<selector-key>".into(),
                url: "<selector-value>".into(),
            },
        );
        pack.pack_version = 2;
        pack.rules[0].when = vec![lodeline_core::policy::Condition {
            selector: "$.gate".into(),
            matcher: Matcher::Equals { value: "go".into() },
            negate: false,
        }];
        let out = RulePackParser::new(pack)
            .unwrap()
            .assess(Path::new("/unused"))
            .unwrap();
        assert_eq!(out.len(), 1);
        match &out[0] {
            // alpha / https://a come from the PRIMARY, not the gate's `$.gate`.
            AiGuardReason::McpServerRemote { server_name, url } => {
                assert_eq!(server_name, "alpha");
                assert_eq!(url, "https://a");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn corrupt_json_returns_parse_error() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("bad.json");
        std::fs::write(&file, "{ not json").unwrap();
        let pack = pack_with_one_rule(
            file.to_str().unwrap(),
            "$.foo",
            Matcher::Exists,
            AiGuardReason::SandboxDisabled,
        );
        let p = RulePackParser::new(pack).unwrap();
        let err = p.assess(Path::new("/unused")).unwrap_err();
        assert!(matches!(err, AssessError::Parse { .. }));
    }

    #[test]
    fn pack_with_malformed_regex_rejected_at_new() {
        let pack = RulePack {
            id: "bad-regex".into(),
            pack_version: 1,
            tool: AiTool::Gemini,
            scope: RulePackScope::UserGlobal,
            watched_paths: vec![],
            platforms: None,
            tool_label: None,
            rules: vec![RuleEntry {
                id: "r1".into(),
                on_file: "/tmp/x".into(),
                format: RuleFormat::Json,
                selector: "$.x".into(),
                matcher: Matcher::Regex {
                    pattern: "[unclosed".into(),
                },
                emit: AiGuardReason::SandboxDisabled,
                when: vec![],
            }],
        };
        assert!(RulePackParser::new(pack).is_err());
    }

    #[test]
    fn rule_pack_parser_reports_tool_label() {
        let mut pack = pack_with_one_rule(
            "/abs/c.json",
            "$.x",
            Matcher::Exists,
            AiGuardReason::SandboxDisabled,
        );
        pack.tool = AiTool::Other;
        pack.tool_label = Some("acme-ai".into());
        let p = RulePackParser::new(pack).unwrap();
        assert_eq!(p.tool(), AiTool::Other);
        assert_eq!(p.tool_label(), Some("acme-ai"));
    }

    #[test]
    fn tool_and_scope_from_pack() {
        let pack = pack_with_one_rule(
            "/tmp/x",
            "$.x",
            Matcher::Exists,
            AiGuardReason::SandboxDisabled,
        );
        let p = RulePackParser::new(pack).unwrap();
        assert_eq!(p.tool(), AiTool::Gemini);
        assert!(matches!(p.scope(), AiGuardScope::UserGlobal));
    }

    fn rule_with_when(on_file: &str, when: Vec<Condition>) -> RulePack {
        let mut p = pack_with_one_rule(
            on_file,
            "$.sandbox",
            Matcher::Equals {
                value: "false".into(),
            },
            AiGuardReason::SandboxDisabled,
        );
        p.pack_version = 2;
        p.rules[0].when = when;
        p
    }

    #[test]
    fn when_gate_holds_emits() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("c.json");
        std::fs::write(&f, r#"{"sandbox": false, "autoApprove": true}"#).unwrap();
        let p = rule_with_when(
            f.to_str().unwrap(),
            vec![Condition {
                selector: "$.autoApprove".into(),
                matcher: Matcher::Equals {
                    value: "true".into(),
                },
                negate: false,
            }],
        );
        let out = RulePackParser::new(p)
            .unwrap()
            .assess(Path::new("/unused"))
            .unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn when_gate_fails_suppresses() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("c.json");
        std::fs::write(&f, r#"{"sandbox": false, "autoApprove": false}"#).unwrap();
        let p = rule_with_when(
            f.to_str().unwrap(),
            vec![Condition {
                selector: "$.autoApprove".into(),
                matcher: Matcher::Equals {
                    value: "true".into(),
                },
                negate: false,
            }],
        );
        let out = RulePackParser::new(p)
            .unwrap()
            .assess(Path::new("/unused"))
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn when_negate_inverts() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("c.json");
        std::fs::write(&f, r#"{"sandbox": false}"#).unwrap();
        let p = rule_with_when(
            f.to_str().unwrap(),
            vec![Condition {
                selector: "$.allowlist".into(),
                matcher: Matcher::Exists,
                negate: true,
            }],
        );
        let out = RulePackParser::new(p)
            .unwrap()
            .assess(Path::new("/unused"))
            .unwrap();
        assert_eq!(out.len(), 1); // NOT exists(allowlist) holds → emit
    }

    #[test]
    fn multiple_gates_all_anded() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("c.json");
        std::fs::write(
            &f,
            r#"{"sandbox": false, "autoApprove": true, "allowlist": ["x"]}"#,
        )
        .unwrap();
        let p = rule_with_when(
            f.to_str().unwrap(),
            vec![
                Condition {
                    selector: "$.autoApprove".into(),
                    matcher: Matcher::Equals {
                        value: "true".into(),
                    },
                    negate: false,
                },
                Condition {
                    selector: "$.allowlist".into(),
                    matcher: Matcher::Exists,
                    negate: true,
                },
            ],
        );
        let out = RulePackParser::new(p)
            .unwrap()
            .assess(Path::new("/unused"))
            .unwrap();
        assert!(out.is_empty()); // second gate (NOT allowlist) fails → suppressed
    }

    #[test]
    fn new_project_resolves_on_file_under_repo_root() {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repoA");
        std::fs::create_dir_all(repo.join(".gemini")).unwrap();
        std::fs::write(repo.join(".gemini/settings.json"), r#"{"sandbox": false}"#).unwrap();

        let mut pack = pack_with_one_rule(
            ".gemini/settings.json",
            "$.sandbox",
            Matcher::Equals {
                value: "false".into(),
            },
            AiGuardReason::SandboxDisabled,
        );
        pack.scope = RulePackScope::Project;
        pack.watched_paths = vec![".gemini/settings.json".into()];

        let p = RulePackParser::new_project(pack, repo.clone()).unwrap();
        assert_eq!(p.scope(), AiGuardScope::Project { path: repo.clone() });
        assert_eq!(p.rule_pack_id(), Some("test-pack"));
        assert_eq!(
            p.watched_paths(Path::new("/unused")),
            vec![repo.join(".gemini/settings.json")]
        );
        let out = p.assess(Path::new("/unused")).unwrap();
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], AiGuardReason::SandboxDisabled));
    }
}
