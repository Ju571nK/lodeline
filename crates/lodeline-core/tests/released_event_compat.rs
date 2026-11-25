//! Pins what released servers do with evidence kinds added after them.

#[allow(dead_code)]
#[path = "fixtures/released/v0_12_6_event.rs"]
mod released;

use lodeline_core::event::{
    AiGuardBucket, AiGuardFinding, AiGuardReason, AiGuardScope, AiTool, Event, Evidence, Severity,
    SourceKind, Subject, UnknownReason, UnknownScope,
};
use lodeline_core::event::{ConfigLayer, ConfigSource};
use time::macros::datetime;

#[test]
fn released_server_accepts_ai_guard_assess_failed_as_unknown() {
    let ev = Event {
        schema_version: lodeline_core::event::SCHEMA_VERSION,
        event_id: uuid::Uuid::now_v7(),
        ts: datetime!(2026-11-03 10:00 UTC),
        host_id: "h".into(),
        agent_version: "0.13.0".into(),
        severity: Severity::Warn,
        source: SourceKind::Agent,
        subject: Subject::Self_,
        evidence: Evidence::AiGuardAssessFailed {
            tool: AiTool::ClaudeCode,
            scope: AiGuardScope::UserGlobal,
            user: Some("alice".into()),
            rule_pack_id: Some("acme-extended".into()),
            tool_label: Some("Acme CLI".into()),
            error_kind: "unreadable".into(),
            path: "/Users/alice/.claude/settings.json".into(),
            failing_since: datetime!(2026-11-03 10:00 UTC),
            last_assessed_ts: Some(datetime!(2026-11-02 09:00 UTC)),
            is_reattestation: false,
        },
        target_id: None,
    };
    let wire = serde_json::to_value(&ev).unwrap();
    assert_eq!(wire["evidence"]["kind"], "ai_guard_assess_failed");
    let old: released::Event = serde_json::from_value(wire).expect("v0.12.6 rejects the event");
    assert!(matches!(old.evidence, released::Evidence::Unknown));
    assert_eq!(old.event_id, ev.event_id);
}

#[test]
fn released_server_ignores_config_found_on_a_risk_reading() {
    let wire = serde_json::json!({
        "schema_version": 1, "event_id": uuid::Uuid::now_v7(), "ts": "2026-11-17T10:00:00Z",
        "host_id": "h", "agent_version": "0.18.0", "severity": "info",
        "source": {"kind": "agent"}, "subject": {"kind": "self"},
        "evidence": {"kind": "ai_guard_risk_assessed", "tool": "gemini",
            "scope": {"kind": "user_global"}, "score": 0.0, "bucket": "low",
            "reasons": [], "is_reattestation": false, "config_found": false}
    });
    let old: released::Event =
        serde_json::from_value(wire.clone()).expect("v0.12.6 rejects config_found");
    assert!(matches!(
        old.evidence,
        released::Evidence::AiGuardRiskAssessed { .. }
    ));
    let ev: Event = serde_json::from_value(wire).unwrap();
    let Evidence::AiGuardRiskAssessed { config_found, .. } = ev.evidence else {
        panic!("{:?}", ev.evidence)
    };
    assert_eq!(config_found, Some(false));
}

/// One sample per reason kind, fields in declaration order, so the bytes a
/// build writes can be compared with these strings.
const KNOWN_REASONS: &[&str] = &[
    r#"{"kind":"destructive_in_inline_command","pattern":"p","hook_event":"PreToolUse","snippet":"s"}"#,
    r#"{"kind":"destructive_in_hook_script","pattern":"p","hook_event":"PreToolUse","script_path":"/h/a.sh","snippet":"s","source_chain":["/h/a.sh"]}"#,
    r#"{"kind":"external_script_unscanned","hook_event":"PreToolUse","script_path":"/x.sh"}"#,
    r#"{"kind":"no_sandbox","executor":"host_shell"}"#,
    r#"{"kind":"broad_matcher","hook_event":"PreToolUse","matcher":".*"}"#,
    r#"{"kind":"permissions_deny_empty"}"#,
    r#"{"kind":"permissions_allow_broad","rule":"Bash(*)"}"#,
    r#"{"kind":"sandbox_disabled"}"#,
    r#"{"kind":"mcp_server_remote","server_name":"s","url":"https://example.com"}"#,
    r#"{"kind":"mcp_server_local_command","server_name":"s","command":"npx"}"#,
    r#"{"kind":"trusted_mcp_server","server_name":"s"}"#,
    r#"{"kind":"auto_approval_enabled","mode":"yolo"}"#,
    r#"{"kind":"mcp_server_suspicious_launcher","server_name":"s","command":"bash","shape":"shell","evidence":"bash -c"}"#,
    r#"{"kind":"project_mcp_auto_enabled","mechanism":"enableAllProjectMcpServers"}"#,
    r#"{"kind":"instruction_file_directive","path":"/r/AGENTS.md","directive_kind":"override_marker","snippet":"s"}"#,
    r#"{"kind":"unattended_scheduled_task","name":"n"}"#,
    r#"{"kind":"mcp_tool_instruction_override","server":"s","tool":"t","pattern":"p"}"#,
    r#"{"kind":"mcp_tool_hidden_text","server":"s","tool":"t","text_kind":"bidi"}"#,
    r#"{"kind":"mcp_tool_name_shadow","tool":"t","servers":["a","b"]}"#,
    r#"{"kind":"mcp_tool_surface_drift","server":"s","tool":"t","baseline_hash":"a","current_hash":"b"}"#,
    r#"{"kind":"mcp_unapproved_new_tool","server":"s","tool":"t","current_hash":"b"}"#,
    r#"{"kind":"mcp_schema_privilege_expansion","server":"s","tool":"t"}"#,
    r#"{"kind":"mcp_read_only_hint_contradiction","server":"s","tool":"t"}"#,
    r#"{"kind":"auto_mode_defaults_dropped","list":"soft_deny"}"#,
    r#"{"kind":"hook_forwards_tool_calls","hook_event":"PreToolUse","destination":"example.com"}"#,
    r#"{"kind":"unattended_loop_prompt","source":"user"}"#,
    r#"{"kind":"standing_command_approval","pattern":"git"}"#,
    r#"{"kind":"mcp_tools_auto_approved","server_name":"s","tools":["t"]}"#,
    r#"{"kind":"project_settings_plugin_enabled","plugins":["p@m"]}"#,
    r#"{"kind":"project_settings_helper_command","key":"apiKeyHelper"}"#,
    r#"{"kind":"project_settings_env_override","variable":"V","effect":"redirect","destination":"example.com"}"#,
    r#"{"kind":"project_settings_env_override","variable":"V","effect":"exec_code"}"#,
    r#"{"kind":"project_settings_ui_command","key":"statusLine"}"#,
    r#"{"kind":"project_settings_marketplace","name":"m","source":"github:o/r"}"#,
];

/// Kinds added after v0.12.6. That release rejects them, and a server from
/// v0.13.0 on keeps them as unknown reasons.
const NEWER_REASONS: &[&str] =
    &[r#"{"kind":"mcp_server_static_credential","server_name":"s","header_name":"Authorization"}"#];

/// Lists every known variant with its wire kind. The match has no wildcard, so
/// a new variant fails to compile here until it gets a kind and a sample.
macro_rules! wire_kinds {
    ($($variant:ident => $kind:literal,)*) => {
        const ALL_KINDS: &[&str] = &[$($kind),*];
        fn wire_kind(r: &AiGuardReason) -> Option<&'static str> {
            match r {
                $(AiGuardReason::$variant { .. } => Some($kind),)*
                AiGuardReason::Unknown(_) => None,
            }
        }
    };
}

wire_kinds! {
    DestructiveInInlineCommand => "destructive_in_inline_command",
    DestructiveInHookScript => "destructive_in_hook_script",
    ExternalScriptUnscanned => "external_script_unscanned",
    NoSandbox => "no_sandbox",
    BroadMatcher => "broad_matcher",
    PermissionsDenyEmpty => "permissions_deny_empty",
    PermissionsAllowBroad => "permissions_allow_broad",
    SandboxDisabled => "sandbox_disabled",
    McpServerRemote => "mcp_server_remote",
    McpServerLocalCommand => "mcp_server_local_command",
    TrustedMcpServer => "trusted_mcp_server",
    AutoApprovalEnabled => "auto_approval_enabled",
    McpServerSuspiciousLauncher => "mcp_server_suspicious_launcher",
    ProjectMcpAutoEnabled => "project_mcp_auto_enabled",
    InstructionFileDirective => "instruction_file_directive",
    UnattendedScheduledTask => "unattended_scheduled_task",
    McpToolInstructionOverride => "mcp_tool_instruction_override",
    McpToolHiddenText => "mcp_tool_hidden_text",
    McpToolNameShadow => "mcp_tool_name_shadow",
    McpToolSurfaceDrift => "mcp_tool_surface_drift",
    McpUnapprovedNewTool => "mcp_unapproved_new_tool",
    McpSchemaPrivilegeExpansion => "mcp_schema_privilege_expansion",
    McpReadOnlyHintContradiction => "mcp_read_only_hint_contradiction",
    AutoModeDefaultsDropped => "auto_mode_defaults_dropped",
    HookForwardsToolCalls => "hook_forwards_tool_calls",
    UnattendedLoopPrompt => "unattended_loop_prompt",
    StandingCommandApproval => "standing_command_approval",
    McpToolsAutoApproved => "mcp_tools_auto_approved",
    McpServerStaticCredential => "mcp_server_static_credential",
    ProjectSettingsPluginEnabled => "project_settings_plugin_enabled",
    ProjectSettingsHelperCommand => "project_settings_helper_command",
    ProjectSettingsEnvOverride => "project_settings_env_override",
    ProjectSettingsUiCommand => "project_settings_ui_command",
    ProjectSettingsMarketplace => "project_settings_marketplace",
}

#[test]
fn known_reasons_keep_their_released_bytes() {
    let mut sampled = std::collections::HashSet::new();
    for wire in KNOWN_REASONS {
        let old: released::AiGuardReason = serde_json::from_str(wire).expect(wire);
        assert_eq!(serde_json::to_string(&old).unwrap(), *wire);
        let new: AiGuardReason = serde_json::from_str(wire).expect(wire);
        let sent: serde_json::Value = serde_json::from_str(wire).unwrap();
        assert_eq!(wire_kind(&new), sent["kind"].as_str(), "{wire}");
        assert_eq!(serde_json::to_string(&new).unwrap(), *wire);
        sampled.insert(wire_kind(&new).unwrap());
    }
    for wire in NEWER_REASONS {
        assert!(serde_json::from_str::<released::AiGuardReason>(wire).is_err());
        let new: AiGuardReason = serde_json::from_str(wire).expect(wire);
        assert_eq!(serde_json::to_string(&new).unwrap(), *wire);
        sampled.insert(wire_kind(&new).unwrap());
    }
    for kind in ALL_KINDS {
        assert!(sampled.contains(kind), "no sample for {kind}");
    }
}

#[test]
fn unknown_reason_kind_keeps_the_event_and_the_object() {
    let wire = serde_json::json!({
        "schema_version": 1, "event_id": uuid::Uuid::now_v7(), "ts": "2026-11-03T10:00:00Z",
        "host_id": "h", "agent_version": "0.14.0", "severity": "warn",
        "source": {"kind": "agent"}, "subject": {"kind": "self"},
        "evidence": {"kind": "ai_guard_risk_assessed", "tool": "codex",
            "scope": {"kind": "user_global"}, "score": 3.0, "bucket": "medium",
            "reasons": [{"kind": "sandbox_disabled"},
                {"kind": "future_reason", "detail": {"n": 2}, "path": "/x"}],
            "is_reattestation": false}
    });
    assert!(
        serde_json::from_value::<released::Event>(wire.clone()).is_err(),
        "v0.12.6 rejects an event with an unknown reason kind"
    );
    let ev: Event = serde_json::from_value(wire.clone()).unwrap();
    let Evidence::AiGuardRiskAssessed { reasons, .. } = &ev.evidence else {
        panic!("{:?}", ev.evidence)
    };
    assert_eq!(reasons[0], AiGuardReason::SandboxDisabled);
    let AiGuardReason::Unknown(UnknownReason { kind, rest }) = &reasons[1].reason else {
        panic!("{:?}", reasons[1])
    };
    assert_eq!(kind, "future_reason");
    assert_eq!(
        serde_json::Value::Object(rest.clone()),
        serde_json::json!({"detail": {"n": 2}, "path": "/x"})
    );
    // Value equality: the same JSON value, though key order may differ.
    assert_eq!(
        serde_json::to_value(reasons).unwrap(),
        wire["evidence"]["reasons"]
    );
    for not_an_object in [r#""sandbox_disabled""#, "7", "null"] {
        assert!(serde_json::from_str::<AiGuardReason>(not_an_object).is_err());
    }
}

#[test]
fn a_reason_without_a_string_kind_is_rejected() {
    for bad in [
        "{}",
        r#"{"a":1}"#,
        r#"{"kind":null}"#,
        r#"{"kind":null,"a":1}"#,
        r#"{"kind":500}"#,
        // A buffered tag would read an integer as a variant index.
        r#"{"kind":0}"#,
        r#"{"kind":5}"#,
        r#"{"kind":7}"#,
        r#"{"kind":7,"x":1}"#,
        r#"{"kind":true}"#,
        r#"{"kind":{"x":1}}"#,
    ] {
        assert!(
            serde_json::from_str::<AiGuardReason>(bad).is_err(),
            "{bad} decoded"
        );
    }
}

fn risk_event(tool: &str, scope: serde_json::Value, bucket: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1, "event_id": uuid::Uuid::now_v7(), "ts": "2026-11-20T10:00:00Z",
        "host_id": "h", "agent_version": "0.19.0", "severity": "warn",
        "source": {"kind": "agent"}, "subject": {"kind": "self"},
        "evidence": {"kind": "ai_guard_risk_assessed", "tool": tool,
            "scope": scope, "score": 3.0, "bucket": bucket,
            "reasons": [], "is_reattestation": false}
    })
}

#[test]
fn unknown_tool_bucket_and_scope_kind_are_kept_and_written_back() {
    let scope = serde_json::json!({"kind": "workspace", "name": "w", "depth": 2});
    for (name, wire) in [
        (
            "tool",
            risk_event("newtool", serde_json::json!({"kind": "user_global"}), "low"),
        ),
        (
            "bucket",
            risk_event(
                "codex",
                serde_json::json!({"kind": "user_global"}),
                "severe",
            ),
        ),
        ("scope", risk_event("codex", scope, "low")),
    ] {
        assert!(
            serde_json::from_value::<released::Event>(wire.clone()).is_err(),
            "v0.12.6 rejects an unknown {name}"
        );
        let ev: Event = serde_json::from_value(wire.clone())
            .unwrap_or_else(|e| panic!("an unknown {name} is kept: {e}"));
        assert_eq!(
            serde_json::to_value(&ev).unwrap()["evidence"],
            wire["evidence"]
        );
    }
}

#[test]
fn unknown_names_land_in_the_unknown_variants() {
    let wire = risk_event(
        "newtool",
        serde_json::json!({"kind": "workspace", "name": "w"}),
        "severe",
    );
    let ev: Event = serde_json::from_value(wire).unwrap();
    let Evidence::AiGuardRiskAssessed {
        tool,
        scope,
        bucket,
        ..
    } = ev.evidence
    else {
        panic!("{:?}", ev.evidence)
    };
    assert_eq!(tool, AiTool::Unknown("newtool".into()));
    assert_eq!(bucket, AiGuardBucket::Unknown("severe".into()));
    let AiGuardScope::Unknown(UnknownScope { kind, rest }) = scope else {
        panic!("{scope:?}")
    };
    assert_eq!(kind, "workspace");
    assert_eq!(
        serde_json::Value::Object(rest),
        serde_json::json!({"name": "w"})
    );
}

#[test]
fn a_scope_without_a_string_kind_is_rejected() {
    for bad in [
        "{}",
        r#"{"kind":null}"#,
        r#"{"kind":0}"#,
        r#"{"kind":1,"x":1}"#,
        r#"{"kind":true}"#,
        r#"{"kind":{"x":1}}"#,
        r#""user_global""#,
        "7",
    ] {
        assert!(
            serde_json::from_str::<AiGuardScope>(bad).is_err(),
            "{bad} decoded"
        );
    }
}

#[test]
fn non_string_tool_and_bucket_are_rejected() {
    for bad in ["7", "null", r#"{"a":1}"#, "[\"codex\"]"] {
        assert!(serde_json::from_str::<AiTool>(bad).is_err(), "{bad}");
        assert!(serde_json::from_str::<AiGuardBucket>(bad).is_err(), "{bad}");
    }
}

#[test]
fn a_known_scope_kind_with_the_wrong_fields_is_rejected() {
    for bad in [
        r#"{"kind":"project"}"#,
        r#"{"kind":"project","path":5}"#,
        r#"{"kind":"application"}"#,
    ] {
        assert!(
            serde_json::from_str::<AiGuardScope>(bad).is_err(),
            "{bad} decoded"
        );
    }
}

#[test]
fn known_findings_without_config_source_keep_their_released_bytes() {
    for wire in KNOWN_REASONS.iter().chain(NEWER_REASONS) {
        let finding: AiGuardFinding = serde_json::from_str(wire).expect(wire);
        assert_eq!(finding.config_source, None, "{wire}");
        assert_eq!(serde_json::to_string(&finding).unwrap(), *wire);
    }
}

fn sourced_event(reasons: serde_json::Value) -> serde_json::Value {
    let mut wire = risk_event(
        "codex",
        serde_json::json!({"kind": "user_global"}),
        "medium",
    );
    wire["evidence"]["reasons"] = reasons;
    wire
}

#[test]
fn released_server_ignores_config_source_on_a_known_reason() {
    let source = serde_json::json!({"layer": "user", "file": "/Users/alice/.codex/config.toml"});
    let wire = sourced_event(serde_json::json!([
        {"kind": "sandbox_disabled", "config_source": source},
        {"kind": "no_sandbox", "executor": "host_shell"},
    ]));
    let old: released::Event =
        serde_json::from_value(wire.clone()).expect("v0.12.6 rejects config_source");
    let released::Evidence::AiGuardRiskAssessed { reasons, .. } = old.evidence else {
        panic!("{:?}", old.evidence)
    };
    assert_eq!(
        serde_json::to_string(&reasons[0]).unwrap(),
        r#"{"kind":"sandbox_disabled"}"#
    );
    let ev: Event = serde_json::from_value(wire.clone()).unwrap();
    let Evidence::AiGuardRiskAssessed { reasons, .. } = &ev.evidence else {
        panic!("{:?}", ev.evidence)
    };
    assert_eq!(reasons[0].reason, AiGuardReason::SandboxDisabled);
    assert_eq!(
        reasons[0].config_source,
        Some(ConfigSource {
            layer: ConfigLayer::User,
            file: "/Users/alice/.codex/config.toml".into()
        })
    );
    assert_eq!(reasons[1].config_source, None);
    assert_eq!(
        serde_json::to_string(&ev).unwrap(),
        serde_json::to_string(&serde_json::from_value::<Event>(wire).unwrap()).unwrap()
    );
}

#[test]
fn an_unknown_reason_kind_keeps_config_source_in_rest() {
    let wire = sourced_event(serde_json::json!([
        {"kind": "future_reason", "n": 2,
         "config_source": {"layer": "project", "file": "/r/.codex/config.toml"}},
    ]));
    let ev: Event = serde_json::from_value(wire.clone()).unwrap();
    let Evidence::AiGuardRiskAssessed { reasons, .. } = &ev.evidence else {
        panic!("{:?}", ev.evidence)
    };
    let AiGuardReason::Unknown(UnknownReason { rest, .. }) = &reasons[0].reason else {
        panic!("{:?}", reasons[0])
    };
    assert!(rest.contains_key("config_source"));
    assert_eq!(reasons[0].config_source, None);
    assert_eq!(
        serde_json::to_value(&ev).unwrap()["evidence"]["reasons"],
        wire["evidence"]["reasons"]
    );
}
