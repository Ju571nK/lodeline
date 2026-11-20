//! Pins the bytes of every known `AiTool`, `AiGuardBucket` and `AiGuardScope`.

use lodeline_core::event::{AiGuardBucket, AiGuardScope, AiTool};

const TOOLS: &[(AiTool, &str)] = &[
    (AiTool::ClaudeCode, r#""claude_code""#),
    (AiTool::Codex, r#""codex""#),
    (AiTool::ClaudeDesktop, r#""claude_desktop""#),
    (AiTool::ContinueDev, r#""continue_dev""#),
    (AiTool::Gemini, r#""gemini""#),
    (AiTool::Cursor, r#""cursor""#),
    (AiTool::Antigravity, r#""antigravity""#),
    (AiTool::Grok, r#""grok""#),
    (AiTool::Other, r#""other""#),
];

const BUCKETS: &[(AiGuardBucket, &str)] = &[
    (AiGuardBucket::Low, r#""low""#),
    (AiGuardBucket::Medium, r#""medium""#),
    (AiGuardBucket::High, r#""high""#),
    (AiGuardBucket::Critical, r#""critical""#),
];

#[test]
fn known_tools_keep_their_bytes() {
    for (tool, bytes) in TOOLS {
        assert_eq!(serde_json::to_string(tool).unwrap(), *bytes);
        assert_eq!(&serde_json::from_str::<AiTool>(bytes).unwrap(), tool);
    }
}

#[test]
fn known_buckets_keep_their_bytes() {
    for (bucket, bytes) in BUCKETS {
        assert_eq!(serde_json::to_string(bucket).unwrap(), *bytes);
        assert_eq!(
            &serde_json::from_str::<AiGuardBucket>(bytes).unwrap(),
            bucket
        );
    }
}

#[test]
fn known_scopes_keep_their_bytes() {
    let scopes = [
        (AiGuardScope::UserGlobal, r#"{"kind":"user_global"}"#),
        (
            AiGuardScope::Project { path: "/r".into() },
            r#"{"kind":"project","path":"/r"}"#,
        ),
        (
            AiGuardScope::Application {
                app: "claude_desktop".into(),
            },
            r#"{"kind":"application","app":"claude_desktop"}"#,
        ),
    ];
    for (scope, bytes) in scopes {
        assert_eq!(serde_json::to_string(&scope).unwrap(), bytes);
        assert_eq!(serde_json::from_str::<AiGuardScope>(bytes).unwrap(), scope);
    }
}

#[test]
fn unknown_tools_sort_after_every_known_tool_and_by_name() {
    let mut tools: Vec<AiTool> = vec![
        AiTool::Unknown("zeta".into()),
        AiTool::Other,
        AiTool::Unknown("alpha".into()),
        AiTool::ClaudeCode,
    ];
    tools.sort();
    assert_eq!(
        tools,
        [
            AiTool::ClaudeCode,
            AiTool::Other,
            AiTool::Unknown("alpha".into()),
            AiTool::Unknown("zeta".into()),
        ]
    );
    let known: Vec<&AiTool> = TOOLS.iter().map(|(t, _)| t).collect();
    let after = AiTool::Unknown(String::new());
    assert!(known.iter().all(|t| **t < after));
}
