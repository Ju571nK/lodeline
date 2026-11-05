// lodeline-core `src/event.rs` as released in v0.12.6 (commit 968cb54), with
// its comments and its two `#[cfg(test)]` modules removed. Do not edit: it
// stands for the event type that released servers decode with.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceKind {
    FileSystem,
    Agent,
    AgentHook,
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Subject {
    Path {
        value: PathBuf,
    },
    #[serde(rename = "self")]
    Self_,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeKind {
    Created,
    Modified,
    Removed,
    Renamed,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceQuality {
    Definitive,
    BestEffort,
    Delayed,
    Incomplete,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentDyingReason {
    Panic,
    UnrecoverableSinkError,
    Signal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySignatureInvalidReason {
    PubkeyUnknown,
    PubkeyInactive,
    SignatureInvalid,
    Expired,
    VersionRegression,
    ParseFailed,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AiTool {
    ClaudeCode,
    Codex,
    ClaudeDesktop,
    ContinueDev,
    Gemini,
    Cursor,
    Antigravity,
    Grok,
    Other,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AiGuardScope {
    UserGlobal,
    Project { path: PathBuf },
    Application { app: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AiGuardBucket {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AiGuardReason {
    DestructiveInInlineCommand {
        pattern: String,
        hook_event: String,
        snippet: String,
    },
    DestructiveInHookScript {
        pattern: String,
        hook_event: String,
        script_path: PathBuf,
        snippet: String,
        #[serde(default)]
        source_chain: Vec<PathBuf>,
    },
    ExternalScriptUnscanned {
        hook_event: String,
        script_path: PathBuf,
    },
    NoSandbox {
        executor: String,
    },
    BroadMatcher {
        hook_event: String,
        matcher: String,
    },
    PermissionsDenyEmpty,
    PermissionsAllowBroad {
        rule: String,
    },
    SandboxDisabled,
    McpServerRemote {
        server_name: String,
        url: String,
    },
    McpServerLocalCommand {
        server_name: String,
        command: String,
    },
    TrustedMcpServer {
        server_name: String,
    },
    AutoApprovalEnabled {
        mode: String,
    },
    McpServerSuspiciousLauncher {
        server_name: String,
        command: String,
        shape: LauncherShape,
        evidence: String,
    },
    ProjectMcpAutoEnabled {
        mechanism: String,
    },
    InstructionFileDirective {
        path: PathBuf,
        directive_kind: InstructionDirectiveKind,
        snippet: String,
    },
    UnattendedScheduledTask {
        name: String,
    },
    McpToolInstructionOverride {
        server: String,
        tool: String,
        pattern: String,
    },
    McpToolHiddenText {
        server: String,
        tool: String,
        text_kind: String,
    },
    McpToolNameShadow {
        tool: String,
        servers: Vec<String>,
    },
    McpToolSurfaceDrift {
        server: String,
        tool: String,
        baseline_hash: String,
        current_hash: String,
    },
    McpUnapprovedNewTool {
        server: String,
        tool: String,
        current_hash: String,
    },
    McpSchemaPrivilegeExpansion {
        server: String,
        tool: String,
    },
    McpReadOnlyHintContradiction {
        server: String,
        tool: String,
    },
    AutoModeDefaultsDropped {
        list: String,
    },
    HookForwardsToolCalls {
        hook_event: String,
        destination: String,
    },
    UnattendedLoopPrompt {
        source: String,
    },
    StandingCommandApproval {
        pattern: String,
    },
    McpToolsAutoApproved {
        server_name: String,
        tools: Vec<String>,
    },
    ProjectSettingsPluginEnabled {
        plugins: Vec<String>,
    },
    ProjectSettingsHelperCommand {
        key: String,
    },
    ProjectSettingsEnvOverride {
        variable: String,
        effect: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        destination: Option<String>,
    },
    ProjectSettingsUiCommand {
        key: String,
    },
    ProjectSettingsMarketplace {
        name: String,
        source: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstructionDirectiveKind {
    FetchPipe,
    Destructive,
    Obfuscation,
    OverrideMarker,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherShape {
    Shell,
    TransientPath,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HookInvocationEvidence {
    pub agent: AiTool,
    pub peer_uid: u32,
    pub agent_session_id: Option<String>,
    pub tool_use_id: Option<String>,
    pub action_kind: String,
    pub other_label: Option<String>,
    pub action_hash: String,
    pub action_preview: Option<String>,
    pub capture_level: String,
    pub capture_status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HookDecisionEvidence {
    pub agent: AiTool,
    pub peer_uid: u32,
    pub agent_session_id: Option<String>,
    pub tool_use_id: Option<String>,
    pub action_kind: String,
    pub action_hash: String,
    pub action_preview: Option<String>,
    pub decision: String,
    pub rule_id: Option<String>,
    pub deny_reason: Option<String>,
    pub enforcement_mode: String,
    pub capture_level: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HookConfigDriftEvidence {
    pub agent: AiTool,
    pub peer_uid: u32,
    pub drift_kind: String,
    pub settings_path: String,
    pub expected_command_hash: String,
    pub observed_command_hash: Option<String>,
    pub expected_matcher: Option<String>,
    pub observed_matcher: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PossibleHookActivitySilentEvidence {
    pub agent: AiTool,
    pub uid: Option<u32>,
    #[serde(with = "time::serde::rfc3339")]
    pub last_hook_seen_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_session_activity_at: Option<OffsetDateTime>,
    pub window_secs: u64,
    pub probe_kind: String,
    pub path_hash: Option<String>,
    pub probe_error: Option<String>,
    pub scan_truncated: bool,
    pub confidence: Confidence,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostMetaSnapshot {
    pub hostname: Option<String>,

    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub architecture: Option<String>,

    pub interfaces: Vec<NetworkInterface>,
    pub default_gateway_v4: Option<String>,
    pub default_gateway_v6: Option<String>,
    pub dns_servers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkInterface {
    pub name: String,
    pub mac: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    FileChange {
        change_kind: FileChangeKind,
        before_hash: Option<String>,
        after_hash: Option<String>,
        recheck_hash: Option<String>,
        rename_from: Option<PathBuf>,
        size_after: Option<u64>,
        evidence_quality: EvidenceQuality,
    },
    Heartbeat {
        uptime_s: u64,
        is_final: bool,
        channel_stall_events_total: u64,
        events_emitted_total: u64,
        events_by_kind: BTreeMap<String, u64>,
        hash_p50_ms: u32,
        hash_p99_ms: u32,
        watcher_backend: String,
        state_db_size_bytes: u64,
        #[serde(with = "time::serde::rfc3339::option")]
        last_log_rotation_ts: Option<OffsetDateTime>,
        last_applied_policy_version: i64,
        policy_expired_active: bool,
        jsonl_above_soft_floor: bool,
    },
    PermissionMissing {
        resource: String,
        platform_hint: String,
    },
    ChannelStall {
        channel: String,
        blocked_seconds_in_window: f32,
        block_events_in_window: u64,
        #[serde(with = "time::serde::rfc3339")]
        first_block_ts: OffsetDateTime,
    },
    WatcherDegraded {
        from: String,
        to: String,
        reason: String,
    },
    AgentDying {
        reason: AgentDyingReason,
        detail: String,
        task: Option<String>,
    },
    RateLimitExceeded {
        target_id: String,
        count_dropped_in_window: u64,
        common_path_prefix: PathBuf,
    },
    HostIdFingerprintDrift {
        prev_fingerprint: String,
        new_fingerprint: String,
    },
    AgentJsonlForceGc {
        total_bytes: u64,
        oldest_segment_age_s: u64,
        segments_deleted: u32,
        segments_skipped_past_sender: u32,
    },
    SenderSkippedSegment {
        count: u32,
        oldest_dropped_filename: String,
    },
    PolicySignatureInvalid {
        reason: PolicySignatureInvalidReason,
        signing_pubkey_id: String,
        policy_version_in_envelope: i64,
        last_applied_policy_version: i64,
    },
    PolicyReloaded {
        policy_version: i64,
    },
    RulePackBundleApplied {
        version: i64,
    },
    PolicyExpiredActive {
        policy_version: i64,
        #[serde(with = "time::serde::rfc3339")]
        valid_until: time::OffsetDateTime,
    },
    HostIdConflict {
        observed_status: u16,
    },
    AgentTooOld {
        observed_status: u16,
        agent_version: String,
    },
    CertExpired {
        #[serde(with = "time::serde::rfc3339")]
        cert_expires_at: time::OffsetDateTime,
    },
    TlsFailure {
        reason: String,
    },
    EventUnprocessableLocal {
        original_event_id: uuid::Uuid,
        server_reason: String,
    },
    ServerProtocolViolation {
        detail: String,
    },
    SenderLagCritical {
        lag_events: u64,
        lag_bytes: u64,
        oldest_unsent_age_s: u64,
    },
    AiGuardRiskAssessed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        controls: Option<Vec<AiGuardControl>>,
        tool: AiTool,
        scope: AiGuardScope,
        score: f32,
        bucket: AiGuardBucket,
        reasons: Vec<AiGuardReason>,
        is_reattestation: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_pack_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool_label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
    },
    AiGuardToggleDrift {
        tool: AiTool,
        scope: AiGuardScope,
        toggle: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_pack_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool_label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
    },
    HostMetaSnapshot {
        snapshot: HostMetaSnapshot,
        is_reattestation: bool,
    },
    HookInvocation(HookInvocationEvidence),
    HookDecision(HookDecisionEvidence),
    HookConfigDrift(HookConfigDriftEvidence),
    PossibleHookActivitySilent(PossibleHookActivitySilentEvidence),
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AiGuardControl {
    pub id: String,
    pub source_path: PathBuf,
    pub setting: String,
    pub value: serde_json::Value,
}

pub const SCHEMA_VERSION: u32 = 1;

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Event {
    pub schema_version: u32,
    pub event_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub host_id: String,
    pub agent_version: String,
    pub severity: Severity,
    pub source: SourceKind,
    pub subject: Subject,
    pub evidence: Evidence,
    pub target_id: Option<String>,
}

impl Event {
    pub fn new_file_change(
        ts: OffsetDateTime,
        host_id: impl Into<String>,
        path: PathBuf,
        evidence: Evidence,
        target_id: Option<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7(),
            ts,
            host_id: host_id.into(),
            agent_version: AGENT_VERSION.to_string(),
            severity: Severity::Warn,
            source: SourceKind::FileSystem,
            subject: Subject::Path { value: path },
            evidence,
            target_id,
        }
    }
}
