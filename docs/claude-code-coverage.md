# Claude Code coverage

This page was checked against the Claude Code settings reference on 2026-11-14, with Claude Code 2.1.323 installed, and lists each security-relevant key on that page as assessed, reported, or not read. Lodeline measures the posture these keys describe. It does not block anything and it does not change a Claude Code setting.

The key list comes from the settings index at https://code.claude.com/docs/en/settings-reference.md. Hook behavior comes from https://code.claude.com/docs/en/hooks.md, and precedence from https://code.claude.com/docs/en/settings.md. Keys that only change appearance, notifications, input handling, model choice, effort or telemetry display are left out of the table because they carry no security posture. A key that appears on the settings page after this date is not read until this page is updated.

## Statuses

- **Assessed.** The key changes the reasons of a Claude Code row, and so its score. A key read from a user file feeds the user row. A key read from a repository file feeds that repository's row.
- **Reported.** The key is copied into the row as a control, with its source file and value. A control moves no score.
- **Not read.** Nothing in Lodeline reads the key. A setting in it has no effect on a row.

## Files read

| File | Rows it feeds |
|---|---|
| `~/.claude/settings.json`, `~/.claude/settings.local.json` | User |
| `<repo>/.claude/settings.json`, `<repo>/.claude/settings.local.json`, and the `settings.local.json` at the repository root | Project |
| `~/.claude.json` (user and local MCP servers), `<repo>/.mcp.json` | User, Project |
| `managed-settings.json`, `managed-settings.d/*.json`, `managed-mcp.json` in the managed folder | User and Project (see below) |
| `CLAUDE.md`, `loop.md`, skill and subagent frontmatter hooks | User, Project |
| `AGENTS.md` | Project |
| `scheduled-tasks/` | User |

The managed folder is `/Library/Application Support/ClaudeCode` on macOS, `C:\Program Files\ClaudeCode` on Windows and `/etc/claude-code` elsewhere. The macOS property list, the Windows registry and server-managed settings are not read. By default Claude Code applies only the highest-priority managed source, so on a host that has one of those, the managed files may not be in force. A reason read from a managed file carries the label `(managed file)`.

When `lodeline scan` runs in the home folder, the home's `.claude/settings.json` is read as a project file, so the project-only keys are reported from it too.

`CLAUDE_CONFIG_DIR` is honored for the user row. Settings passed with `--settings` are runtime state and are not read.

## Assessed

| Key | Read from | Effect |
|---|---|---|
| `hooks` | user, project, managed | Any hook event with at least one entry gives `no_sandbox` (executor `host_shell`) once per row. The handler types are in the next table. |
| `hooks[].matcher` | user, project, managed | An empty, `*` or `.*` matcher gives `broad_matcher`, unless every handler in the group has an `if` rule that narrows it. |
| `hooks[].hooks[].if` | user, project, managed | A handler whose `if` rule names one tool with a non-wildcard argument narrows its group. |
| `disableAllHooks` | user, project, managed | `true` drops the hook reasons and the `statusLine`, `subagentStatusLine` and `fileSuggestion` reasons of the files below it. Only a managed `true` drops managed hooks. |
| `allowedHttpHookUrls` | user, project, managed | The lists merge. An `http` hook whose URL no pattern can match, or any `http` hook when the list is empty, gives no `hook_forwards_tool_calls`. A pattern the documentation leaves open keeps the hook reported. |
| `permissions.allow` | user, project, managed | A rule that is `*:*`, ends in `:*`, has a wildcard argument (`Bash(*)`, `Bash(.*)`, `Bash(*:*)`), or names every tool of one MCP server (`mcp__github__*`) gives `permissions_allow_broad`. A narrower rule such as `Bash(rm:*)` does not. |
| `permissions.deny` | user, project, managed | A file with a `permissions` object and no `deny` key, or an empty `deny` list, gives `permissions_deny_empty`. A file with no `permissions` object gives it only when its `hooks` object is not empty. A `deny` value that is not a list gives nothing. The user row combines the user and managed lists. A project row reads the project files only. |
| `permissions.defaultMode` | user, project, managed | `auto`, `bypassPermissions` and `acceptEdits` give `auto_approval_enabled`. `default`, `plan` and `dontAsk` do not. `auto` and `bypassPermissions` from a project or local file are ignored, as Claude Code ignores them. With no effective value in the user row, the row assumes the built-in `auto` of Claude Code 2.1.283 and later. |
| `autoMode` | user, managed | Only `soft_deny` and `hard_deny`. A list without the `$defaults` entry gives `auto_mode_defaults_dropped`, and only when the session starts in `auto`. A project or local `autoMode` is not read, because Claude Code ignores it. |
| `disableAutoMode`, `permissions.disableAutoMode` | user, managed | The value `disable` turns off the `auto` start mode in the result. |
| `mcpServers` | user, project, managed | A remote URL gives `mcp_server_remote`, `trust: true` gives `trusted_mcp_server`, a `command` gives `mcp_server_local_command` and `no_sandbox`, and a shell launcher or transient path gives `mcp_server_suspicious_launcher`. Servers come from settings, `~/.claude.json`, `.mcp.json` and `managed-mcp.json`. |
| `managedMcpServers` | managed | The entries Claude Code loads are scored as `mcpServers` are. An entry it drops is not. |
| `deniedMcpServers` | user, managed | Only a managed server a deny entry matches is dropped. A user or project server a deny entry matches is still scored. |
| `disabledMcpServers` | `~/.claude.json` | A local server of a project is dropped when that project's `disabledMcpServers` lists it. A project folder that no longer exists drops its servers too. |
| `enableAllProjectMcpServers` | user, project | `true` gives `project_mcp_auto_enabled`. A project row needs a `.mcp.json` with servers. |
| `enabledMcpjsonServers` | project | A non-empty list gives `project_mcp_auto_enabled` when `.mcp.json` has servers. |
| `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `gcpAuthRefresh`, `otelHeadersHelper` | project | A non-empty command gives `project_settings_helper_command` with the key name and never the command. A user file's helper is not read. |
| `statusLine`, `subagentStatusLine`, `fileSuggestion` | project | A non-empty `command` gives `project_settings_ui_command`, unless `disableAllHooks` is on. A user file's command is not read. The settings index and the pages checked do not list `subagentStatusLine`. |
| `env` | project | A redirect (`ANTHROPIC_BASE_URL` and the Bedrock, Vertex and Foundry variants, `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`), a code-loading variable (`NODE_OPTIONS`, `BASH_ENV`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`) or a TLS weakening (`NODE_EXTRA_CA_CERTS`, or `NODE_TLS_REJECT_UNAUTHORIZED` set to `0`) gives `project_settings_env_override`. A loopback destination is not reported. Names match without case, and an empty value is ignored. Other variables are ignored. |
| `enabledPlugins` | project | Plugins set to `true` give one `project_settings_plugin_enabled`. |
| `extraKnownMarketplaces`, `additionalMarketplaces` | project | Each marketplace gives `project_settings_marketplace` with its source kind and host. The settings index does not list `additionalMarketplaces`. |

### Hook handler types

| `type` | Effect |
|---|---|
| `command` (or no `type`) | The command is classified. A destructive inline command gives `destructive_in_inline_command`. A script is read and scanned, and one that cannot be read gives `external_script_unscanned`. |
| `http` | A non-loopback URL that the allow list admits gives `hook_forwards_tool_calls` with the host. A loopback URL gives nothing. |
| `mcp_tool` | Gives `hook_forwards_tool_calls` with destination `mcp:<server>`. |
| `prompt` | Counts toward `no_sandbox` only. The payload goes to the model already in use. |
| `agent` | Counts toward `no_sandbox` only, for the same reason. |

A `PermissionRequest` hook also gives `standing_command_approval`, because it answers the permission prompt.

A hook command that names a script by a relative path is read from the project root when the hook is in a project's `.claude/settings.json` or `.claude/settings.local.json`, or in a skill or subagent of that project. Claude Code runs a hook in the current directory (`CLAUDE_PROJECT_DIR` is the project root where the session started), so a script that a session reaches after a `cd` can differ from the one read. A relative script in a user or managed hook gives `external_script_unscanned`, because no single folder is right for it, and the agent never reads a file from its own working directory. An absolute path, a `~` or `$HOME` path and a path in quotes are read as written. The first word of the command may be in matching quotes, as an operand of `sh` or `bash` may be.

## Reported

| Key | Read from | Control value |
|---|---|---|
| `allowedHttpHookUrls` | user files | The number of patterns in the merged list. Never a pattern. |
| `permissions.blockReadsOutsideWorkingDirectories` | user, project, managed | `true`, when set to `true`. |
| `permissions.blockWritesOutsideWorkingDirectories` | user, project, managed | `true`, when set to `true`. |
| `disableAutoMode`, `permissions.disableAutoMode` | managed | `disable`. |
| The `permissions` key that disables `bypassPermissions` mode (named in the settings index) | managed | `disable`. |
| `allowManagedPermissionRulesOnly` | managed | `true`. |
| `allowManagedHooksOnly` | managed | `true`. The assessment still scores user and project hooks. |
| `allowManagedMcpServersOnly` | managed | `true`. |
| `disableSideloadFlags` | managed | `true`. |
| `disableSkillShellExecution` | managed | `true`. |
| `strictPluginOnlyCustomization` | managed | `true`. Claude Code also accepts a list of `skills`, `agents`, `hooks` and `mcp`. The list form gives no control. |
| `sandbox.enabled` | managed | `true`. |
| `sandbox.allowUnsandboxedCommands` | managed | `false`, and only when `sandbox.enabled` is `true`. |
| `sandbox.network.allowManagedDomainsOnly` | managed | `true`, and only when `sandbox.enabled` is `true`. |
| `sandbox.filesystem.allowManagedReadPathsOnly` | managed | `true`, and only when `sandbox.enabled` is `true`. |

A control states what a local file says. It does not state what Claude Code enforces, because cloud policy, device policy and a running session are not visible to the agent.

## Not read

| Key | Reason |
|---|---|
| `permissions.ask`, `permissions.additionalDirectories` | No reason kind scores them. |
| `permissions.denyInsteadOfPrompting`, `skipDangerousModePermissionPrompt`, `skipAutoPermissionPrompt` | Prompt behavior of a session. No reason kind scores it. |
| `autoMode.classifyAllShell`, `useAutoModeDuringPlan` | Classifier tuning. Only `soft_deny` and `hard_deny` are read. |
| The `permissions` key that disables `bypassPermissions` mode, `sandbox.enabled`, `sandbox.allowUnsandboxedCommands` | In a user or project file. Only the managed copy is reported. |
| `sandbox`, `sandbox.allowAppleEvents`, `sandbox.allowNestedUserNamespaces`, `sandbox.autoAllowBashIfSandboxed`, `sandbox.bwrapPath`, `sandbox.credentials`, `sandbox.credentials.allowPlaintextInject`, `sandbox.credentials.awsPairs`, `sandbox.credentials.envVars`, `sandbox.credentials.files`, `sandbox.credentials.sigv4`, `sandbox.enableWeakerNestedSandbox`, `sandbox.enableWeakerNetworkIsolation`, `sandbox.excludedCommands`, `sandbox.failIfUnavailable`, `sandbox.filesystem`, `sandbox.filesystem.allowRead`, `sandbox.filesystem.allowWrite`, `sandbox.filesystem.denyRead`, `sandbox.filesystem.denyWrite`, `sandbox.filesystem.disabled`, `sandbox.ignoreViolations`, `sandbox.network`, `sandbox.network.allowAllUnixSockets`, `sandbox.network.allowedDomains`, `sandbox.network.allowLocalBinding`, `sandbox.network.allowMachLookup`, `sandbox.network.allowUnixSockets`, `sandbox.network.deniedDomains`, `sandbox.network.httpProxyPort`, `sandbox.network.socksProxyPort`, `sandbox.network.strictAllowlist`, `sandbox.network.tlsTerminate`, `sandbox.ripgrep`, `sandbox.socatPath` | Sandbox tuning. Lodeline does not model what a sandbox profile lets through, and a hook or MCP command is scored as running outside it. |
| `httpHookAllowedEnvVars` | Limits which variables an `http` hook may put in headers. The headers are not read. |
| `allowedMcpServers`, `disabledMcpjsonServers` | An allow list and a project reject list. The assessment scores every server it finds and does not subtract these. |
| `allowAllClaudeAiMcps`, `allowClaudeInChromeWithManagedMcp`, `disableClaudeAiConnectors` | Servers Claude Code fetches or ships itself are not in a file Lodeline reads. |
| `blockedMarketplaces`, `strictKnownMarketplaces`, `pluginSuggestionMarketplaces`, `disableCommandPluginSources`, `pluginTrustMessage` | Marketplace policy. Only the marketplaces a project registers are read, and a marketplace's `headersHelper` command is not. |
| `allowedChannelPlugins`, `channelsEnabled`, `pluginConfigs`, `appendPlugins`, `prependPlugins`, `syncClaudeAiPlugins`, `syncClaudeAiSkills`, `skillOverrides`, `disableBundledSkills` | Plugin and skill loading. Only a project's `enabledPlugins` is read. |
| `strictPluginOnlyCustomization.agents`, `strictPluginOnlyCustomization.hooks`, `strictPluginOnlyCustomization.mcp`, `strictPluginOnlyCustomization.skills` | Entries of the list form, which the settings index lists as sub-keys. Only the value `true` is reported. |
| `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `gcpAuthRefresh`, `otelHeadersHelper`, `statusLine`, `subagentStatusLine`, `fileSuggestion`, `env`, `enabledPlugins`, `extraKnownMarketplaces` | In a user or managed file. Read in project files only, because a repository can plant them for a person who clones it. |
| `forceLoginMethod`, `forceLoginOrgUUID`, `forceLoginGatewayUrl`, `allowedProviders`, `gatewayInternalNetworks` | Login and provider policy. No reason kind scores it. |
| `availableModels`, `availableModelsMatch`, `deniedModels`, `enforceAvailableModels`, `modelOverrides`, `modelPicker`, `modelPricing` | Model policy. No reason kind scores it. |
| `forceRemoteSettingsRefresh`, `managedSourcesBehavior`, `parentSettingsBehavior`, `policyHelper`, `policyHelper.path`, `policyHelper.refreshIntervalMs`, `policyHelper.timeoutMs`, `requiredMinimumVersion`, `requiredMaximumVersion`, `minimumVersion`, `wslInheritsWindowsSettings`, `claudeMd`, `processWrapper` | Managed delivery and enforcement. A helper executable's output is not run by Lodeline. |
| `remoteControlAtStartup`, `disableRemoteControl`, `crossSessionInbound`, `isolatePeerMachines`, `remote.defaultEnvironmentId`, `sshConfigs`, `sshHostAllowlist`, `sshHostCommands`, `disableDesktopLocalSessions` | Remote and cross-machine behavior. No reason kind scores it. |
| `browserExternalPageTools`, `disableBrowserExternalNavigation`, `disableMobileSimulatorTools`, `disableRemotePreviewScripts` | Desktop app panes. The agent does not read the desktop app's policy. |
| `cleanupPeriodDays`, `desktopSessionCleanupPeriodDays`, `autoMemoryDirectory`, `autoMemoryEnabled`, `plansDirectory`, `fileCheckpointingEnabled`, `claudeMdExcludes`, `includeGitInstructions`, `skipWebFetchPreflight`, `disableDeepLinkRegistration`, `disableAgentView`, `disableWorkflows`, `enableWorkflows`, `enableArtifact`, `disableArtifact`, `agent`, `defaultShell`, `respondToBashCommands`, `worktree`, `worktree.baseRef`, `worktree.bgIsolation`, `worktree.location`, `worktree.sparsePaths`, `worktree.symlinkDirectories` | Data location, retention and session behavior. No reason kind scores it. |
| `disableSideloadFlags`, `disableSkillShellExecution`, `allowManagedPermissionRulesOnly`, `allowManagedHooksOnly`, `allowManagedMcpServersOnly` | In a user or project file. Only the managed copy is reported. |

## Limits

The managed readings are checked by unit tests only. The `allowedHttpHookUrls` list from a managed file and the two `block*OutsideWorkingDirectories` keys from a managed file cannot be exercised end to end without a file in the root-owned managed folder.

A project row cannot see `--settings`, a plugin's own hooks, or a file Claude Code loads after the agent last read the folder. A plugin's own hooks are not read.
