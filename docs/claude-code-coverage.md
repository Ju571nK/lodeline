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
| `~/.claude/settings.json` | User |
| `<repo>/.claude/settings.json`, `<repo>/.claude/settings.local.json`, and the `settings.local.json` at the repository root | Project |
| `~/.claude/settings.local.json` | Project, only for a project whose folder is the home folder |
| `~/.claude.json` (user and local MCP servers), `<repo>/.mcp.json` | User, Project |
| `managed-settings.json`, `managed-settings.d/*.json`, `managed-mcp.json` in the managed folder | User and Project (see below) |
| `CLAUDE.md`, `loop.md`, skill, subagent and command frontmatter hooks | User, Project |
| `AGENTS.md` | Project |
| `scheduled-tasks/` | User |

The managed folder is `/Library/Application Support/ClaudeCode` on macOS, `C:\Program Files\ClaudeCode` on Windows and `/etc/claude-code` elsewhere. The macOS property list, the Windows registry and server-managed settings are not read. By default Claude Code applies only the highest-priority managed source, so on a host that has one of those, the managed files may not be in force. A reason read from a managed file carries the label `(managed file)`.

When `lodeline scan` runs in the home folder, the home's `.claude/settings.json` is read as a project file, so the project-only keys are reported from it too.

`CLAUDE_CONFIG_DIR` is honored for the user row, which reads `settings.json` in that folder and no `settings.local.json`. Claude Code's user scope is `settings.json` only; a `~/.claude/settings.local.json` is the local file of a session started in the home folder, so it feeds only the project row of the home folder. Settings passed with `--settings` are runtime state and are not read.

A `CLAUDE_CONFIG_DIR` in the `env` block of a home's `~/.claude/settings.json` moves that home's user row to the folder the same way, for the scan and for the agent service, which does not watch that folder and so shows an edit there at its next full pass. The variable in the process environment wins over it. The value counts only as an absolute path: Claude Code resolves a relative path against the session's folder and takes `~` as a folder name, so a scan ignores both. A redirect inside the redirected folder is not followed.

A project row reads the hooks in skill (`.claude/skills/<name>/SKILL.md`), subagent (`.claude/agents/**/*.md`) and command (`.claude/commands/**/*.md`) frontmatter from these folders, which are the ones Claude Code loads for a session started in the row's folder:

- The row's own `.claude`.
- The `.claude` of each subfolder, down to eight levels. Hidden folders, `node_modules` and `target` are skipped.
- The `.claude` of each parent folder up to the repository root, or up to the worktree root in a linked worktree. Outside a git repository no parent folder is read. The home folder's `.claude` is the user scope, so the user row reads it and a project row does not.
- In a linked worktree whose root has no `.claude/skills` folder, the main checkout's `.claude/skills`. The same holds for `.claude/agents` and `.claude/commands`. Only a missing folder reads through: an empty one does not. Claude Code reads skills through from version 2.1.277, and the agent does not know the installed version, so it reads them through for every worktree.

So a skill, subagent or command at the repository root shows in the root's row and again in the row of each subfolder that has a row of its own, and a main checkout's skills show again in the row of a worktree. That is intended: each row is what a session started in its folder loads. A folder gets a row only when it has a project file of its own, such as `CLAUDE.md` or `.claude/settings.json`. When two subagents share a `name`, Claude Code uses the one nearest the start folder; Lodeline does not model this, so a hook in the subagent that is not used is still reported.

With the agent running, a change to a skill, subagent or command file in any of these project folders is assessed when it is written. The agent builds the list of folders to watch when it starts and on each policy reload, from the folders that exist then: the row's own `.claude`, the nested folders, and the parent and main checkout folders. It watches at most 64 of the parent and nested folders for each project, one limit shared by skills, subagents and commands, and logs a warning when it leaves some out. A folder created while the agent runs is not watched until the next policy reload or restart, so a skill added in a new subfolder is picked up at the next periodic assessment, which runs once a day. A change in an unwatched folder waits for it too.

Command files are read as skill files are. The skills page says a command file in `.claude/commands/` accepts the same frontmatter as a skill except `name` and `paths`, so its `hooks` field registers hooks for the rest of the session. A command in a subfolder is a namespaced command (`.claude/commands/ops/deploy.md` is `/ops:deploy`), so the whole folder tree is read, to eight levels and at most 1,000 files per folder kind. Lodeline replaces `${CLAUDE_SKILL_DIR}` only in a skill's hooks, not in a command's. Claude Code's pages name only the project command folder. Lodeline also reads `~/.claude/commands` for the user row by the same rule as user skills, and the default policy watches it, so a change to a user command file is assessed when it is written.

## Assessed

| Key | Read from | Effect |
|---|---|---|
| `hooks` | user, project, managed | Any hook event with at least one entry gives `no_sandbox` (executor `host_shell`) once per row. The handler types are in the next table. A `PreToolUse` group that holds the command `lodeline-hook install --agent claude-code` writes, an absolute path to `lodeline-hook` outside a temp folder and the project, made of letters, digits and `/ \ : . _ -` (spaces only inside double quotes), with the install arguments, gives neither `no_sandbox` nor `broad_matcher`. |
| `hooks[].matcher` | user, project, managed | An empty, `*` or `.*` matcher gives `broad_matcher`, unless every handler in the group has an `if` rule that narrows it. |
| `hooks[].hooks[].if` | user, project, managed | A handler whose `if` rule names one tool with a non-wildcard argument narrows its group. |
| `disableAllHooks` | user, project, managed | `true` drops the hook reasons and the `statusLine`, `subagentStatusLine` and `fileSuggestion` reasons of the files below it. Only a managed `true` drops managed hooks. |
| `allowedHttpHookUrls` | user, project, managed | The lists merge. An `http` hook whose URL no pattern can match, or any `http` hook when the list is empty, gives no `hook_forwards_tool_calls`. A pattern the documentation leaves open keeps the hook reported. |
| `permissions.allow` | user, project, managed | A rule that is `*:*`, ends in `:*`, has a wildcard argument (`Bash(*)`, `Bash(.*)`, `Bash(*:*)`), or names every tool of one MCP server (`mcp__github__*`) gives `permissions_allow_broad`. A narrower rule such as `Bash(rm:*)` does not. |
| `permissions.deny` | user, project, managed | A file with a `permissions` object and no `deny` key, or an empty `deny` list, gives `permissions_deny_empty`. A file with no `permissions` object gives it only when its `hooks` object is not empty. A `deny` value that is not a list gives nothing. The user row combines the user and managed lists. A project row reads the project files only. |
| `permissions.defaultMode` | user, project, managed | `auto`, `bypassPermissions` and `acceptEdits` give an auto-approval finding. It weighs 4.0 for `bypassPermissions` (a HIGH reading alone), 2.0 for `acceptEdits` and 1.5 for `auto`. `default`, `plan` and `dontAsk` do not. `auto` and `bypassPermissions` from a project or local file are ignored, as Claude Code ignores them. With no effective value in the user row, the row assumes the built-in `auto` of Claude Code 2.1.283 and later. |
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

A hook command that names a script by a relative path is read from the project root when the hook is in a project's `.claude/settings.json` or `.claude/settings.local.json`, or in a skill, subagent or command file of that project. Claude Code runs a hook in the current directory (`CLAUDE_PROJECT_DIR` is the project root where the session started), so a script that a session reaches after a `cd` can differ from the one read. A relative script in a user or managed hook gives `external_script_unscanned`, because no single folder is right for it, and the agent never reads a file from its own working directory. An absolute path, a `~` or `$HOME` path and a path in quotes are read as written. The first word of the command may be in matching quotes, as an operand of `sh` or `bash` may be.

In a project hook, `$CLAUDE_PROJECT_DIR` and `${CLAUDE_PROJECT_DIR}` at the start of the script path stand for the project root, as a relative path does, and the script is read from there. The shell form accepts each of them bare or in double quotes (`"$CLAUDE_PROJECT_DIR"/x.sh`, `"${CLAUDE_PROJECT_DIR}/x.sh"`). A hook with `args` runs with no shell, so only the unquoted `${CLAUDE_PROJECT_DIR}` form is read, and on Windows, where PowerShell rewrites only the braced placeholder, only the braced form. The same variable in a user or managed hook, and in a Cursor or Codex hook, is not expanded and gives `external_script_unscanned`, because the agent does not know which project that hook runs for. The page for the variable says the project root is "where the session started" and does not say which folder that is for a session started below the git root. Lodeline uses the root of the project row, the same folder as for a relative script. It cannot tell a desktop app worktree session, where the variable names the main checkout, so a hook script there can differ from the one read.

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
