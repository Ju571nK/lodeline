# Codex coverage

This page says what Lodeline reads from Codex configuration and where its reading stops. It was checked on Codex 0.167.0. For each claim about profiles and about an inline `bearer_token`, the check ran `codex debug prompt-input`, which loads configuration and prints without contacting a service, against a scratch `CODEX_HOME` that held only the file under test. A claim marked "from source" comes from the `openai/codex` repository at `ee344ca9` (2026-11-15) and was not run on 0.167.0.

## Layers

Lodeline reads these Codex layers:

| Layer | Row | Read |
|---|---|---|
| `/etc/codex/config.toml` (on Windows, `%ProgramData%\OpenAI\Codex\config.toml`) | User | Yes, under the user layer. A user scalar wins, `mcp_servers` tables merge, and the hooks of both layers are assessed. |
| `config.toml`, `hooks.json` and `rules/` in `~/.codex` (or `CODEX_HOME`) | User | Yes. |
| `config.toml`, `hooks.json` and `rules/` in `<repo>/.codex/` | Project | Yes. |
| Hooks of an enabled plugin, in `plugins/cache/<marketplace>/<plugin>/<version>/` under `~/.codex` (or `CODEX_HOME`) | User | Yes. See "Plugin hooks" below. |
| The same files in `.codex/` folders below the repo root, such as `services/api/.codex/` | Project, with the repo's row | Yes. See below. |
| `${PWD}/config.toml` | None | No. The configuration page does not list it. From source, `discover_project_layers` reads `<folder>/.codex/` for each parent folder and no bare `config.toml`, although a comment in `codex-rs/config/src/loader/mod.rs` still lists `${PWD}/config.toml` and may be stale. This was not run. |
| Files passed with `--profile` | None | No. The flag is runtime state that a daemon cannot see. |
| macOS managed preferences | None | No. MDM delivers them, and no file on the host holds them. |
| Cloud-managed `config.toml` defaults | None | No. Codex fetches them for the signed-in workspace, and the agent cannot see them. |

Codex layers every `.codex/` from the project root down to the folder a session starts in, and the agent cannot know that folder. So the agent reads every `.codex/` folder below the repo root, and a hook in `services/web/.codex/` can be reported although a session at `services/api/` never runs it. This is an over-report, like the one for a modified hook below. A subfolder hook follows the repo's trust rule: it is reported only when the user config records a `trusted_hash` for it.

The walk below the repo root goes at most five folders deep and visits at most 2,000 folders. A layer past either limit is not read. It skips hidden folders, `node_modules`, `target` and `vendor`, follows no link, and does not enter a folder that has its own `.git` entry, because Codex takes a nested repository or a submodule as its own project. The agent finds the layers when it starts and when it reloads its policy. A `.codex/` folder created later is not watched until the next reload. A change to a file in a found layer re-assesses the repo.

Reading the subfolders can raise a repo score. A hook, MCP server or rule there is a new finding, and the same hook in several layers is one finding per layer. A repo whose only Codex files sit in a subfolder is found by the daemon, and `lodeline scan` run in a Git repository builds a Codex project row for it too. A `.codex/hooks.json` at the repo root, with or without a `.codex/config.toml` or an `AGENTS.md`, gives `lodeline scan` a Codex project row. A root or user `config.toml` that does not parse is a read error for its row. The error names the file, the line and the column, and never the text of the line. A subfolder `config.toml` that does not parse is skipped with no error and no finding.

Codex loads project `.codex/` layers only when the project is trusted, and skips them for a project marked untrusted. When the user config holds `[projects."<repo>"]` with `trust_level = "untrusted"` for the repo root, Lodeline reads no `.codex/` layer of that repo, the root or below it, and the repo's `AGENTS.md` is still scanned. A repo with no `projects` entry is still read: Codex asks for trust on launch, and one keypress activates the layers. The Codex configuration pages say this in general terms and do not list MCP servers among what an untrusted project skips, so Lodeline treats them like the other layers. This was not run on 0.167.0. Lodeline matches the repo root only, so an untrusted parent folder does not skip a repo below it.

The event scope separates user and project findings, but the system and user layers share the user event. A finding can name the file it came from in a `config_source` key, with the layer (`system`, `user` or `project`) and the absolute path of the file (contract section 14.18). The agent sets it where one file holds the setting:

- A hook finding names the `config.toml` or `hooks.json` that holds the hook, and the layer of that folder.
- A finding built from a merged setting names the highest layer whose own `config.toml` sets the key, which is the layer Codex takes the value from. This covers `approval_policy`, `approvals_reviewer`, `sandbox_mode`, `default_permissions` (only for the built-in `:danger-full-access`), the `sandbox_workspace_write` keys, `notify`, `openai_base_url`, a provider `base_url` and `shell_environment_policy.set`. The `auto_review` finding names the layer of `approvals_reviewer`.
- An MCP server or app finding names the highest layer that defines the server or app by name. The fields of one server can come from two layers, and the finding still names the highest one.
- A standing command approval or a broad prefix names the first `.rules` file that yields it. The user event reads the system layer, then the user layer, and a project row reads its own layer. The files of a folder go in name order.
- A finding about `AGENTS.md` names that file: the user layer for `AGENTS.override.md` or `AGENTS.md` in the Codex folder, the project layer for the repo's `AGENTS.md`.
- A project finding names the `.codex/config.toml` of its layer, and a finding from a subfolder layer names that subfolder's file. The `sandbox_workspace_write` keys of a project row are read from the project layer, so they name it.

A `sandbox_disabled` finding that comes from a named permission profile has no `config_source`. The profile resolves in the merged `[permissions]` table, which no one file holds. The built-in `:danger-full-access` profile does carry one, and names the layer that picks it. Other tools write no `config_source` yet.

The change detector includes the key, so a setting that moves to another layer sends a new event. The agent keeps its last reading in memory, so the first assessment after an upgrade is a boot assessment and sends no extra event.

## Profiles

Lodeline does not apply the legacy `profile = "<name>"` key or the `[profiles.<name>]` tables. Codex 0.167.0 stops when `config.toml` sets the key, with or without the table. The error reads: legacy `profile = "p"` config is no longer supported; use `--profile p` with `p.config.toml` instead. A `[profiles.<name>]` table without the key loads and has no effect. A profile table therefore never runs, and reporting it would report a setting Codex does not use. The release that removed the key is not known.

Files passed with `--profile`, such as `p.config.toml`, are not read. The flag is runtime state that a daemon cannot see.

## Approval policy

`approval_policy = "never"` as a plain value in the system, user or project config gives an auto-approval finding that weighs 4.0, a HIGH reading alone, as `bypassPermissions` does for Claude Code. `approvals_reviewer = "auto_review"` keeps 1.5. A config that also sets `sandbox_mode = "danger-full-access"` reads 7.0 where it read 5.0.

The granular `approval_policy` table is read on purpose. It only turns prompts into rejections, so it is not a finding by itself. The requirements allowlist still names `untrusted`.

## Hook scripts

A hook command that names a script by an absolute path, in matching quotes or not, is read and scanned. A script named by a relative path gives `external_script_unscanned`, and the agent never reads a file from its own working directory. Codex runs a hook from the session folder, which can be a subfolder of the repo, and its hooks page advises against a relative path for a repo-local hook, so no single folder is right for one.

## Hook trust

Lodeline reads hook trust from the trust state in the user config. A hook whose stored hash no longer matches is still reported as running. Codex is expected to skip such a hook, so Lodeline over-reports a modified hook. It does not compare the hash, because the input to that hash changes between Codex releases and a wrong mismatch would hide a hook that runs. The skip behaviour comes from the Codex source at rust-v0.164 and was not checked on 0.167.0.

The hash input is the part that moves. The `hook_hash` function in `codex-rs/hooks/src/engine/discovery.rs` hashes "a normalized, config-derived identity" of the handler, and a Codex test, `supported_events_retain_per_handler_additional_context_limit_and_hash_it`, shows that a new handler field changes the hash. Between 2026-08-03 and 2026-10-23 the file that holds the function had 17 commits, and in 6 of them the changed lines mention the hash, among them "Bind plugin hook approval to plugin contents" (#54619). This count is from source and was not checked on 0.167.0.

## Plugin hooks

Codex runs the hooks that an enabled, trusted plugin brings, with no `hooks.json` of the user's. Lodeline reads them from the Codex folder (`~/.codex` or `CODEX_HOME`) and scores them as it scores other Codex hooks, so no new finding kind exists for them. A finding names the plugin's hooks file, or its manifest for an inline hook, with the user layer. The rules below come from the Codex source at rust-v0.172.0 (`core-plugins/src/loader.rs` and `manifest.rs`, `hooks/src/engine/discovery.rs`, `plugin_trust.rs` and `plugin_fingerprint.rs`, `utils/plugins/src/plugin_namespace.rs`). They were not run against a live Codex, because that needs a plugin install. The declaration hash in particular is computed from the source and was not compared with a hash that Codex wrote. If it differs, a plugin hook is missed, never invented.

Which plugin and which files:

- A plugin counts when the config holds `[plugins."<name>@<marketplace>"]` that does not set `enabled = false`. A non-boolean `enabled` skips the plugin. The id follows the Codex grammar: ASCII letters, digits, `-` and `_`, and for the plugin name dots between non-empty segments, on every platform.
- Lodeline reads the `local` version folder under `plugins/cache/<marketplace>/<plugin>/` when it exists, and otherwise the highest version folder by semantic version, with a text comparison when a name is not one. This is how Codex picks the active version.
- The manifest is the first of `.codex-plugin/plugin.json`, `.claude-plugin/plugin.json` and `.cursor-plugin/plugin.json`. A plugin with no manifest, a manifest that does not parse, one whose `name`, `version`, `description`, `apps` or `keywords` has the wrong type, or a root `plugin.json` that names an Agent Plugins schema, adds nothing. Lodeline checks only the manifest fields that it reads, so a manifest that Codex would reject for another field, such as `interface`, can still be scored.
- A manifest `hooks` value that is a `./` path, a list of such paths, an inline object or a list of objects replaces the default `hooks/hooks.json`. A value Codex cannot use, such as `{"hooks":123}`, a list of bad paths or an empty list, means the default file. A path is first confined to the plugin folder by its text, and a path that leaves the folder is dropped. A named file that is absent is skipped without a warning. A file that does not parse or breaks the Codex hook types is skipped with a warning.

Trust, checked in this order for each handler:

- The `hooks.state` key is `<name>@<marketplace>:<file>:<event>:<group>:<handler>` in the user config. `<file>` is the resolved path below the plugin folder, with `/` separators, or `plugin.json#hooks[<index>]` for an inline block. Group and handler counts start at zero.
- The state needs a `trusted_hash` equal to the declaration hash. Lodeline computes it as Codex does: SHA-256 of the sorted JSON of the event name, the matcher for events that take one, and the normalized handler (default timeout, command for the platform). A handler that Codex skips has none: an invalid matcher, a `prompt` or `agent` handler, an empty command, an MCP handler on `SessionEnd`. A state with `enabled = false`, or a field of the wrong type, does not run.
- With a `trusted_content_hash`, it must equal the SHA-256 over the plugin folder that Codex computes. Without one, the approval is a legacy one: if the baseline file `.hook-trust/<hash>` in the Codex folder exists, its bytes must equal the current folder hash. If it does not exist, Codex creates it from the current hash on first use and runs the hook, so Lodeline scores the hook as running. A write failure on the Codex side, which would stop the hook, is not seen, so this case can over-report. The baseline file is read and never written. A folder that cannot be hashed means the hook does not run.
- When the system `requirements.toml` sets `allow_managed_hooks_only = true`, plugin hooks are skipped.

Limits:

- Nothing in a plugin folder is read before the user config holds a `hooks.state` row for that plugin. A manifest path is first confined to the plugin folder by its text, then its resolved path must lie under the Codex folder. A regular file that is reached through a folder link is read when the link resolves inside the Codex folder, and skipped with a warning when it resolves outside. A link at the file itself is refused with a warning, even when it points inside the Codex folder. In the folder hash, any link makes the hash fail, as in Codex. A link that changes between the check and the read is not caught.
- A version folder list over 1,000 entries skips the plugin, and a hooks file that a manifest names twice is read once. A manifest or hooks file is read only when it is a regular file of at most 1 MiB. The baseline file is read up to 256 bytes. The folder hash stops at 10,000 files, 20,000 entries or 256 MiB, with a warning, and the plugin's hooks then do not run.
- Only the Codex parser reads plugins. No watch target covers a plugin folder, and a policy reload does not read plugins. A change to a plugin file, such as its manifest or hooks file, does not itself trigger a rescore. It is seen at the next Codex assessment, which runs at agent start, at the periodic reading (every 24 hours), on `lodeline scan`, and when a watched Codex file such as `~/.codex/config.toml` changes. A change to the approval in the user config is seen as soon as that file's change triggers an assessment.
- The shared hook reader still classifies the command text as written. Codex replaces `${PLUGIN_ROOT}` and similar variables in a command before it runs, and Lodeline does not.

Not covered, and left out on purpose:

- Plugins that Codex installs from a remote catalog and records outside `config.toml`.
- Plugin policy that Codex applies: the `allows_plugin` check and the marketplace filters.
- Bundled plugin hooks that Codex trusts without a state row, and the session override that makes Codex run an untrusted hook for one invocation.
- Plugin enablement or approval from a layer or session flag that the agent cannot read. The agent ignores a shell `CODEX_HOME`, as for the rest of Codex; `lodeline scan` honors it.
- A plugin's MCP servers, skills and apps, and the scripts that a plugin hook command names.

## MCP credentials

Lodeline reports a credential that an MCP server in a Codex config stores as plain text. That is a static `http_headers` entry, as the CHANGELOG describes for the `mcp_server_static_credential` finding. The finding names the server and the header and never the value. Whether a header holds a credential is a judgment from its name. An empty value, or a value that only names a variable, is not reported, because Codex sends an `http_headers` value as literal text (from source, `codex-rs/rmcp-client/src/utils.rs`). Headers in `env_http_headers` name environment variables (Codex MCP docs, https://developers.openai.com/codex/mcp) and are not reported. On a stdio server, Codex refuses `http_headers` and does not load the config (from source, `mcp_types.rs` in the Codex repository), and the hint says to remove the entry. A server with `enabled = false` is skipped.

These keys are not findings. `bearer_token_env_var` names an environment variable, so the config holds no secret. `auth` takes a fixed set of values, such as `chatgpt`, and holds no secret either. An inline `bearer_token` is refused by Codex. On 0.167.0, a scratch `CODEX_HOME` with an MCP server that sets `bearer_token` made `codex debug prompt-input` stop with `bearer_token is not supported for streamable_http`, and the same server without that key loaded. Lodeline reads the file as TOML and does not report the key, because Codex does not run that server. `http_headers_helper` runs a local command, so Lodeline reads it. A non-blank value on a server that sets `url` and no `command` gives a `project_settings_helper_command` finding with the key `mcp_servers.<name>.http_headers_helper`, from the system, user and project layers. The finding does not record the command, because a helper can embed a credential. If the command text matches a destructive pattern, a `destructive_in_inline_command` finding is added with an empty snippet. Codex runs the command with `sh -c` the first time it sends an HTTP request to the server, and once more after a 401 or 403 from the same origin. It does not run the command for `codex mcp list` or `codex mcp get` (checked on 0.172.0 in a scratch home). Codex refuses to load a config where the key is blank, sits on a stdio server, or sits on a server in another environment, so those give no finding. These rules are from source at rust-v0.172.0, `config/src/mcp_types.rs` and `rmcp-client/src/http_headers.rs`, and from https://developers.openai.com/codex/mcp (read 2026-11-26).

## Remote control

The `allow_remote_control` constraint in the system `requirements.toml` is read. Set to false, it is one of the `configured` observations.

Whether a session is paired for remote control is not read. From source, the daemon keeps its settings in `app-server-daemon/settings.json` under `CODEX_HOME`, with a `remoteControlEnabled` key that records intent, and the pairing state is the `remote_control_enrollments` table of Codex's state database. Lodeline reads neither. The file shows what was asked for, not an active pairing, and the table is a database that no check here opened. The name and place of the state database were not checked. These paths and keys are from source on main and were not checked on 0.167.0.

## Import

The `/import` command of Codex copies Claude Code or Cursor setup, project files and recent chats into Codex configuration and local files. The Codex documentation at https://developers.openai.com/codex/cli/slash-commands describes it and does not list which Claude Code or Cursor settings become which Codex keys. A hook, MCP server or permission in Claude Code or Cursor configuration can therefore reach Codex through it. Lodeline scores the copy from Codex's own files, as it scores any other Codex setting, and does not read the import. The remediation hints do not mention `/import`.
