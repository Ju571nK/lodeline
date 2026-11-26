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

Codex runs the hooks that an enabled, trusted plugin brings, with no `hooks.json` of the user's. Lodeline reads them and scores them as it scores other Codex hooks, so no new finding kind exists for them. A finding names the plugin's `hooks/hooks.json`, or its `.codex-plugin/plugin.json` for an inline hook, with the user layer. This comes from the Codex source at rust-v0.172.0 (`core-plugins/src/loader.rs`, `hooks/src/engine/discovery.rs`, `plugin_trust.rs`, `plugin_fingerprint.rs`) and was not run on the installed 0.172.0, because that would need a plugin install.

- A plugin counts when the config holds `[plugins."<name>@<marketplace>"]` that does not set `enabled = false`. A plugin that is absent or disabled adds nothing.
- Lodeline reads the `local` version folder when it exists, and otherwise the highest version folder by semantic version, with a text comparison when a name is not one. This is how Codex picks the active version.
- A manifest `hooks` value that is a path, a list of paths, an inline object or a list of objects replaces the default `hooks/hooks.json`. A file that does not parse is skipped with a warning. A plugin whose manifest does not parse adds nothing.
- A plugin hook runs only when the user config holds `[hooks.state."<name>@<marketplace>:<file>:<event>:<group>:<handler>"]` with a `trusted_hash`. For an inline hook the file part is `plugin.json#hooks[<index>]`. Lodeline also compares `trusted_content_hash` with a SHA-256 over the plugin folder, computed as Codex does, and treats a mismatch like a hook with no approval. The folder hash is checked against a hash computed outside Lodeline with the same input. The `trusted_hash` of the declaration is not compared, for the reason under "Hook trust". An approval with no `trusted_content_hash` is a legacy one, and Lodeline reads it as trusted, because Codex settles it against a baseline file that it creates on first use.
- The agent watches the `hooks/hooks.json` and `.codex-plugin/plugin.json` of every plugin folder, and the files that an enabled plugin's manifest names. An edit of another file in a plugin folder changes the folder hash but does not trigger a new reading until the next periodic one.
- Not read: a plugin's MCP servers, skills and apps, and the scripts that a plugin hook command names.

## MCP credentials

Lodeline reports a credential that an MCP server in a Codex config stores as plain text. That is a static `http_headers` entry, as the CHANGELOG describes for the `mcp_server_static_credential` finding. The finding names the server and the header and never the value. Whether a header holds a credential is a judgment from its name. An empty value, or a value that only names a variable, is not reported, because Codex sends an `http_headers` value as literal text (from source, `codex-rs/rmcp-client/src/utils.rs`). Headers in `env_http_headers` name environment variables (Codex MCP docs, https://developers.openai.com/codex/mcp) and are not reported. On a stdio server, Codex refuses `http_headers` and does not load the config (from source, `mcp_types.rs` in the Codex repository), and the hint says to remove the entry. A server with `enabled = false` is skipped.

These keys are not findings. `bearer_token_env_var` names an environment variable, so the config holds no secret. `auth` takes a fixed set of values, such as `chatgpt`, and holds no secret either. An inline `bearer_token` is refused by Codex. On 0.167.0, a scratch `CODEX_HOME` with an MCP server that sets `bearer_token` made `codex debug prompt-input` stop with `bearer_token is not supported for streamable_http`, and the same server without that key loaded. Lodeline reads the file as TOML and does not report the key, because Codex does not run that server. `http_headers_helper` runs a local command, so Lodeline reads it. A non-blank value on a server that sets `url` and no `command` gives a `project_settings_helper_command` finding with the key `mcp_servers.<name>.http_headers_helper`, from the system, user and project layers. The finding does not record the command, because a helper can embed a credential. If the command text matches a destructive pattern, a `destructive_in_inline_command` finding is added with an empty snippet. Codex runs the command with `sh -c` the first time it sends an HTTP request to the server, and once more after a 401 or 403 from the same origin. It does not run the command for `codex mcp list` or `codex mcp get` (checked on 0.172.0 in a scratch home). Codex refuses to load a config where the key is blank, sits on a stdio server, or sits on a server in another environment, so those give no finding. These rules are from source at rust-v0.172.0, `config/src/mcp_types.rs` and `rmcp-client/src/http_headers.rs`, and from https://developers.openai.com/codex/mcp (read 2026-11-26).

## Remote control

The `allow_remote_control` constraint in the system `requirements.toml` is read. Set to false, it is one of the `configured` observations.

Whether a session is paired for remote control is not read. From source, the daemon keeps its settings in `app-server-daemon/settings.json` under `CODEX_HOME`, with a `remoteControlEnabled` key that records intent, and the pairing state is the `remote_control_enrollments` table of Codex's state database. Lodeline reads neither. The file shows what was asked for, not an active pairing, and the table is a database that no check here opened. The name and place of the state database were not checked. These paths and keys are from source on main and were not checked on 0.167.0.

## Import

The `/import` command of Codex copies Claude Code or Cursor setup, project files and recent chats into Codex configuration and local files. The Codex documentation at https://developers.openai.com/codex/cli/slash-commands describes it and does not list which Claude Code or Cursor settings become which Codex keys. A hook, MCP server or permission in Claude Code or Cursor configuration can therefore reach Codex through it. Lodeline scores the copy from Codex's own files, as it scores any other Codex setting, and does not read the import. The remediation hints do not mention `/import`.
