# Codex Surface Refresh (#200)

Checked 2026-11-06 against `openai/codex` tag `rust-v0.164.0`, the version
installed here (`codex --version` prints `codex-cli 0.164.0`; the latest
release is `rust-v0.166.0`), and the
[configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference).
Only static reads were run. No Codex command that writes config or trust
state was run. Earlier notes: `codex-config-layers-hooks-json-2026-10-27.md`
and `policy-controls-compatibility-2026-09-12.md`.

## Status of the issue's gaps

| Gap | Status | Source |
|---|---|---|
| 1. `approval_policy` table form | Already read without error. This change records why it is not a finding. `on-failure` is a serde alias of `on-request`. | `AskForApproval`, `GranularApprovalConfig` in `protocol/src/protocol.rs`; `render_decision_for_unmatched_command` in `core/src/exec_policy.rs` |
| 2. Layer stack | Partly read: system, user (`CODEX_HOME`), repository `.codex/` with `config.toml`, `hooks.json` and `rules/`. Nested `.codex/` folders and per-reason layer names are not read. | `config/src/loader/mod.rs` |
| 3. `rules/*.rules` | Already read as `standing_command_approval`. This change adds `permissions_allow_broad` for broad prefixes. | `BANNED_PREFIX_SUGGESTIONS` in `core/src/exec_policy.rs`; `execpolicy/src/parser.rs`, `rule.rs` |
| 4. Remote control | Still out of scope. `allow_remote_control` in `requirements.toml` is read as a control. | `config/src/config_requirements.rs` |
| 5. `requirements.toml` | Already read as controls. It also takes a `[features]` table (alias `feature_requirements`) that pins features. This change reads its `hooks` pin. | `config/src/config_requirements.rs`, `core/src/config/managed_features.rs` |
| 6. Lifecycle hooks | Already read per layer from `[hooks]` and `hooks.json`, with trust state. This change honors `features.hooks = false`. | `features/src/lib.rs`, `features/src/legacy.rs`, `hooks/src/engine/mod.rs` |
| 7. MCP per-server keys | `default_tools_approval_mode` and per-tool `approval_mode` are already read (`approve` only). Changed: Codex now refuses a plain `bearer_token`. | `config/src/mcp_types.rs` |
| 8. `/import` | Not done. No remediation text mentions it. | |

## Details

**`approval_policy`.** The values are `untrusted`, `on-request` (alias
`on-failure`), `never`, and `{ granular = { ... } }`. The reference page says
`on-failure` is deprecated and `untrusted` is unsupported. The 0.164.0 source
still accepts `untrusted`. The granular booleans are `sandbox_approval`,
`rules`, `mcp_elicitations`, and the optional `skill_approval` and
`request_permissions`. `true` lets that prompt reach the user and `false`
rejects the request instead. A command that no prompt covers gets the same
decision as under `on-request`, so a granular policy never approves more than
`on-request` does. Lodeline reports no granular shape, including all-false.
Codex sends granular escalations to the `auto_review` reviewer as it does for
`on-request`, and Lodeline already scores that combination.

**Layers.** In ascending precedence the loader reads packaged defaults,
macOS managed preferences, system (`/etc/codex/config.toml` or
`%ProgramData%\OpenAI\Codex\config.toml`), cloud bundle fragments, user
(`${CODEX_HOME}/config.toml`), a profile (`${CODEX_HOME}/<name>.config.toml`,
selected only with `--profile`), then `.codex/` folders from the project root
down to the working directory, then runtime flags. The project root is found
by root markers, `.git` by default. Codex skips a project `.codex/` that is
its own `CODEX_HOME`. Untrusted projects skip project config, hooks, and
rules. `PROJECT_LOCAL_CONFIG_DENYLIST` now lists `openai_base_url`,
`chatgpt_base_url`, `apps_mcp_product_sku`, `responses_api_metadata`,
`model_provider`, `model_providers`, `notify`, `profile`, `profiles`, two
realtime URLs, and `otel`. It still does not list `mcp_servers`, `hooks`, or
`approval_policy`.

**Rules.** `prefix_rule(pattern=[...], decision=...)` matches the first
argv words; a nested list is a set of alternatives at that position, and a
missing `decision` means `allow`. When every parsed command segment matches
an `allow` rule, Codex runs the command with no prompt and outside the
sandbox (the `Decision::Allow` arm of `ExecApprovalRequirement` in
`core/src/exec_policy.rs`). Codex will not suggest a standing approval for
the prefixes in `BANNED_PREFIX_SUGGESTIONS`: shells and their `-c` forms,
interpreters and their eval flags, `npm run`, `pnpm run`, `yarn run`,
`bun run`, `env`, `git`, `osascript`, `rm`, and `sudo`. Lodeline uses that
list as its definition of a broad prefix. A rule whose pattern equals an
entry, or is a shorter prefix of one, is reported as
`permissions_allow_broad`. First words compare as basenames without `.exe`,
and words compare case-insensitively, so `/usr/bin/python3` and `CMD.EXE /C`
match. The finding's `rule` is spelled from the list, never from the rules
file.

**Hooks feature.** `[features] hooks` (stable, on by default) replaced
`codex_hooks`, which is still read as an alias. Codex applies the keys in
sorted order, so when both are set `hooks` wins. With the feature off, Codex
drops every config and plugin hook and keeps only internal ones. A
`requirements.toml` `[features]` pin overrides the config value. Lodeline
reads the merged system, user, and project `features` table and the system
`requirements.toml` pin. MDM and cloud pins, profile files, and
`--enable`/`--disable` flags are not read.

**MCP.** `default_tools_approval_mode` takes `auto | prompt | writes |
approve`, and a per-tool `approval_mode` overrides it. Codex 0.164.0 rejects
a plain `bearer_token` for both stdio and streamable HTTP servers
(`throw_if_set` in `mcp_types.rs`), so a config that sets it does not load.
Only `bearer_token_env_var`, `http_headers`, `env_http_headers`, and
`http_headers_helper` remain. Lodeline does not report `writes` mode.

**Local install.** `~/.codex/` holds `config.toml`, `hooks.json`,
`rules/default.rules`, and the folders `app-server-control` and
`app-server-daemon`. The last two are candidates for remote-control state;
their contents were not read.

## Not covered

- `.codex/` folders below a repository root, which apply when Codex starts
  in that subfolder.
- A field naming the layer behind each reason. The event scope separates
  user and project findings, but system and user findings share one event.
- Profile files, `${PWD}/config.toml`, and remote-control state.
- MCP `writes` mode, `http_headers` with literal credentials, and `/import`.
