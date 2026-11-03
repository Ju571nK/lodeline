# Cursor and Grok hook scopes (#203)

Date: 2026-11-03
Scope: AI Guard scanner (`lodeline scan` and the daemon)

This record follows the compatibility gate in
[generative-ai-compatibility-2026-08-16.md](generative-ai-compatibility-2026-08-16.md).
It lists the hook and MCP files each product reads, the evidence for each, and
what Lodeline now scores.

## Versions

| Product | Version | How it was examined |
| --- | --- | --- |
| Cursor Agent CLI | 2026.10.22-27dcf5f (local install) | Read the installed JavaScript bundle. No session was started. |
| Cursor Desktop | Not installed | Not examined. |
| Grok Build | 0.2.32 (local install) | Read the bundled user guide and the binary strings. |
| Grok Build | 1.0.70 (current stable, disposable copy) | Ran `grok inspect --json` with an isolated `HOME` and `GROK_HOME`. No prompt was sent. |

## Cursor

| Scope | Path | Precedence | Source | Verified by |
| --- | --- | --- | --- | --- |
| Enterprise | macOS `/Library/Application Support/Cursor/hooks.json`, Linux `/etc/cursor/hooks.json`, Windows `C:\ProgramData\Cursor\hooks.json` | All layers run | Bundle (`hooks` loader) and [docs](https://cursor.com/docs/hooks) | Bundle reading. The Windows path is hardcoded, not read from `%ProgramData%`. |
| Team | Dashboard state. The CLI writes scripts to `~/.cursor/managed/team_<id>/hooks/` and keeps the event map in memory. The worker reads `~/.cursor/managed/active-team-hooks/hooks.json`. | All layers run | Bundle (`team-hooks-sync`) and docs | Bundle reading. Not scored. |
| User | `~/.cursor/hooks.json` | All layers run | Bundle and docs | Bundle reading |
| Project | `<workspace>/.cursor/hooks.json` | All layers run | Bundle and docs | Bundle reading. The CLI loads it by default (`loadProjectHooks` defaults to true and no caller passes false). The docs say it needs a trusted workspace. |
| Claude compatibility | `~/.claude/settings.json`, `<workspace>/.claude/settings.json`, `<workspace>/.claude/settings.local.json` | Run after the Cursor files. A command that a Cursor file already registers is dropped. | Bundle | Bundle reading |

Every layer runs, and the verdicts merge as deny over ask over allow
(`executeAllAndMerge`). No layer replaces another. The documented order
(Enterprise, Team, Project, User) affects only fields where the last answer
wins.

Entry shape: `{"version": 1, "hooks": {<event>: [<entry>]}}`. An entry has
`type` (`command`, the default, or `prompt`), `command` or `prompt`, and the
optional `matcher`, `timeout`, `loop_limit`, `failClosed` and `model`. The
file is parsed as JSONC.

A `prompt` hook that passes returns `{"permission": "allow"}` on a permission
event. In the CLI shell path only `deny` and `ask` change the call, so an
allow approves nothing (local bundle). This matches forum reports that only
`deny` is enforced.

Cloud agents run project, team and enterprise command hooks. They do not run
user hooks, prompt hooks or MCP hooks (docs only).

## Grok Build

The local 0.2.32 build and current 1.0.70 disagree on trust:

| Scope | Path | 0.2.32 (bundled guide) | 1.0.70 (measured) |
| --- | --- | --- | --- |
| User hook files | `~/.grok/hooks/*.json` | Always trusted | Loaded only in a trusted folder. Home, filesystem roots and headless runs count as trusted. |
| User config hooks | `[hooks]` in `~/.grok/config.toml`, Codex-shaped | Not documented | Loaded (with an "unrecognized config key" warning) |
| Project hook files | `<repo>/.grok/hooks/*.json` | Trust through `~/.grok/trusted-hook-projects` | Loaded only in a trusted folder (`~/.grok/trusted_folders.toml`) |
| Project config hooks | `[hooks]` in `<repo>/.grok/config.toml` | Not documented | Not loaded |
| MCP | `[mcp_servers.<name>]` in `~/.grok/config.toml` and `<repo>/.grok/config.toml` | Documented | Loaded. A server with `enabled = false` is dropped. |
| Organization | `managed_config.toml` (`$GROK_HOME`, `/etc/grok`), `requirements.toml` | Not present | Documented in 1.0.70. Not measured. |
| Cross-tool | `~/.claude/settings.json`, `.claude/settings*.json`, `~/.cursor/hooks.json`, `.cursor/hooks.json`, `~/.claude.json`, `~/.cursor/mcp.json`, `.mcp.json` | Documented | `.cursor/hooks.json` matcher groups load. Cursor's flat entries do not run in 1.0.70. |

The inspect runs used `GROK_FOLDER_TRUST=0` to load every source. The trust
store format of 1.0.70 was not confirmed, and a repository under `/tmp` loads
no project hooks.

Hooks fail open on any error except an explicit deny (JSON `deny`, or exit
code 2), per both versions' guides.

## What Lodeline scores

| Product | Scope | Scored |
| --- | --- | --- |
| Cursor | User and enterprise `hooks.json` | Yes, in the user row |
| Cursor | Project `.cursor/hooks.json` | Yes, in the project row. It is also a discovery marker for `lodeline scan` and `cursor_workspaces`. |
| Cursor | Team hooks | No. They are remote state. |
| Grok | `~/.grok/hooks/*.json`, `~/.grok/config.toml` hooks and MCP | Yes, in the user row |
| Grok | `<repo>/.grok/hooks/*.json`, `<repo>/.grok/config.toml` MCP | Yes, in `lodeline scan` only. The daemon has no `grok_workspaces` policy key. |
| Grok | Organization files, trust store | No |

Command hooks reuse the existing hook reason kinds. A Cursor prompt hook adds
no reason.

## Not verified

- Cursor runtime behavior. No Cursor session was started, so the bundle
  reading is static.
- Whether Cursor 3.11 Desktop enforces only `deny`.
- Grok 1.0.70 folder-trust storage, and whether a declined trust prompt
  leaves `~/.grok/hooks/lodeline-hook.json` unloaded for that session.
- Grok `managed_config.toml` and `requirements.toml` hooks.
