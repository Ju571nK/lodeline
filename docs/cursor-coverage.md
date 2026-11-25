# Cursor coverage

This page says which Cursor hook files Lodeline reads, which it does not, and why. Lodeline measures posture. It does not block anything and it does not change a Cursor setting.

Checked on 2026-11-25 against Cursor's hooks page at https://cursor.com/docs/agent/hooks. The installed `cursor-agent` is 2026.11.22, and the one command run on it was `--version`. No Cursor Desktop build was available. The scope list and the entry shape come from that page and from the bundle reading in `docs/research/cursor-grok-hook-scopes-2026-11-03.md`.

## Files read

| File | Row it feeds | Read |
|---|---|---|
| `~/.cursor/hooks.json` | User | Yes |
| Enterprise `hooks.json`: `/Library/Application Support/Cursor/hooks.json` on macOS, `/etc/cursor/hooks.json` on Linux, `C:\ProgramData\Cursor\hooks.json` on Windows | User | Yes |
| `<project>/.cursor/hooks.json` | Project | Yes. Skipped when the project root is a home folder, because the user row reads that file. |
| `~/.cursor/mcp.json`, `<project>/.cursor/mcp.json` | User, Project | Yes |
| Team hooks set in the Cursor web dashboard | None | No |
| Plugin hooks | None | No |

Cursor runs the hooks of every scope and merges their answers, so each file is scored on its own.

## What a hook file contributes

A `command` hook (the default when `type` is missing) is checked like a Claude Code command hook: an inline destructive command, a hook script that holds one, and a script Lodeline cannot read are reported through the existing reason kinds. The event name does not matter. Lodeline scores a command under any event name, including events added after this page was written, such as `beforeSubmitPrompt`, `subagentStart` and `workspaceOpen`.

A `prompt` hook asks a model to judge a condition and runs no command on the host, so it adds no reason and no finding. Its text is not read as a command. A file that holds only `prompt` hooks is clean. Reporting that a decision is delegated to a model would need a new reason kind, which this release does not add.

A `hooks.json` that does not parse is skipped with a warning and does not hide the MCP findings beside it.

## Watch targets

The user row watches `~/.cursor/hooks.json`, `~/.cursor/hooks` and the enterprise file. A project row watches `<project>/.cursor/hooks.json` and `<project>/.cursor/hooks`. The daemon finds projects through the `cursor_workspaces` policy field. A change to a watched file scores that row again.

## What is not covered

**Team hooks.** The Cursor dashboard distributes them to members. Cursor keeps them in memory and in a managed folder under `~/.cursor`, and no file the user or the repository owns holds them, so Lodeline reads nothing for them.

**Cursor cloud agents.** They run on Cursor's servers, not on this host. They load project hooks and, on an enterprise plan, team and enterprise hooks, and they do not load `~/.cursor/hooks.json`. A Lodeline agent sees the files on its own host, so a posture score here says nothing about a cloud agent run. A hook in `~/.cursor/hooks.json` does not apply to cloud agents either.

**Runtime behavior.** The deny path was not run on an installed Cursor Desktop build. See `docs/grok-coverage.md` for what Lodeline relies on.
