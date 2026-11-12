# Claude Code Surface Refresh (#199)

Checked 2026-11-06 against the official docs and the locally installed Claude
Code 2.1.318 (`claude --version`). The local changelog copy ends at 2.1.318.
Only static file reads were run. No hook was executed, and no Claude Code
config file was changed.

Sources:

- [Permissions](https://code.claude.com/docs/en/permissions)
- [Settings](https://code.claude.com/docs/en/settings) and the
  [settings reference](https://code.claude.com/docs/en/settings-reference)
- [Hooks](https://code.claude.com/docs/en/hooks)
- [Auto mode config](https://code.claude.com/docs/en/auto-mode-config)
- [Scheduled tasks](https://code.claude.com/docs/en/scheduled-tasks) and
  [Desktop scheduled tasks](https://code.claude.com/docs/en/desktop-scheduled-tasks)
- [Skills](https://code.claude.com/docs/en/skills),
  [subagents](https://code.claude.com/docs/en/sub-agents) and
  [worktrees](https://code.claude.com/docs/en/worktrees)
- The Claude Code changelog, 2.1.310 to 2.1.318

## The seven gaps

| Gap | Status on 2026-11-06 | Where |
| --- | --- | --- |
| 1. `defaultMode` values | Still accurate. The docs list `default` (labeled Manual, alias `manual`), `acceptEdits`, `plan`, `auto`, `dontAsk` and `bypassPermissions`. Changed since July: with no `defaultMode`, interactive 2.1.283+ sessions start in `auto`, and `auto` and `bypassPermissions` take no effect from project or local files (`bypassPermissions` since 2.1.257). Already implemented. | #206, #402; `start_mode` in `parser/claude_code.rs` |
| 2. `autoMode` block | Still accurate. `environment`, `allow`, `soft_deny`, `hard_deny` and `classifyAllShell`; `"$defaults"` splices the built-in list in. The classifier reads `autoMode` from `~/.claude/settings.json`, managed settings and `--settings` only. Changed: a `classifyAllShell: true` in user settings wins over a managed `false`, and an `allow` list without `"$defaults"` no longer drops the built-in scheduled-task rule. The `$defaults` check is implemented. Matching prose `allow` entries against the built-in deny rules is not, because the rules are prose. | #206; `emit_auto_mode_reasons` |
| 3. Hook types and locations | Still accurate. Five handler types: `command`, `http`, `mcp_tool`, `prompt`, `agent`. Locations: the settings files, managed settings, plugin `hooks/hooks.json`, and skill and subagent frontmatter. Implemented: `http` to a non-loopback URL and `mcp_tool` report `hook_forwards_tool_calls`; frontmatter hooks are scored. Not read: `allowedHttpHookUrls`, under which Claude Code skips an `http` hook whose URL matches no pattern (`*` wildcard, arrays merge, an empty array blocks every `http` hook). | #206, #318 |
| 4. `loop.md` | Still accurate. `.claude/loop.md` wins over `~/.claude/loop.md`; content past 25,000 bytes is cut. Implemented for both scopes. New: with feature-flag fetching off, a CronCreate task asked to survive the session is stored in the project's `.claude/scheduled_tasks.json`, and the 2.1.318 binary's tool text names the same file for durable tasks; not read yet. Desktop tasks stay at `~/.claude/scheduled-tasks/<name>/SKILL.md`, under `CLAUDE_CONFIG_DIR` when set, which #191 covers. | #206; `emit_loop_prompt_reason` |
| 5. Enumeration | Changed, and implemented in this change. See the next section. | this change |
| 6. Hardening keys | Implemented as `configured` controls from the managed files. New since: `permissions.blockReadsOutsideWorkingDirectories` (2.1.257) and `permissions.blockWritesOutsideWorkingDirectories` (2.1.314), both honored as `true` from any scope; not in the control allowlist yet. | #207, #220; `claude_controls` |
| 7. Rule forms | Still accurate. Deny and ask rules match `Tool(param:value)` on a direct input field of a built-in tool; allow rules keep each tool's own specifier. Tool-name globs: `*` and `mcp__*` in deny and ask; in allow only after a literal `mcp__<server>__`. Settings `mcp__` rules with parentheses are skipped. Implemented. | #206; `is_broad_allow` |

## Gap 5 in detail

### The local settings file

- "If you start Claude Code in a subdirectory of a git repository, it reads
  and writes that file at the repository root and applies the approval across
  the whole repository. In a worktree, it uses the file at the main checkout's
  root." ([settings](https://code.claude.com/docs/en/settings))
- The file stays next to `.claude/settings.json` outside a git repository,
  when the root is the home directory, on Windows, and when the root or its
  `.git` or `.claude` is not owned by the user.
- Before v2.1.211 the file lived in the start directory. Claude Code still
  reads such a copy: the root's value wins a key both set, and permission
  rules from both apply.
- `.claude/settings.json` and hooks still load from the start directory only,
  with no parent fallback ([permissions](https://code.claude.com/docs/en/permissions)).
- `~/.claude/settings.local.json` is local scope, read only for sessions
  started in the home directory itself.

Lodeline now resolves the root from the start directory's `.git`: a `.git`
directory marks the root, and a `.git` file names a git dir whose `commondir`
leads to the main checkout's `.git`. A `.git` file without `commondir` is a
submodule, which is its own repository. This matches the layout `git worktree
add` writes, checked on a real worktree. The start directory's owner stands in
for the user, because the agent can run as another account. A worktree of a
bare repository keeps its own file.

### Nested skills

- Skill layout is one level: `<skills>/<name>/SKILL.md`. Nothing recurses
  inside `skills/`.
- "Nested" means `<subdir>/.claude/skills/<name>/SKILL.md` below the start
  directory. Such a skill loads "the first time Claude reads or edits a file in
  that subdirectory and stay[s] available for the rest of the session"
  ([skills](https://code.claude.com/docs/en/skills)).
- A session also loads `.claude/skills/` from each parent directory up to the
  repository root, or up to the worktree root in a linked worktree. Since
  2.1.277 a worktree with no `.claude/skills` at its root loads the main
  checkout's skills.
- Subagents in `.claude/agents/` are found by walking up from the working
  directory to the repository root, and are scanned recursively.

Lodeline now scores frontmatter hooks of nested skills below a discovered
repository. The walk goes at most 8 folders deep and reads at most 20,000
folders, skips hidden, `node_modules` and `target` folders, and does not follow
symlinked directories. Nested skills have their own 1,000-file budget.
Subagents in a subfolder's `.claude/agents/` are read the same way, under the same
folder bounds, with their own 1,000-file budget. Claude Code loads them for a
session started in that subfolder ("Project subagents are discovered by walking up
from the current working directory", read 2026-11-12), so a session at the root
does not load them, but the assessment reports them.

### Discovery

A repository is now discovered when its only Claude Code file is
`.claude/settings.local.json` or `.claude/loop.md`. `lodeline scan` uses the
same markers as the agent.

## Left for later

- `allowedHttpHookUrls`: drop `http` hooks it would skip, and report it as a
  control.
- `.claude/scheduled_tasks.json` as an unattended task source.
- Parent-directory skills for a start directory below the root, the worktree
  fallback to the main checkout's skills, and nested
  `.claude/settings.json` files.
- The user scope still merges `~/.claude/settings.local.json` into every
  session, which over-reports for sessions started elsewhere.
- `permissions.blockReadsOutsideWorkingDirectories` and
  `permissions.blockWritesOutsideWorkingDirectories` as controls.
- Changes to nested skills and subagents and to the repository root's local file
  are picked up by the watcher only where a watch target covers them: the root
  file has one, nested skills and subagents wait for the next assessment.
