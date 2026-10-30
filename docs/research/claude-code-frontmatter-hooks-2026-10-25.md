# Claude Code Skill and Subagent Frontmatter Hooks

Checked 2026-10-25 against the official docs and the locally installed Claude
Code 2.1.310. Only static file reads were run; no hook was executed.

## What the docs say

[Hooks in skills and agents](https://code.claude.com/docs/en/hooks#hooks-in-skills-and-agents)
lets a skill or subagent declare `hooks:` in its YAML frontmatter "in the same
configuration format as settings-based hooks". A skill's hooks are registered
when the skill is invoked and keep running for the rest of the session. A
subagent's hooks run only while that subagent runs, and `Stop` becomes
`SubagentStop`. Plugin subagents ignore `hooks`, `mcpServers`, and
`permissionMode` ([subagents](https://code.claude.com/docs/en/sub-agents)).
Project subagent hooks need workspace trust (since v2.1.218); project skill
hooks follow the settings-file trust rule.

Locations ([skills](https://code.claude.com/docs/en/skills),
[subagents](https://code.claude.com/docs/en/sub-agents)):

| Component | Personal | Project | Layout |
| --- | --- | --- | --- |
| Skill | `~/.claude/skills/` | `.claude/skills/` | `<name>/SKILL.md`, one level; `<name>` may be a symlink |
| Subagent | `~/.claude/agents/` | `.claude/agents/` | `*.md`, scanned recursively |

Skills under a `.claude/skills/` below the start directory load on demand once
Claude touches a file there. Project subagents are found by walking up from
the working directory to the repository root.

## What the local install shows

`~/.claude/skills/` on this machine holds 71 entries, many of them symlinks.
Four declare frontmatter hooks (`careful`, `freeze`, `guard`, `investigate`),
all `PreToolUse` command hooks of the form
`bash ${CLAUDE_SKILL_DIR}/bin/<check>.sh`. Several entries, `careful`
included, are symlinks into `skills/gstack/`. The docs list `${CLAUDE_SKILL_DIR}`
substitution for skill content and `allowed-tools`, not hooks; these skills
rely on it in hooks anyway.

## What Sigil reads now

- Personal and project `skills/<name>/SKILL.md` (through symlinks) and
  `agents/**/*.md` (depth 8, no symlinked directories). Each kind has its own
  budget of 1,000 files, so a flood of one kind cannot hide the other; a
  warning is logged when a budget runs out. Only the first 256 KiB of each
  file is read.
- Only the frontmatter `hooks` value is converted, so a YAML tag or a
  non-string key in another field does not hide the hooks. Merge keys
  (`<<: *anchor`) are resolved. A YAML syntax error skips that file with a
  warning.
- The `hooks` object goes through the settings hook emitter, so it yields the
  same reasons: `no_sandbox` (once per assessment), `broad_matcher`,
  destructive inline commands, scanned hook scripts, and
  `hook_forwards_tool_calls`. Scripts those hooks run are watched like
  settings hook scripts.
- `${CLAUDE_SKILL_DIR}` is replaced with the directory of the resolved
  `SKILL.md`. On this machine `careful/SKILL.md` is a symlink and its `bin/`
  exists only next to the target, so the skill could not work with the link's
  directory. That is the basis for resolving; it is inferred, not documented.
- A hook command of the form `bash <script>` (also `sh`, `zsh`, `dash`) now
  has its script scanned, for settings hooks too. Before, only a command
  whose first token was a path was. A command chained after the script is
  checked inline, so `bash ./ok.sh && rm -rf ~` is reported; the script's own
  arguments are not, since guards often receive the patterns they block. An operand that still
  holds a `$VAR` is not treated as a script. Since 2026-10-29 the
  interpreter may follow `NAME=value` assignments or an `env` launcher
  without options (`/usr/bin/env bash x.sh`), may be `bash.exe`, and may
  carry flags (`bash -euo pipefail x.sh`, `--rcfile <file>`). `-c`, `-s`,
  and a lone `-` mean no script file. A command substitution in the words
  before the script makes the whole command checked inline. Since
  2026-10-30 `env` may carry `-i`, `-0`, `-v`, `-u NAME` and `-P PATH`
  (and their long forms). `-C`, `-S` and other options leave the command
  checked inline, because the script path no longer reads off the command.
- A repo with only `.claude/skills/` or `.claude/agents/` is now discovered.

`sigil scan` on this machine after the change logs no frontmatter warning
and reports `destructive_in_hook_script` for `careful`'s `check-careful.sh`.
That is a false positive: the match is a comment listing the patterns the
script blocks. Skipping comment lines was tried and dropped, because a
line-based filter misreads a `#` inside a multi-line quote or after a `\`
continuation and would hide code that runs. Sigil does not block, so the
false positive is the cheaper error.

Not covered: plugin skills and agents, nested `<subdir>/.claude/skills/`
below a repository root, parent-directory walks, and workspace-trust state.
Changes to a symlinked `SKILL.md` target outside the watched directories are
picked up on the next periodic assessment, not by the watcher. Reasons carry
no field naming the skill or agent that declared the hook.
