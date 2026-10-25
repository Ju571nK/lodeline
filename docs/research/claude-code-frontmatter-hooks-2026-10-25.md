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
`bash ${CLAUDE_SKILL_DIR}/bin/<check>.sh`. The docs list `${CLAUDE_SKILL_DIR}`
substitution for skill content and `allowed-tools`, not hooks; these skills
rely on it in hooks anyway.

## What Sigil reads now

- Personal and project `skills/<name>/SKILL.md` (through symlinks) and
  `agents/**/*.md` (depth 8, no symlinked directories), at most 500 files per
  `.claude` directory.
- The frontmatter `hooks` object goes through the settings hook emitter, so it
  yields the same reasons: `no_sandbox` (once per assessment),
  `broad_matcher`, destructive inline commands, scanned hook scripts, and
  `hook_forwards_tool_calls`.
- `${CLAUDE_SKILL_DIR}` is replaced with the skill directory before
  classification, so a hook that runs a bundled script by path gets that
  script scanned.
- A repo with only `.claude/skills/` or `.claude/agents/` is now discovered.

Not covered: plugin skills and agents, nested `<subdir>/.claude/skills/`
below a repository root, parent-directory walks, and workspace-trust state.
Reasons carry no field naming the skill or agent that declared the hook.
