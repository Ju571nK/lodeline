# Claude Code Skills and Subagents Watch, and Two Controls (#539)

Checked 2026-11-11 against the official docs and the locally installed Claude
Code 2.1.322 (`claude --version`; nothing else was run). No Claude Code config
file was read or changed.

Sources: [settings](https://code.claude.com/docs/en/settings),
[settings reference](https://code.claude.com/docs/en/settings-reference),
[skills](https://code.claude.com/docs/en/skills),
[subagents](https://code.claude.com/docs/en/sub-agents).

## Skills and subagents

- Personal skills are `~/.claude/skills/<skill-name>/SKILL.md`, project skills
  `.claude/skills/<skill-name>/SKILL.md`. Subagents are `~/.claude/agents/` and
  `.claude/agents/`, scanned recursively.
- Claude Code picks up a skill or subagent change in the running session. It
  does not pick up a top-level `skills` or `agents` folder that was missing
  when the session started: skills need `/reload-skills`, subagents a restart.
  So a file in a new folder is not active in a running session, but the next
  session loads it. Lodeline reads the files on disk, so it still assesses them
  as soon as they appear.

## The two controls

The settings reference lists both keys with scope "Any file":

- `permissions.blockReadsOutsideWorkingDirectories`: "Make the file tools
  refuse reads outside the working directories in every permission mode".
- `permissions.blockWritesOutsideWorkingDirectories`: "Make the `Write`,
  `Edit`, and `NotebookEdit` tools refuse paths outside the working
  directories in every permission mode", apart from some of Claude Code's own
  files.

The settings page lists both under keys where `true` is honored "from any
scope" and "even when a managed source sets `false`" (reads since v2.1.257,
writes since v2.1.314). The key names are as above, under `permissions`. Only
`true` is a restriction, so only `true` is reported. Lodeline reads managed
files for controls, as it does for the other keys of the allowlist.

## Watch targets

An event reaches the parser only if its path matches a target path as a glob:
a bare folder path matches the folder itself, not the files in it, and policy
files reject `**`. The shipped user-global target therefore lists
`~/.claude/skills/*/SKILL.md` and `~/.claude/agents/*.md` (`*` also crosses
folder separators, so nested subagent files match), and the per-project target
lists the same two patterns under `.claude/`. See the addendum below for the
skills entry.

Windows paths are the same strings as the neighbouring entries and were not
tried on a device. `CLAUDE_CONFIG_DIR` is not covered, as for the other
user-global entries.

Addendum, 2026-11-12. The `skills/*/SKILL.md` and `scheduled-tasks/*/SKILL.md`
entries matched a `SKILL.md` at any depth, also inside a skill's `node_modules`,
while the assessment reads `skills/<name>/SKILL.md` one level deep. In these
built-in entries, and in the per-project skills entry, the `*` now stands for one
folder. A pattern in an operator's policy file still lets `*` cross folders, and
the agents and hooks entries still match at any depth.
