# Continue Config Surfaces

Checked 2026-10-30 against `continuedev/continue` main at `5522c6f`
(committed 2026-07-21). The GitHub API reports the repository as not
archived, with a push on 2026-10-29, although
`generative-ai-compatibility-2026-08-16.md` calls it read-only. Continue is
not installed on the machine used, so nothing here was observed at runtime.

## What the source says

- `slashCommands[].step` has no effect. The config schema describes it as
  "This property is no longer required and has no effect."
- `core/config/load.ts` resolves each `slashCommands` entry with
  `getLegacyBuiltInSlashCommandFromDescription`
  (`core/commands/slash/built-in-legacy/index.ts`), which matches `name`
  against the built-in commands and keeps only `params` and `description`.
  An entry with another name is dropped. `SlashCommandDescription` in
  `core/index.d.ts` is `{name, description, prompt?, params?}`; `run` is a
  TypeScript function on built-ins, so a `run` string in JSON is never used.
- `customCommands[]` is `{name, prompt, description?, sourceFile?}` and is
  turned into a prompt template. There is no `command` field.
- The built-in `cmd` command (`slashCommands: [{"name": "cmd"}]`) runs a
  model-written shell command through `ide.runCommand` with no confirmation.
  Its only guard is a substring check for `rm -rf`, `sudo` and `cd / `
  (`built-in-legacy/cmd.ts`).
- In `config.json`, MCP servers live under
  `experimental.modelContextProtocolServers`, not a top-level `mcpServers`.

## What Sigil reads

Since this change Sigil no longer reads `slashCommands` entries (`step`,
`run`, `prompt`) or `customCommands[].command`, and no longer watches scripts
named by `step`. A custom command's `prompt` is still scanned for destructive
patterns, as text handed to the model. A `slashCommands` entry's `prompt` is
not, since the resolver does not copy it.

Not covered yet: the `cmd` built-in, `experimental.modelContextProtocolServers`,
`config.yaml` and its `mcpServers`, `.continue/mcpServers/` directories,
CLI hooks in `.continue/settings.json`, `~/.continue/config.ts`, and
`~/.continue/permissions.yaml`. Whether Continue loads a repository's
`.continue/config.json` at all (workspace JSON is `.continuerc.json`) has not
been confirmed.
