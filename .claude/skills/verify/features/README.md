# Lodeline verification map

This directory is the maintained source for verifying the user-facing behavior of the Lodeline CLI. Read the index before you drive a binary, then use the matching feature file as the recipe.

## Baseline preconditions

- A run exists and `drive.sh doctor <run>` exits 0. See [`../SKILL.md`](../SKILL.md).
- The temp HOME is empty unless the recipe seeds it.
- Recipes below write `drive.sh` for `.claude/skills/verify/drive.sh`, from the repo root, and `$RUN` for the run id.

## Driving conventions

- Run every command through `drive.sh run` or `drive.sh bg`. The sandbox replaces the environment.
- The working directory of a drive is `scratch/project`. Sibling scratch directories are at `../home`, `../state`, and `../run`. Recipes keep their own files in `../fleet`.
- Seed fixtures with `sh -c '...'` so `$HOME` expands inside the sandbox.
- Treat every command as literal. Keep flags and quoted values unchanged.
- Start each recipe from a clean run when a previous recipe seeded the same paths.

## Proof and skip reporting

- CLI proof is the `.cmd`, `.stdout`, `.stderr`, and `.exit` set for a label.
- Mutation proof includes a read-only second view of the stored result.
- Assert on the fixture's row or key, not on the whole output. Host state can add rows.
- Record the feature file and entry point with every result.
- Report an unreachable path with the attempted command and the unmet precondition.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior. It then uses exactly four H2 sections in this order.

1. `Sub-features` lists short IDs with one line for each behavior.
2. `How to get to it (user POV)` lists every user entry point.
3. `Driving it with drive.sh` starts with `Preconditions:` and uses labeled bullets that pair each user action with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a verification run.

## Features

- [Scan posture](./scan.md) covers the human report for an empty home, a risky user-global config, and a project directory.
- [Scan JSON](./scan-json.md) covers the `--json` contract for scripts.
- [Doctor](./doctor.md) covers the diagnostic report, exit codes, and rubric overrides.
- [Hook install](./hook-install.md) covers preview, write in a temp HOME, drift detection, uninstall, and opt-in enforce.
- [Fleet local](./fleet-local.md) covers policy signing and the plain-HTTP server on loopback.
