---
name: verify
description: Drive the real Lodeline CLI (lodeline, lodeline-hook, lodeline-sign, lodeline-server) as short-lived processes in an isolated temp HOME and capture evidence. Use to prove a change to scan, doctor, hook install or enforce, or policy signing on the real binaries, not just in tests, or to reproduce a CLI bug.
---

# Verify Lodeline

Primary surface: the CLI. There is no server to keep alive. Build once per run, then run each drive as its own process through `drive.sh`, which replaces the whole environment and points every path the binaries resolve at a per-run scratch directory.

Read [`features/README.md`](features/README.md), then the matching feature file. A proof covers every entry point the feature file lists, or names the ones it skipped.

## Hard rules

- Run every binary through `drive.sh`. Never run `target/debug/lodeline*` directly. A direct run reads the real `~/.claude`, `~/.codex`, and `~/.cursor`.
- Never pass a real path to `--policy`, `--state-db`, `--events-dir`, `--control-socket`, or `--keystore`. Point them under `../` of the drive's working directory. `doctor --state-db` opens the file it is given.
- Never run `lodeline run`. See [What cannot be isolated](#what-cannot-be-isolated).
- `lodeline-hook install` and `uninstall` stay preview, without `--write`, unless `drive.sh` runs them. Inside `drive.sh`, `--write` lands in the temp HOME.
- Never run `lodeline-hook install --agent antigravity --force --write`. It calls the external `agy` CLI, whose state this harness does not isolate.
- Lodeline measures and does not block by default. Blocking journeys are opt-in, use `--enforce`, and run only through `drive.sh`. A default-path proof must show that nothing was blocked.
- Kill only what the run started. `drive.sh cleanup` does that by recorded pid and start time. Never use `pkill`, `killall`, or a kill by process name.
- Commit no account IDs, keys, credentials, or personal paths. Evidence holds real home paths (see below), so quote it in a PR only after you replace them. AWS test-node procedures stay out of this skill.

## Launch

From the repo root or a worktree root:

```sh
RUN=$(.claude/skills/verify/drive.sh new)
```

This runs `cargo build --locked` for `lodeline-agent`, `lodeline-hook`, `lodeline-signer`, and `lodeline-server`, creates the empty run, and prints the run id on stdout. The instance is ready when the id prints and Doctor passes. No migration or seed step exists: scratch starts empty, and each feature file seeds what it needs.

The shell does not keep `RUN` between tool calls, so pass the id literally in each later call. Every run has its own scratch directory, so runs can overlap, except for the fleet port in [`features/fleet-local.md`](features/fleet-local.md).

## Doctor

```sh
.claude/skills/verify/drive.sh doctor "$RUN"
```

Read-only. It exits 0 when each binary reports the workspace version, no source changed since the build, `lodeline` resolves `state.db` inside scratch, and each background process of this run is still up. After a `[FAIL]` about changed source, start a new run. Run Doctor first whenever anything looks off.

## Drive

```sh
.claude/skills/verify/drive.sh run "$RUN" <label> -- <command> [args...]
.claude/skills/verify/drive.sh bg "$RUN" <label> -- <command> [args...]
```

- `run` executes one command in `scratch/project` and returns its exit code. It prints the first 40 lines of stdout and the first 20 of stderr. Stdin passes through.
- `bg` starts a long-lived process, for `lodeline-server` only, and records its pid.
- Inside a drive, `$HOME`, `$XDG_STATE_HOME`, `$XDG_CONFIG_HOME`, `$XDG_RUNTIME_DIR`, and `$TMPDIR` are scratch paths, and `PATH` is `target/debug`, `/usr/bin`, and `/bin`. Use `sh -c '...'` with single quotes to seed fixtures, so those variables expand inside the sandbox.
- A label is single-use, so evidence is never overwritten.

`drive.sh` refuses root, because as root the binaries use `/var/run`, `/var/lib`, and `/etc` with no override. It is macOS and Linux only. The Windows paths have no driver.

## Evidence

Each drive writes `<label>.cmd`, `<label>.stdout`, `<label>.stderr`, and `<label>.exit` to `${TMPDIR:-/tmp}/lodeline-verify/<run>/evidence/`, outside the repo. `build.txt` there records the git SHA, the dirty files, and the binary versions. `drive.sh` refuses a `TMPDIR` inside the repo. Evidence survives cleanup and stays until the OS clears `TMPDIR`, so copy it elsewhere if it must last.

Proof standards:

- Drive the real user path: the shipped binary and its flags. Test seams such as `report_json_for` are not proof.
- Capture the action and the resulting state. Pair a command with a read-only second view, such as `lodeline-hook verify` after `install --write`.
- Check side effects with `find` on the scratch roots. A preview proof shows that nothing was written.
- Mock only at a production boundary. Fixture configs under the temp HOME are fine. A stubbed verdict is not proof of a daemon decision.
- Report each result as verified, skipped, or failed. A skipped entry point is not verified through another path.

## Cleanup

```sh
.claude/skills/verify/drive.sh cleanup "$RUN"
```

Stops this run's background processes, removes `scratch/`, keeps `evidence/`, and prints what survived. It is safe to run twice. Run it after every failed attempt too.

## What cannot be isolated

- **User enumeration.** `lodeline doctor` and `lodeline show paths` take users from `/Users` on macOS and `/etc/passwd` on Linux, not from `$HOME`. `doctor` checks that real users' config paths exist and prints those paths, so its evidence holds real home paths. It does not read their contents.
- **System policy files.** `lodeline scan` reads managed settings at `/Library/Application Support/ClaudeCode` on macOS, `/etc/claude-code` on Linux, and `/etc/codex`, read-only. On a host with those files, extra rows or controls appear. Assert on your fixture's row, not on the whole table.
- **Full Disk Access.** `doctor` on macOS probes the system TCC database path. The result, and so the exit code, depends on the host.
- **The daemon.** `lodeline run` watches every enumerated user's real configs. A policy can disable a target by id, but no run has shown that this covers every daemon read. Daemon behavior stays with `cargo test -p lodeline-agent`. Anything that needs a live daemon is out of reach here: `show stats`, `show risk`, `show policy-status`, `show targets`, `reload`, live AI Guard data in `doctor`, and real deny verdicts.

## Secondary surfaces

- **Fleet stack.** `lodeline-sign` and `lodeline-server` in plain HTTP on loopback run locally, as [`features/fleet-local.md`](features/fleet-local.md) shows. `lodeline-sender`, mTLS, and enrollment have no recipe here and stay with `cargo test -p lodeline-server` and `cargo test -p lodeline-sender`. The `lodeline-manager` console lives in another repo.
- **Diagnostic app.** The macOS Tauri app is planned and has no driver yet.

Keep the map current with `/maintain-verification-skill`.
