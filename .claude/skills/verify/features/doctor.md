# Doctor

`lodeline doctor` checks configuration and permissions without starting the daemon. It prints a line per check and the effective scoring rubric, and its exit code separates a clean host, reduced coverage, and a config the daemon would refuse.

## Sub-features

- `doctor-report` prints targets, enumerated users, path counts, and the rubric.
- `doctor-fresh` reports a missing state.db as `[INFO]`, not as a warning.
- `doctor-daemon-down` falls back to the static rubric when no daemon answers.
- `doctor-override` marks a `--policy` rubric override with `*`.
- `doctor-bad-policy` exits `2` on a policy that does not parse.

## How to get to it (user POV)

- Run `lodeline doctor` in a terminal.
- Run `lodeline doctor --policy <path>` to check a policy file before use.

## Driving it with drive.sh

Preconditions:

- `drive.sh doctor "$RUN"` exits 0.
- No `state.db` exists under `$XDG_STATE_HOME`.

- **Fresh host.** Run `drive.sh run "$RUN" doctor-fresh -- lodeline doctor`. Stdout starts with `Lodeline doctor`, holds `[INFO] state.db not yet present` with a path under `scratch/state`, and holds `lodeline agent not running on control socket` and `Effective Rubric (static)`. The last line is `All checks passed.` with exit code `0`, or a warning count with exit code `1`.
- **Seed policies.** Run `drive.sh run "$RUN" doctor-seed -- sh -c 'printf "version: 1\nhost_id_strategy: hostname\nrubric_overrides:\n  destructive_in_hook_script: 5.0\n" > ../home/override.yaml; printf "not: [valid\n" > ../home/bad.yaml'`. Exit code `0`.
- **Override marker.** Run `drive.sh run "$RUN" doctor-override -- lodeline doctor --policy ../home/override.yaml`. `.stdout` holds `destructive_in_hook_script            5.0 *`.
- **Bad policy.** Run `drive.sh run "$RUN" doctor-bad -- lodeline doctor --policy ../home/bad.yaml`. Exit code `2`, stdout holds `[ERROR] policy parse failed`, and the last line is `1 error(s); daemon will not start.`.
- **No state created.** Run `drive.sh run "$RUN" doctor-side-effects -- find ../state -type f`. Stdout is empty.

## Gotchas

- `--control-socket` does not reach `doctor`. It resolves the socket from `XDG_RUNTIME_DIR` or `TMPDIR`, which is why `drive.sh` sets both.
- Exit code `1` on a developer Mac can mean Full Disk Access is missing, not a regression. Read the `[WARN]` line.
- `enumerated users` and the `[INFO] target ...` lines describe the real host. They do not follow the temp HOME.
- `.stdout` holds real home paths. Replace them before you quote it.
- `drive.sh run` shows only the first 40 lines, so the rubric rows and the last line are in the `.stdout` file.
