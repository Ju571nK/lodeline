---
name: signed-policy
description: Formally verify Lodeline's signed policy apply path with a TLA+ model of apply, verify_envelope, atomic_write, boot reconciliation, and reload. Use before you change those functions, the policy watermark, policy.yaml writes, or control-socket concurrency, or to answer whether an older, expired, or unsigned policy can take effect across a crash or restart.
---

# Verify the signed policy apply path

`spec/SignedPolicy.tla` models how the agent takes a signed envelope from the control socket to `policy.yaml`, `state.db`, and the live evaluator. TLC checks every order of those steps within the bounds below. Any party can deliver any envelope any number of times, because the agent's only defense is `verify_envelope`.

## Run the check

```sh
python3 .claude/skills/signed-policy/check.py
```

The command exits 0 only if all three parts pass. The run takes about 25 seconds on a 12-core Mac.

1. It compares each function in the coverage table with its text at the sync commit, and prints `DRIFT` for each difference.
2. It runs TLC on `spec/concurrent.cfg`, `spec/gap.cfg`, and `spec/serial.cfg`, and prints `PASS` or `FAIL` for each.
3. It breaks the model six ways and prints `KILLED` when TLC reports the expected property. `SURVIVED` means that a property can no longer fail.

Use `--drift` for part 1 alone. Use `--model` for part 2 alone while you edit the model.

### Install the tools once

`check.py` downloads TLC 1.7.4 from the official tlaplus GitHub release on its first run and verifies the pinned SHA-256. The jar stays in `~/.cache/lodeline-formal/`, or under `$XDG_CACHE_HOME` when that is set.

TLC needs Java 11 or later, and `/usr/bin/java` on macOS is a stub. `check.py` tries `$JAVA_HOME`, then Homebrew's `openjdk@21`, then `java` on `PATH`.

```sh
# macOS. A plain install also upgrades shared libraries that headless Java does not use.
HOMEBREW_NO_AUTO_UPDATE=1 brew install --ignore-dependencies openjdk@21

# Debian or Ubuntu
sudo apt-get install openjdk-21-jre-headless
```

## What the check proves

| Property | Claim | Harm if it breaks | Broken variant that TLC catches |
|---|---|---|---|
| `OnlySignedAccepted` | `policy.yaml` holds only an envelope that passed checks 1 and 2 of `verify_envelope`. | Anyone who reaches the sender or the socket can install a policy. | Remove the signature check. |
| `NoExpiredApplied` | The agent applies an envelope only if `now < valid_until` at verification. | A long-expired policy replaces the current one. | Remove the expiry check. |
| `WatermarkNeverAhead` | `last_applied_policy_version` never exceeds the version in `policy.yaml`. | A retry fails as a regression, and the host reports a version that it does not hold. | Move the watermark update before the rename. |
| `NoRollback` | The version in `policy.yaml` never decreases. | An older policy with weaker deny rules replaces a newer one. | Remove the version check. |
| `WatermarkMonotonic` | `last_applied_policy_version` never decreases. | Envelopes older than the last applied one become acceptable again. | Remove the version check. |
| `LiveMatchesDisk` | With no apply in flight and no reload pending, the live policy is the one in `policy.yaml`. | The agent acknowledges a policy and keeps enforcing the old one. | Remove the reload notification. |

Each config checks only the properties that it lists. A property says nothing about a config that does not list it.

| Config | Connections | Fault between `Write` and `Bump` | Properties | Distinct states |
|---|---|---|---|---|
| `concurrent` | 2 | yes | `OnlySignedAccepted`, `NoExpiredApplied` | 8,170,560 |
| `gap` | 1 | yes | The above, and `WatermarkNeverAhead` | 91,016 |
| `serial` | 1 | no | All six | 16,208 |

All three configs allow a crash at every other step.

## Decide if your change touches verified code

Read the coverage table. If your change touches a listed function, `check.py` prints `DRIFT` until you confirm the model at a new sync commit.

Sync commit: `2962e9210e207c9c2636d69bf36aee2fbd0851a9`

| Model element | File | Function |
|---|---|---|
| `Verify, Write, Notify, holder` | `crates/lodeline-agent/src/policy_apply.rs` | `apply` |
| `Verify` | `crates/lodeline-core/src/policy/verify.rs` | `verify_envelope` |
| `Verify` | `crates/lodeline-core/src/policy/pubkeys.rs` | `active_pubkey` |
| `Write, Bump, BumpFails` | `crates/lodeline-core/src/policy/atomic_writer.rs` | `atomic_write` |
| `Write` | `crates/lodeline-core/src/policy/atomic_writer.rs` | `write_file_durably` |
| `Bump` | `crates/lodeline-core/src/host_meta.rs` | `host_meta_set_policy_version` |
| `Boot` | `crates/lodeline-agent/src/runtime.rs` | `reconcile_policy_on_boot` |
| `Reload` | `crates/lodeline-agent/src/policy_reload_task.rs` | `reload` |
| `Workers` | `crates/lodeline-agent/src/control.rs` | `serve_until` |

The check cannot read Rust. A `PASS` covers the model, and `DRIFT` is the only link from the model to the code. The check also cannot see inside `runtime::run`, which is too large to track. If you change the order of `reconcile_policy_on_boot`, the policy load, and the start of the control socket, update `Boot` by hand.

## Resolve a DRIFT line

1. Run `git diff <sync commit> -- <file>` and read the change to the function.
2. If the change alters no step, order, guard, or lock, go to step 5.
3. Edit the matching action in `spec/SignedPolicy.tla` so that it does what the code now does. Keep one action per indivisible step in the code.
4. Run `check.py --model`. Then resolve each `FAIL`.
5. Move the sync commit in this file to a commit on `main`. A squash merge drops branch commits. Move it only after you confirm that the model describes the code at that commit.
6. Run `check.py`. All three parts must pass.

## Resolve a FAIL line

TLC prints a trace. Each state names the action that produced it and the variables that changed.

1. Find each action in the coverage table and read its code.
2. If the code cannot take those steps in that order, the model is wrong. Fix the action, and keep the property and the bounds.
3. If the code can take those steps, compare the last state with the harm in the property table. If the harm cannot follow, the property claims too much. Restate the same claim more exactly, and add a mutant that proves the new form can fail.
4. Otherwise you found a bug. Report the trace as a short list of steps in the code's words. Then fix the code or report the bug. Do not weaken a property, lower a bound, or remove an action to get a pass.

## Resolve a SURVIVED line

A property that cannot fail proves nothing. Find out why the break no longer reaches the property, and correct the model or the mutant in `check.py`. A mutant edit must match the model text exactly once, so a rename in the model stops the run with an error.

A property written as `[][...]_vars` skips any step that changes no variable. If the failure you want to catch leaves a value unchanged, write the property as an invariant.

## Know what a pass covers

The bounds are four versions, three `valid_until` values, a clock of 0 to 3, and three crashes.

The model assumes these facts:

- ed25519 and the canonical bytes work. `auth` stands for checks 1 and 2 of `verify_envelope`.
- `rename` plus the directory fsync is durable, and one SQLite `UPDATE` is atomic.
- The wall clock only moves forward. A tick between verification and the rename does not count against `NoExpiredApplied`.
- Each host starts with no `policy.yaml`. Local edits to `policy.yaml` and `state.db` are outside the model, because a local writer does not pass through `verify_envelope`.
- Every envelope that passes `Verify` loads at `Reload` and at `Boot`.

The model leaves out these parts:

- `apply_rule_packs` and `rule-packs.yaml`.
- `lodeline-sender`, `lodeline-server`, and `lodeline-sign`.
- Document content: check 5 of `verify_envelope`, `merge`, and deny-rule compilation.
- `policy_expiry_task`.
- `DeploymentStore` and `DeploymentCoordinator`, which `runtime::run` does not use yet.
- Windows rename semantics.

To bring this skill back in line after changes that skipped it, run `/maintain-formal-verification-skill`.
