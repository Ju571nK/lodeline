---
name: signed-policy
description: Formally verify Lodeline's signed policy apply path with a TLA+ model of apply, verify_envelope, atomic_write, settle_pending, the file in force, boot, and reload. Use before you change those functions, the policy watermark, the pending envelope row, PolicyPaths or SignedFile::in_force, policy.yaml writes, or control-socket concurrency, or to answer whether an older, expired, or unsigned policy can take effect across a crash, a power cut, or a restart.
---

# Verify the signed policy apply path

`spec/SignedPolicy.tla` models how the agent takes a signed envelope from the control socket to the applied file, `state.db`, and the live evaluator, and how it chooses between the applied file and the operator's local file. TLC checks every order of those steps within the bounds below. Any party can deliver any envelope any number of times, because the agent's only defense is `verify_envelope`.

## Run the check

```sh
python3 .claude/skills/signed-policy/check.py
```

The command exits 0 only if all three parts pass. The run takes about 35 seconds on a 12-core Mac.

1. It compares each function and block in the coverage table with its text at the sync commit, and prints `DRIFT` for each difference.
2. It runs TLC on `spec/policy.cfg`, `spec/rule_packs.cfg`, and `spec/local_edits.cfg`, and prints `PASS` or `FAIL` for each.
3. It breaks the model 19 ways, and prints `KILLED` when TLC reports the expected property through the expected steps. `SURVIVED` means that a property can no longer fail. `OFF-TARGET` means that the property failed for some other reason than the mutant stands for.

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

Below, the applied file is `SignedFile.applied`, the local file is `SignedFile.local`, and the file in force is what `SignedFile::in_force` returns: the applied file if it exists, else the local file. Each property covers one file, `policy.yaml` or `rule-packs.yaml`, and its own version.

| Property | Claim | Harm if it breaks | Broken variants that TLC catches |
|---|---|---|---|
| `OnlySignedAccepted` | The applied file holds only an envelope that passed checks 1 and 2 of `verify_envelope`. The local file is the operator's, and this says nothing about it. | Anyone who reaches the sender or the socket can install a policy. | No signature check. |
| `NoExpiredApplied` | An apply goes on to `record_pending` only if `now < valid_until` at verification. | A long-expired policy replaces the current one. | No expiry check. |
| `VersionCheckHolds` | From verification to the rename, the envelope an apply holds is newer than the file in force. | An older envelope is written over a newer one. | No version check. No `apply_lock`. No settle in `apply`. |
| `WatermarkNeverAhead` | The applied version never exceeds the version of the file in force. | A retry fails as a regression, and the host reports a version that it does not hold. | Promote before the rename. No directory fsync in `write_file_durably`. No directory sync in `settle_pending`. |
| `NoRollback` | The version of the file in force falls only at a stop that leaves a pending row. Boot then drops that row, and the applied version never claimed the lost file. This is the one way a power cut can lower the file. The property is about the file and is not a claim about acceptance, which is `VersionCheckHolds`. | An older policy with weaker deny rules replaces a newer one. | No version check and no `record_pending` guard together. Either one alone is not enough to break it. |
| `WatermarkMonotonic` | The applied version falls only at a stop that brings back the pending row with its file still in force, so boot finishes the same apply. | Envelopes older than the last applied one become acceptable again. | No guard on the version at any step. |
| `BootSettles` | After boot no row is pending, and the applied record is the envelope behind the file in force, or nothing for the operator's file. | An apply checked against a stale record replaces a newer policy. | No settle at boot. Boot settles the apply target. `record_pending` at `synchronous=NORMAL`, where a power cut keeps the rename and loses the row. |
| `LiveMatchesDisk` | With no apply in flight, no row pending, no change unseen, and no reload running, the live policy is the applied file if it exists, else the local file. | The agent acknowledges a policy and keeps enforcing the old one. | The local file read first. No reload notification. The change consumed after the read. |
| `ExpiryMatchesDisk` | With no apply in flight and no row pending, `active_valid_until` is the expiry of the file in force. | The host reports an expiry for a policy it does not run. | No expiry seeded at boot. A settled apply not published. |
| `LoadedPolicyKept` | A running agent that loaded a policy file keeps it when the file goes missing. | A save that unlinks before it writes drops every deny rule. | No missing-file rule in `reload`. |

Each config checks only the properties that it lists. A property says nothing about a config that does not list it.

| Config | Kind | Connections | Failed steps | Power cuts | Hand edits | Properties | Distinct states |
|---|---|---|---|---|---|---|---|
| `policy` | policy | 2 | yes | yes | no | All but `LoadedPolicyKept` | 994,084 |
| `rule_packs` | bundle | 2 | yes | yes | no | The same, less `ExpiryMatchesDisk` | 852,580 |
| `local_edits` | policy | 2 | yes | no | yes | `OnlySignedAccepted`, `NoExpiredApplied`, `VersionCheckHolds`, `WatermarkMonotonic`, `LoadedPolicyKept` | 2,732,004 |

All three configs allow a crash at every step, and start from all five hosts in `Starts`. `local_edits` leaves out the other properties because a hand edit breaks them on purpose: the documented way back to the local file keeps the signed version and its expiry while the local file runs.

## Decide if your change touches verified code

Read the coverage table. If your change touches a listed function or block, `check.py` prints `DRIFT` until you confirm the model at a new sync commit. A row such as `first..last` tracks the lines from the first line that contains `first` to the next line that contains `last`, for a block of a function too large to track whole.

Sync commit: `9dfff8c9878db3650401ab1e7ebce9d97dea6276`

| Model element | File | Function |
|---|---|---|
| `Settle, Verify, Reject, Finish, cacheLock` | `crates/lodeline-agent/src/policy_apply.rs` | `apply` |
| `Settle, Verify, Reject, Finish, cacheLock` | `crates/lodeline-agent/src/policy_apply.rs` | `apply_rule_packs` |
| `Settle, applyLock` | `crates/lodeline-agent/src/policy_apply.rs` | `settle_earlier_apply` |
| `Publish, Notify, NotifySettled` | `crates/lodeline-agent/src/policy_apply.rs` | `publish_policy` |
| `Notify, NotifySettled` | `crates/lodeline-agent/src/policy_apply.rs` | `publish_rule_packs` |
| `Verify` | `crates/lodeline-core/src/policy/verify.rs` | `verify_envelope` |
| `Verify` | `crates/lodeline-core/src/policy/pubkeys.rs` | `active_pubkey` |
| `Record, Rename, Fsync, Promote` | `crates/lodeline-core/src/policy/atomic_writer.rs` | `atomic_write` |
| `SettleRow, Matches, Finished` | `crates/lodeline-core/src/policy/atomic_writer.rs` | `settle_pending` |
| `Rename, RenameFails, Fsync, FsyncFails` | `crates/lodeline-core/src/policy/atomic_writer.rs` | `write_file_durably` |
| `RenameFails` | `crates/lodeline-core/src/policy/atomic_writer.rs` | `create_dir_durably` |
| `Fsync, SettleRow` | `crates/lodeline-core/src/policy/atomic_writer.rs` | `sync_dir` |
| `Record, RecordFails` | `crates/lodeline-core/src/host_meta.rs` | `record_pending` |
| `Matches` | `crates/lodeline-core/src/host_meta.rs` | `pending` |
| `Promote, PromoteFails, SettleRow` | `crates/lodeline-core/src/host_meta.rs` | `promote_pending` |
| `SettleRow` | `crates/lodeline-core/src/host_meta.rs` | `clear_pending` |
| `Verify, Boot` | `crates/lodeline-core/src/host_meta.rs` | `host_meta_get` |
| `InForce, ReloadCheck` | `crates/lodeline-agent/src/runtime.rs` | `in_force` |
| `target, local` | `crates/lodeline-agent/src/runtime.rs` | `at` |
| `target, local` | `crates/lodeline-agent/src/runtime.rs` | `policy_paths` |
| `target, local` | `crates/lodeline-agent/src/runtime.rs` | `system_policy_paths` |
| `target, local` | `crates/lodeline-agent/src/runtime.rs` | `default_policy_paths` |
| `target, local` | `crates/lodeline-agent/src/runtime.rs` | `resolve_policy_paths_unix` |
| `InForce` | `crates/lodeline-agent/src/runtime.rs` | `policy_path_for_command` |
| `Boot` | `crates/lodeline-agent/src/runtime.rs` | `let policy_path_for_apply = cfg..let policy_file_loaded` |
| `Settle, Rename` | `crates/lodeline-agent/src/runtime.rs` | `let apply_ctx = Arc::new..apply_lock: Default::default()` |
| `ReloadRead, loaded` | `crates/lodeline-agent/src/runtime.rs` | `paths: cfg.policy_paths.clone()..policy_file_loaded,` |
| `ReloadCheck, ReloadRead` | `crates/lodeline-agent/src/policy_reload_task.rs` | `reload` |
| `ReloadCheck` | `crates/lodeline-agent/src/policy_reload_task.rs` | `run` |
| `ReloadRead` | `crates/lodeline-agent/src/policy_reload_task.rs` | `read_bundle_state` |
| `ReloadCheck` | `crates/lodeline-agent/src/control.rs` | `Request::ReloadPolicy => {..send_modify` |
| `Workers` | `crates/lodeline-agent/src/control.rs` | `serve_until` |

The check cannot read Rust. A `PASS` covers the model, and `DRIFT` is the only link from the model to the code. `Boot` stands for the block above and for its order in `runtime::run`, which no row can see: settle, load the file, then start the control socket. If you change that order, update `Boot` by hand.

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

## Resolve a SURVIVED or OFF-TARGET line

A property that cannot fail proves nothing. Find out why the break no longer reaches the property, and correct the model or the mutant in `check.py`. A mutant edit must match the model text exactly once, so a rename in the model stops the run with an error.

`OFF-TARGET` prints the trace TLC found and the steps the mutant expects. Read the trace. If it shows the harm the mutant stands for by a shorter way, correct the expected steps. If it shows some other failure, tune the mutant until it fails for its own reason. A mutant that fails for the wrong reason says nothing about the code it stands for.

A property written as `[][...]_vars` skips any step that changes no variable. If the failure you want to catch leaves a value unchanged, write the property as an invariant.

## Know what a pass covers

The bounds are four versions, three `valid_until` values, a clock of 0 to 3, and three stops, which crashes and power cuts share. The checks and the guards behind `apply_lock` overlap, so removing the `record_pending` or `promote_pending` guard alone changes nothing the model can see. The mutants that need one remove several at once.

The model assumes these facts:

- ed25519 and the canonical bytes work. `auth` stands for checks 1 and 2 of `verify_envelope`.
- `rename` plus the directory fsync is durable, one SQLite transaction is atomic, and WAL commits reach the disk in order.
- The state directory is not lost. `create_dir_durably` keeps a new directory, and the model treats the directory as there.
- The wall clock only moves forward. A tick after verification does not count against `NoExpiredApplied`.
- A host starts in one of the five `Starts`: no local file, the operator's file, an older agent's file, or an older agent stopped just after or just before its rename. An older agent's rename has reached the disk, and its record has an expiry.
- `policy.yaml` and `rule-packs.yaml` do not affect each other. They share `apply_lock` and a `state.db` connection, and the model checks each alone.
- Two envelopes never hold the same bytes, so `pending = file` stands for the blake3 comparison in `settle_pending`.
- Every envelope that passes `Verify` loads at `ReloadRead` and at `Boot`, the operator's file also loads, and a reload's read succeeds.
- The only writers other than an apply are the hand edits in `local_edits`: deleting the applied file, and adding or removing the local one. Nobody else writes these files or `state.db`.

The model leaves out these parts:

- The other hand edits, and power cuts in `local_edits`.
- `lodeline-sender`, `lodeline-server`, and `lodeline-sign`.
- Document content: check 5 of `verify_envelope`, `merge`, deny-rule compilation, and the corrupt and empty states of `read_bundle_state`.
- `policy_expiry_task`, and the wake-ups of `rule_packs_watch`, which `ReloadCheck` only stands for as a reload at any time.
- Commands that only read the files: `assess`, `show`, `doctor`, and `status`.
- `host_meta_get` reading version 1 with no expiry as no envelope, and a recorded version with no expiry.
- `DeploymentStore` and `DeploymentCoordinator`, which `runtime::run` does not use yet.
- Windows rename semantics and its `sync_dir`, which does nothing.

To bring this skill back in line after changes that skipped it, run `/maintain-formal-verification-skill`.
