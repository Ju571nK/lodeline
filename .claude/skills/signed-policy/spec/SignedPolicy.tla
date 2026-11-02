--------------------------- MODULE SignedPolicy ---------------------------
(***************************************************************************)
(* The agent's apply path for one signed artifact file, across concurrent  *)
(* control-socket connections, failed steps, process crashes, power cuts,  *)
(* and restarts. Any party may deliver any envelope, any number of times:  *)
(* each `Verify` picks freely from Envelopes. SKILL.md maps every action   *)
(* to the Rust it stands for.                                              *)
(***************************************************************************)
EXTENDS Integers, TLC

CONSTANTS
    Workers,      \* one per connection: serve_until spawns a task for each
    Kind,         \* "policy" or "rule_packs": which apply and which file
    MaxVersion,
    MaxClock,
    MaxCrashes,
    Faults,       \* TRUE: any step of atomic_write may return an error
    PowerCuts,    \* TRUE: a crash may also lose what never reached the disk
    LocalEdits,   \* TRUE: an operator may edit the files by hand at any time
    NoWorker

Envelopes == [v : 1..MaxVersion, until : 1..MaxClock, auth : {"good", "bad"}]

\* Stands for no file, no recorded envelope, and no pending row. Each envelope
\* has its own bytes, so `pending = file` stands for the blake3 comparison.
NoFile == [v |-> 0, until |-> 0, auth |-> "none"]

\* The operator's unsigned file: in /etc/lodeline, or at the apply target on a host
\* with no local file.
OperatorFile == [v |-> 0, until |-> 0, auth |-> "local"]

\* What an older agent, which applied into /etc/lodeline, left there.
OlderEnvelope(v) == [v |-> v, until |-> MaxClock, auth |-> "good"]

\* The hosts an agent can start on. `--policy`, a non-root agent, and Windows have
\* no local file. The operator's file on those hosts is the apply target, and an
\* apply replaces it. Their older-agent states get no row, because a stop during an
\* apply from the first two rows gives the same states.
Starts == {
    [target |-> NoFile, local |-> NoFile, applied |-> NoFile, pending |-> NoFile],
    [target |-> OperatorFile, local |-> NoFile, applied |-> NoFile, pending |-> NoFile],
    [target |-> NoFile, local |-> OperatorFile, applied |-> NoFile, pending |-> NoFile],
    [target |-> NoFile, local |-> OlderEnvelope(2), applied |-> OlderEnvelope(2), pending |-> NoFile],
    \* An older agent stopped after its rename.
    [target |-> NoFile, local |-> OlderEnvelope(2), applied |-> OlderEnvelope(1), pending |-> OlderEnvelope(2)],
    \* An older agent stopped before its rename.
    [target |-> NoFile, local |-> OlderEnvelope(1), applied |-> OlderEnvelope(1), pending |-> OlderEnvelope(2)]
}

VARIABLES
    target,       \* SignedFile.applied, as a read sees it
    savedTarget,  \* the same, as a power cut leaves it
    local,        \* SignedFile.local. An apply never writes it
    applied,      \* host_meta version with applied_envelope.valid_until
    savedApplied, \* the same, as a power cut leaves it
    pending,      \* the pending_envelope row
    savedPending, \* the same, as a power cut leaves it
    clock,
    up,           \* the agent process is running
    pc,           \* each worker's position in apply()
    msg,          \* the envelope each worker holds
    applyLock,    \* ApplyContext.apply_lock
    cacheLock,    \* ApplyContext.cache, held across atomic_write
    notified,     \* policy_version_tx has an unseen change
    reading,      \* the file the running reload chose and has not read yet
    retry,        \* ReloadCtx.unfinished holds a reason, so a root tick reloads
    live,         \* the envelope the last load read
    loaded,       \* ReloadCtx.policy_file_loaded
    activeUntil,  \* active_valid_until
    crashes

durable == <<target, savedTarget, local, applied, savedApplied, pending, savedPending>>
world == <<clock, up, crashes>>
loader == <<notified, reading, retry, live, loaded>>
vars == <<durable, world, pc, msg, applyLock, cacheLock, loader, activeUntil>>

\* The saved copies matter only with power cuts. Keeping them constant otherwise
\* stops TLC counting states that no action can tell apart.
Saved(x) == IF PowerCuts THEN x ELSE NoFile

WorkerSymmetry == Permutations(Workers)

Init ==
    /\ \E s \in Starts :
        /\ target = s.target
        /\ savedTarget = Saved(s.target)
        /\ local = s.local
        /\ applied = s.applied
        /\ savedApplied = Saved(s.applied)
        /\ pending = s.pending
        /\ savedPending = Saved(s.pending)
    /\ clock = 0
    /\ up = FALSE
    /\ pc = [w \in Workers |-> "idle"]
    /\ msg = [w \in Workers |-> NoFile]
    /\ applyLock = NoWorker
    /\ cacheLock = NoWorker
    /\ notified = FALSE
    /\ reading = "no"
    /\ retry = FALSE
    /\ live = NoFile
    /\ loaded = FALSE
    /\ activeUntil = NoFile.until
    /\ crashes = 0

\* SignedFile::in_force: the local file only when the applied one is known to be
\* absent. An uncheckable path stays on the applied file, whose read then fails.
InForce == IF target # NoFile THEN target ELSE local

\* settle_pending: the rename happened if the file holds the pending bytes.
Matches(file) == pending # NoFile /\ pending = file

Finished(file) == Matches(file) /\ applied.v <= pending.v

\* The directory sync, then promote_pending or clear_pending at synchronous=NORMAL.
\* A stop between the two leaves what `WriteBackFile` then a stop leaves. Only the
\* apply target can be unsynced, because an older agent's rename is long past.
SettleRow(file) ==
    /\ savedTarget' = IF Matches(target) THEN Saved(target) ELSE savedTarget
    /\ applied' = IF Finished(file) THEN pending ELSE applied
    /\ pending' = NoFile

\* A settled policy publishes through publish_policy, and a settled bundle through
\* publish_rule_packs, which has no expiry cell.
PublishStart == IF Kind = "policy" THEN "publish" ELSE "notify"
PublishSettledStart == IF Kind = "policy" THEN "publishSettled" ELSE "notifySettled"

\* apply() or apply_rule_packs() returns. The lock guard drops last.
Finish(w) ==
    /\ pc' = [pc EXCEPT ![w] = "idle"]
    /\ msg' = [msg EXCEPT ![w] = NoFile]
    /\ applyLock' = NoWorker

\* An error leaves atomic_write. Pending stays for the next settle.
Fail(w) ==
    /\ Finish(w)
    /\ cacheLock' = NoWorker
    /\ UNCHANGED <<durable, world, loader, activeUntil>>

\* The first line of apply(), then settle_earlier_apply, which settles against the
\* apply target. Boot has settled every older row by now. A settle that fails changes
\* nothing, so it is no step. settle_pending runs under the cache lock.
Settle(w) ==
    /\ up
    /\ pc[w] = "idle"
    /\ applyLock = NoWorker
    /\ applyLock' = w
    /\ cacheLock = NoWorker
    /\ SettleRow(target)
    /\ pc' = [pc EXCEPT ![w] = IF Finished(target) THEN PublishSettledStart ELSE "verify"]
    /\ msg' = [msg EXCEPT ![w] = IF Finished(target) THEN pending ELSE NoFile]
    /\ UNCHANGED <<target, local, savedApplied, savedPending, world, cacheLock, loader, activeUntil>>

\* apply(): host_meta_get, then verify_envelope, then merge_on_this_host. These
\* only read, and apply_lock keeps out the only writer, so they are one step.
Verify(w, e) ==
    /\ up
    /\ pc[w] = "verify"
    /\ cacheLock = NoWorker
    /\ e.auth = "good"
    /\ clock < e.until
    /\ e.v > applied.v
    /\ pc' = [pc EXCEPT ![w] = "record"]
    /\ msg' = [msg EXCEPT ![w] = e]
    /\ UNCHANGED <<durable, world, applyLock, cacheLock, loader, activeUntil>>

\* Any envelope can fail those checks, and the failure only returns.
Reject(w) ==
    /\ up
    /\ pc[w] = "verify"
    /\ Finish(w)
    /\ UNCHANGED <<durable, world, cacheLock, loader, activeUntil>>

\* record_pending at synchronous=FULL, which also syncs every earlier commit. The
\* cache lock is taken here and held to the end of atomic_write.
Record(w) ==
    /\ up
    /\ pc[w] = "record"
    /\ cacheLock = NoWorker
    /\ cacheLock' = w
    /\ pending = NoFile
    /\ applied.v <= msg[w].v
    /\ pending' = msg[w]
    /\ savedPending' = Saved(msg[w])
    /\ savedApplied' = Saved(applied)
    /\ pc' = [pc EXCEPT ![w] = "rename"]
    /\ UNCHANGED <<target, savedTarget, local, applied, world, msg, applyLock, loader, activeUntil>>

\* record_pending returns StateBeforeDisk: an I/O error, a primary key conflict on
\* the row, or WouldLowerVersion.
RecordFails(w) ==
    /\ up
    /\ pc[w] = "record"
    /\ cacheLock = NoWorker
    /\ Faults \/ pending # NoFile \/ applied.v > msg[w].v
    /\ Fail(w)

\* write_file_durably: rename over the target. The rename is not yet saved.
Rename(w) ==
    /\ up
    /\ pc[w] = "rename"
    /\ target' = msg[w]
    /\ pc' = [pc EXCEPT ![w] = "fsync"]
    /\ UNCHANGED <<savedTarget, local, applied, savedApplied, pending, savedPending, world, msg, applyLock, cacheLock, loader, activeUntil>>

\* write_file_durably: an error from create_dir_durably, the temp file, or the
\* rename. record_pending failing after its row commits, when it restores
\* synchronous=NORMAL, leaves the same state.
RenameFails(w) ==
    /\ Faults
    /\ up
    /\ pc[w] = "rename"
    /\ Fail(w)

\* write_file_durably: fsync of the parent directory.
Fsync(w) ==
    /\ up
    /\ pc[w] = "fsync"
    /\ savedTarget' = Saved(target)
    /\ pc' = [pc EXCEPT ![w] = "promote"]
    /\ UNCHANGED <<target, local, applied, savedApplied, pending, savedPending, world, msg, applyLock, cacheLock, loader, activeUntil>>

\* The directory fsync returns an error. The rename may stand.
FsyncFails(w) ==
    /\ Faults
    /\ up
    /\ pc[w] = "fsync"
    /\ Fail(w)

\* promote_pending: one transaction at synchronous=NORMAL, so it is not yet saved.
\* It reads the pending row, not the worker's envelope.
Promote(w) ==
    /\ up
    /\ pc[w] = "promote"
    /\ pending # NoFile
    /\ applied.v <= pending.v
    /\ applied' = pending
    /\ pending' = NoFile
    /\ cacheLock' = NoWorker
    /\ pc' = [pc EXCEPT ![w] = PublishStart]
    /\ UNCHANGED <<target, savedTarget, local, savedApplied, savedPending, world, msg, applyLock, loader, activeUntil>>

\* promote_pending returns StateAfterDisk: an I/O error, no row, or WouldLowerVersion.
PromoteFails(w) ==
    /\ up
    /\ pc[w] = "promote"
    /\ Faults \/ pending = NoFile \/ applied.v > pending.v
    /\ Fail(w)

\* publish_policy: *active_valid_until.write() = Some(valid_until).
Publish(w) ==
    /\ up
    /\ pc[w] \in {"publish", "publishSettled"}
    /\ activeUntil' = msg[w].until
    /\ pc' = [pc EXCEPT ![w] = IF pc[w] = "publish" THEN "notify" ELSE "notifySettled"]
    /\ UNCHANGED <<durable, world, msg, applyLock, cacheLock, loader>>

\* policy_version_tx.send, or rule_packs_version_tx.send.
Notify(w) ==
    /\ up
    /\ pc[w] = "notify"
    /\ notified' = TRUE
    /\ Finish(w)
    /\ UNCHANGED <<durable, world, cacheLock, reading, retry, live, loaded, activeUntil>>

\* The same send for a settled apply. This apply then goes on to its own check.
NotifySettled(w) ==
    /\ up
    /\ pc[w] = "notifySettled"
    /\ notified' = TRUE
    /\ pc' = [pc EXCEPT ![w] = "verify"]
    /\ msg' = [msg EXCEPT ![w] = NoFile]
    /\ UNCHANGED <<durable, world, applyLock, cacheLock, reading, retry, live, loaded, activeUntil>>

\* SignedFile::in_force, as reload calls it.
ReloadChoice == IF target # NoFile THEN "applied" ELSE "local"

\* policy_reload_task::run wakes, clears ctx.unfinished, and reload calls in_force.
\* A wake on this kind's channel consumes the change. The other kind's channel, the
\* rule-packs file watcher, and Request::ReloadPolicy wake it too, at any time, and
\* leave any change on this channel unseen.
ReloadCheck ==
    /\ up
    /\ reading = "no"
    /\ reading' = ReloadChoice
    /\ notified' \in {FALSE, notified}
    /\ retry' = FALSE
    /\ UNCHANGED <<durable, world, pc, msg, applyLock, cacheLock, live, loaded, activeUntil>>

\* A root tick finds ctx.unfinished not empty, and reload takes it and calls in_force.
\* A tick consumes no change.
ReloadRetry ==
    /\ up
    /\ retry
    /\ reading = "no"
    /\ reading' = ReloadChoice
    /\ retry' = FALSE
    /\ UNCHANGED <<durable, world, pc, msg, applyLock, cacheLock, notified, live, loaded, activeUntil>>

\* reload reads the chosen file. Rename makes that read atomic. A policy file that
\* was loaded and has gone missing keeps the previous state and waits for a retry. A
\* bundle that has gone missing is a deliberate removal, which read_bundle_state
\* reports as Absent.
ReloadRead ==
    /\ up
    /\ reading # "no"
    /\ LET file == IF reading = "applied" THEN target ELSE local
           keep == Kind = "policy" /\ file = NoFile /\ loaded
       IN  /\ live' = IF keep THEN live ELSE file
           /\ loaded' = IF keep THEN loaded ELSE (Kind = "policy" /\ file # NoFile)
           /\ retry' = keep
    /\ reading' = "no"
    /\ UNCHANGED <<durable, world, pc, msg, applyLock, cacheLock, notified, activeUntil>>

\* reload finds the file unusable: a read or parse error, a defaults() or merge error
\* after it, or a bundle that read_bundle_state reports as Corrupt or Empty. It keeps
\* what is live and notes the reason in ctx.unfinished.
ReloadReadFails ==
    /\ Faults
    /\ up
    /\ reading # "no"
    /\ reading' = "no"
    /\ retry' = TRUE
    /\ UNCHANGED <<durable, world, pc, msg, applyLock, cacheLock, notified, live, loaded, activeUntil>>

Tick ==
    /\ clock < MaxClock
    /\ clock' = clock + 1
    /\ UNCHANGED <<durable, up, crashes, pc, msg, applyLock, cacheLock, loader, activeUntil>>

LoseMemory ==
    /\ crashes < MaxCrashes
    /\ crashes' = crashes + 1
    /\ up' = FALSE
    /\ pc' = [w \in Workers |-> "idle"]
    /\ msg' = [w \in Workers |-> NoFile]
    /\ applyLock' = NoWorker
    /\ cacheLock' = NoWorker
    /\ notified' = FALSE
    /\ reading' = "no"
    /\ retry' = FALSE
    /\ live' = NoFile
    /\ loaded' = FALSE
    /\ activeUntil' = NoFile.until

\* The process dies. The operating system keeps every write it was handed.
Crash ==
    /\ up
    /\ LoseMemory
    /\ UNCHANGED <<durable, clock>>

\* The machine loses power. Only what reached the disk remains.
PowerCut ==
    /\ PowerCuts
    /\ LoseMemory
    /\ target' = savedTarget
    /\ applied' = savedApplied
    /\ pending' = savedPending
    /\ UNCHANGED <<savedTarget, local, savedApplied, savedPending, clock>>

\* The file system writes the rename out on its own schedule.
WriteBackFile ==
    /\ PowerCuts
    /\ savedTarget # target
    /\ savedTarget' = target
    /\ UNCHANGED <<target, local, applied, savedApplied, pending, savedPending, world, pc, msg, applyLock, cacheLock, loader, activeUntil>>

\* SQLite syncs the WAL on a checkpoint. Commits reach the disk in order, and at
\* most one commit is unsynced, because each later commit is a FULL record_pending.
WriteBackDb ==
    /\ PowerCuts
    /\ savedApplied # applied \/ savedPending # pending
    /\ savedApplied' = applied
    /\ savedPending' = pending
    /\ UNCHANGED <<target, savedTarget, local, applied, pending, world, pc, msg, applyLock, cacheLock, loader, activeUntil>>

\* runtime::run: settle_pending against the file in force, seed active_valid_until
\* from the applied envelope, load the file, then serve the control socket. An older
\* agent's row targets the local file, so the apply target would be the wrong one.
\* A settle or a check that fails stops the boot and changes nothing, so it is no
\* step. A stop after the settle is `Boot` then `Crash`.
Boot ==
    /\ ~up
    /\ SettleRow(InForce)
    /\ activeUntil' = IF Kind = "policy" THEN applied'.until ELSE NoFile.until
    /\ live' = InForce
    /\ loaded' = (Kind = "policy" /\ InForce # NoFile)
    /\ up' = TRUE
    /\ UNCHANGED <<target, local, savedApplied, savedPending, clock, crashes, pc, msg, applyLock, cacheLock, notified, reading, retry>>

\* The documented way back to the local file. This writer skips verify_envelope.
DeleteApplied ==
    /\ LocalEdits
    /\ target # NoFile
    /\ target' = NoFile
    /\ UNCHANGED <<savedTarget, local, applied, savedApplied, pending, savedPending, world, pc, msg, applyLock, cacheLock, loader, activeUntil>>

\* A save that unlinks before it writes, or an operator adding or removing the file.
EditLocal ==
    /\ LocalEdits
    /\ local' = IF local = NoFile THEN OperatorFile ELSE NoFile
    /\ UNCHANGED <<target, savedTarget, applied, savedApplied, pending, savedPending, world, pc, msg, applyLock, cacheLock, loader, activeUntil>>

Next ==
    \/ \E w \in Workers :
        \/ Settle(w)
        \/ \E e \in Envelopes : Verify(w, e)
        \/ Reject(w)
        \/ Record(w)
        \/ RecordFails(w)
        \/ Rename(w)
        \/ RenameFails(w)
        \/ Fsync(w)
        \/ FsyncFails(w)
        \/ Promote(w)
        \/ PromoteFails(w)
        \/ Publish(w)
        \/ Notify(w)
        \/ NotifySettled(w)
    \/ ReloadCheck
    \/ ReloadRetry
    \/ ReloadRead
    \/ ReloadReadFails
    \/ Tick
    \/ Crash
    \/ PowerCut
    \/ WriteBackFile
    \/ WriteBackDb
    \/ Boot
    \/ DeleteApplied
    \/ EditLocal

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

AllIdle == \A w \in Workers : pc[w] = "idle"

Quiet == up /\ AllIdle /\ pending = NoFile

\* The operator's file records nothing.
Recorded(file) == IF file.auth = "local" THEN NoFile ELSE file

\* The operator's file at the apply target comes only from `Starts`. No apply writes
\* it, and a power cut restores it only while the rename that replaced it is unsaved.
OnlySignedAccepted == target \in {NoFile, OperatorFile} \/ target.auth = "good"

NoExpiredApplied ==
    [][\A w \in Workers : (pc[w] = "verify" /\ pc'[w] = "record") => clock < msg'[w].until]_vars

VersionCheckHolds == \A w \in Workers : pc[w] \in {"record", "rename"} => msg[w].v > InForce.v

WatermarkNeverAhead == applied.v <= InForce.v

\* The version in force may fall only at a stop that leaves a pending row. Boot then
\* drops the row, and the applied version never claimed the lost file.
NoRollback == [][InForce'.v >= InForce.v \/ (~up' /\ pending' # NoFile)]_vars

\* A power cut may drop a promote only if the file and the row come back with it.
WatermarkMonotonic ==
    [][applied'.v >= applied.v \/ (~up' /\ pending' = InForce' /\ InForce'.v >= applied.v)]_vars

BootSettles == [][(~up /\ up') => (pending' = NoFile /\ applied' = Recorded(InForce'))]_vars

\* Spelled out, not `InForce`, so that a change to the read order cannot pass here.
\* While a retry is pending the live policy may lag, and only then.
LiveMatchesDisk ==
    (Quiet /\ ~notified /\ reading = "no" /\ ~retry) => live = IF target # NoFile THEN target ELSE local

ExpiryMatchesDisk == (Kind = "policy" /\ Quiet) => activeUntil = InForce.until

LoadedPolicyKept == [][(Kind = "policy" /\ up /\ up' /\ live # NoFile) => live' # NoFile]_vars

=============================================================================
