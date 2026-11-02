--------------------------- MODULE SignedPolicy ---------------------------
(***************************************************************************)
(* The agent's apply path for a signed policy envelope, across concurrent  *)
(* control-socket connections, agent crashes, and restarts. Any party may  *)
(* deliver any envelope, any number of times: each `Verify` picks freely   *)
(* from Envelopes. SKILL.md maps every action to the Rust it stands for.   *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    Workers,      \* one per connection: serve_until spawns a task for each
    MaxVersion,
    MaxClock,
    MaxCrashes,
    GapFaults,    \* TRUE allows a fault between Write and Bump
    NoWorker

Envelopes == [v : 1..MaxVersion, until : 1..MaxClock, auth : {"good", "bad"}]
NoFile == [v |-> 0, until |-> MaxClock + 1, auth |-> "none"]

VARIABLES
    disk,       \* policy.yaml, durable
    watermark,  \* host_meta.last_applied_policy_version, durable
    clock,
    up,         \* the agent process is running
    pc,         \* each worker's position in apply()
    msg,        \* the envelope each worker holds
    at,         \* the `now` each worker passed to verify_envelope
    holder,     \* the cache Mutex
    notified,   \* policy_version_tx has an unseen change
    live,       \* the policy the reload task last loaded
    crashes

vars == <<disk, watermark, clock, up, pc, msg, at, holder, notified, live, crashes>>

Init ==
    /\ disk = NoFile
    /\ watermark = 0
    /\ clock = 0
    /\ up = FALSE
    /\ pc = [w \in Workers |-> "idle"]
    /\ msg = [w \in Workers |-> NoFile]
    /\ at = [w \in Workers |-> 0]
    /\ holder = NoWorker
    /\ notified = FALSE
    /\ live = NoFile
    /\ crashes = 0

\* apply(): read the watermark under the lock, release it, run verify_envelope.
\* The verifier is pure, so this is one step. A rejected envelope changes nothing.
Verify(w, e) ==
    /\ up
    /\ pc[w] = "idle"
    /\ holder = NoWorker
    /\ e.auth = "good"
    /\ clock < e.until
    /\ e.v > watermark
    /\ pc' = [pc EXCEPT ![w] = "write"]
    /\ msg' = [msg EXCEPT ![w] = e]
    /\ at' = [at EXCEPT ![w] = clock]
    /\ UNCHANGED <<disk, watermark, clock, up, holder, notified, live, crashes>>

\* apply() retakes the lock. atomic_write: rename over policy.yaml.
Write(w) ==
    /\ up
    /\ pc[w] = "write"
    /\ holder = NoWorker
    /\ holder' = w
    /\ disk' = msg[w]
    /\ pc' = [pc EXCEPT ![w] = "bump"]
    /\ UNCHANGED <<watermark, clock, up, msg, at, notified, live, crashes>>

\* atomic_write: host_meta_set_policy_version. The lock is released after it.
Bump(w) ==
    /\ up
    /\ pc[w] = "bump"
    /\ watermark' = msg[w].v
    /\ holder' = NoWorker
    /\ pc' = [pc EXCEPT ![w] = "notify"]
    /\ UNCHANGED <<disk, clock, up, msg, at, notified, live, crashes>>

\* host_meta_set_policy_version fails: AtomicWriteError::StateAfterDisk.
BumpFails(w) ==
    /\ GapFaults
    /\ up
    /\ pc[w] = "bump"
    /\ holder' = NoWorker
    /\ pc' = [pc EXCEPT ![w] = "idle"]
    /\ msg' = [msg EXCEPT ![w] = NoFile]
    /\ at' = [at EXCEPT ![w] = 0]
    /\ UNCHANGED <<disk, watermark, clock, up, notified, live, crashes>>

\* apply(): policy_version_tx.send.
Notify(w) ==
    /\ up
    /\ pc[w] = "notify"
    /\ notified' = TRUE
    /\ pc' = [pc EXCEPT ![w] = "idle"]
    /\ msg' = [msg EXCEPT ![w] = NoFile]
    /\ at' = [at EXCEPT ![w] = 0]
    /\ UNCHANGED <<disk, watermark, clock, up, holder, live, crashes>>

\* policy_reload_task::reload re-reads policy.yaml. Rename makes that read atomic.
Reload ==
    /\ up
    /\ notified
    /\ live' = disk
    /\ notified' = FALSE
    /\ UNCHANGED <<disk, watermark, clock, up, pc, msg, at, holder, crashes>>

Tick ==
    /\ clock < MaxClock
    /\ clock' = clock + 1
    /\ UNCHANGED <<disk, watermark, up, pc, msg, at, holder, notified, live, crashes>>

\* Memory is lost. disk and watermark survive.
Crash ==
    /\ up
    /\ crashes < MaxCrashes
    /\ GapFaults \/ \A w \in Workers : pc[w] # "bump"
    /\ up' = FALSE
    /\ pc' = [w \in Workers |-> "idle"]
    /\ msg' = [w \in Workers |-> NoFile]
    /\ at' = [w \in Workers |-> 0]
    /\ holder' = NoWorker
    /\ notified' = FALSE
    /\ live' = NoFile
    /\ crashes' = crashes + 1
    /\ UNCHANGED <<disk, watermark, clock>>

\* reconcile_policy_on_boot reads the `version:` key of policy.yaml, then the
\* agent loads the file. parse() requires that key to be 1.
Boot ==
    /\ ~up
    /\ LET documentVersion == IF disk = NoFile THEN 0 ELSE 1
       IN  watermark' = IF documentVersion > watermark THEN documentVersion ELSE watermark
    /\ live' = disk
    /\ up' = TRUE
    /\ UNCHANGED <<disk, clock, pc, msg, at, holder, notified, crashes>>

Next ==
    \/ \E w \in Workers :
        \/ \E e \in Envelopes : Verify(w, e)
        \/ Write(w)
        \/ Bump(w)
        \/ BumpFails(w)
        \/ Notify(w)
    \/ Reload
    \/ Tick
    \/ Crash
    \/ Boot

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

OnlySignedAccepted == disk = NoFile \/ disk.auth = "good"

NoExpiredApplied == \A w \in Workers : pc[w] = "write" => at[w] < msg[w].until

WatermarkNeverAhead == watermark <= disk.v

AllIdle == \A w \in Workers : pc[w] = "idle"

LiveMatchesDisk == (up /\ AllIdle /\ ~notified) => live = disk

NoRollback == [][disk'.v >= disk.v]_vars

WatermarkMonotonic == [][watermark' >= watermark]_vars

=============================================================================
