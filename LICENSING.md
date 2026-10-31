# Lodeline Licensing & Module-Split Policy

This document describes which parts of Lodeline are open source under
[Apache License 2.0](LICENSE), and which parts are distributed separately —
as signed rule-pack bundles, separate repositories, or hosted services. It is
the canonical reference when adding new modules or rule packs.

The rule is simple: the **detection mechanism** lives here, open and
auditable. **Detection content** — rule knowledge, threat-intel, upstream
integrations — is distributed separately and verified by that mechanism.

---

## Open source (Apache 2.0)

These modules are public and accept community contributions:

| Crate / module                                    | Role                                             |
| ------------------------------------------------- | ------------------------------------------------ |
| `crates/lodeline-core`                              | Event schema, policy types, signing primitives   |
| `crates/lodeline-agent`                             | Daemon runtime, file watcher, IPC, GC, heartbeat |
| `crates/lodeline-spool`                             | Generic JSONL spool (producer/consumer/GC)       |
| `crates/lodeline-rules-basic`                       | Baseline detection ruleset (macOS + Windows)     |
| `crates/lodeline-core/src/sink/jsonl.rs`            | JSONL output sink                                |
| `crates/lodeline-core/src/policy/verify.rs`         | Signed-policy verification chain                 |
| `crates/lodeline-core/src/policy/canonical.rs`      | RFC 8785 canonical JSON for signature input      |
| `crates/lodeline-core/src/policy/atomic_writer.rs`  | Crash-safe policy.yaml + state.db commit         |
| `crates/lodeline-agent/src/policy_apply.rs`         | apply_policy IPC handler                         |
| `crates/lodeline-agent/src/normalizer.rs`           | Default event normalizer/classifier              |
| `crates/lodeline-agent/src/cli.rs`                  | CLI surface                                      |
| All Phase 1+ tests                                | Integration + property tests                     |

**Why these stay open**: trust in a security daemon depends on operators
being able to audit *how* events are captured, *how* policies are
verified, and *how* data is persisted. Mechanism transparency builds
that trust. Open contributors also accelerate platform support and
edge-case fixes.

## Distributed separately (not in this repository)

These deliverables are **not** part of the public repository and ship as
either signed policy bundles, separate private crates, or hosted
services. The choice depends on integration depth.

| Deliverable                  | Form                            | Notes                                          |
| ---------------------------- | ------------------------------- | ---------------------------------------------- |
| Extended detection rule pack | `lodeline-rules-pro` (private)    | Shadow AI, MCP/IDE configs, SaaS agents, etc.  |
| Enterprise rule packs        | Signed policy bundle (Phase 2)  | Verified via `lodeline-core::policy::verify`     |
| `lodeline-sender`              | Binary release (Plan B)         | Signs + ships envelopes to fleet               |
| Hosted policy service        | Cloud service                   | Enterprise rule distribution + telemetry       |
| SIEM / EDR connectors        | Separate private crates         | One per upstream (Splunk/Sentinel/CrowdStrike) |

**Why these are separate**: this repository carries the *mechanism* — the code
that captures, verifies, persists, and enforces. Detection *content* is
distributed as signed bundles that the mechanism verifies (see below), on its
own cadence and from its own sources. Separating the two keeps the mechanism
auditable by operators and lets content ship without an agent rebuild. The
same split is standard in security tooling (cf. Falco/Sysdig, Snort/Talos,
Suricata/ET Pro).

**Trust boundary by distribution form**: Personal installs use *unsigned* local
rule packs distributed via git — trust derives from the git repository (the pack
carries enforcement authority via `hook_deny_rules`; only apply packs from repos
you trust). Fleet installs use *signed* policy bundles verified by the OSS agent
via `verify_envelope` before any pack is applied.

---

## Decision rule for new modules

When adding a new file or crate, ask:

1. **Does it implement a verification, transport, or storage mechanism?**
   → Open source. Auditability matters more than competitive advantage.

2. **Does it encode detection knowledge (rule strings, paths, regexes,
   ML models, threat-intel)?**
   → Closed if it represents non-trivial research or customer value;
   open otherwise (e.g. trivial single-target watch rules belong in
   `lodeline-rules-basic`).

3. **Does it integrate with an enterprise upstream (SIEM, IdP, ticketing)?**
   → Closed (separate private crate or service).

Publishing is one-way: code released under Apache-2.0 stays available under
Apache-2.0 in the versions it shipped in, and a later decision to close it
does not retract those. So settle the boundary before the first release, not
after. When rule 1 applies, open it deliberately.

---

## How signed policy packs replace the old "monolithic binary" approach

Plan A (already merged) shipped:

- `SignedEnvelope` + RFC 8785 canonical JSON ([signed_envelope.rs](crates/lodeline-core/src/policy/signed_envelope.rs), [canonical.rs](crates/lodeline-core/src/policy/canonical.rs))
- 5-check `verify_envelope` chain ([verify.rs](crates/lodeline-core/src/policy/verify.rs))
- Pubkey keystore loader ([pubkeys.rs](crates/lodeline-core/src/policy/pubkeys.rs))
- `apply_policy` IPC handler ([policy_apply.rs](crates/lodeline-agent/src/policy_apply.rs))
- Atomic disk + state.db commit ([atomic_writer.rs](crates/lodeline-core/src/policy/atomic_writer.rs))

Together these form a **signed policy bundle pipeline**: a private
`lodeline-rules-pro` build can ship as a signed YAML that the OSS agent
applies via the same code path operators audit. No `.dylib`/`.dll`
plugin loading, no Rust ABI boundary, no commercial-only code paths in
the daemon binary itself.

This is the recommended distribution form for closed rule packs.

---

## Repository layout commitments

- The `main` branch is and remains Apache 2.0.
- Closed content lives in **separate repositories** (e.g.
  `lodeline-rules-pro`), never as `.gitignored` files in this tree.
- `lodeline-rules-basic` is the boundary marker: anything more specialized
  than its baseline targets is a candidate for the closed track.

---

## Distributing the pro rule pack — signed bundles, not build linking

The OSS daemon does **not** link `lodeline-rules-pro` at build time. We
considered a Cargo `pro` feature gated behind a private git dep, but
Cargo records every conditional dep in `Cargo.lock` and tries to fetch
on every build, which (a) breaks OSS CI on forks/PRs without SSH access
to the private repo and (b) leaks the private URL into a public lock
file. The cleaner architecture — already enabled by Plan A — is to ship
extended rule packs as **signed policy bundles**.

**The pipeline (already shipped in Plan A)**:
1. `lodeline-rules-pro` (private repo) holds the YAML rule sources.
2. A signing tool (Plan B `lodeline-sender` companion) wraps a YAML
   payload in a [`SignedEnvelope`](crates/lodeline-core/src/policy/signed_envelope.rs)
   using a private ed25519 key.
3. `lodeline-sender` (Plan B) ships the envelope to fleet hosts over the
   Phase 2 transport (mTLS + apply_policy IPC).
4. The OSS agent verifies via [`verify_envelope`](crates/lodeline-core/src/policy/verify.rs)
   (5-check chain), commits via [`atomic_write`](crates/lodeline-core/src/policy/atomic_writer.rs),
   and emits `PolicyReloaded` — all paths operators can audit.

**Why this is better than build-time linking**:
- OSS binary stays trivially reproducible — one artifact, no secret deps.
- Rule pack iteration doesn't require an agent rebuild — push a signed
  YAML and the live fleet picks it up.
- Customer-specific rule packs are possible without a per-customer build.
- Aligns with the open-mechanism / closed-content split this document
  describes — the signing key is the only secret the daemon needs to
  trust.

**Status**: `lodeline-rules-pro` repo holds the rule YAML sources today
([github.com/Ju571nK/lodeline-rules-pro](https://github.com/Ju571nK/lodeline-rules-pro)).
The signer + sender pieces land in Plan B; until then the YAML is only
consumed via the signed-bundle test fixtures used by `verify.rs`.

---

## Audit log tamper-evidence (and its limits)

Earlier `lodeline-server` releases appended a signed, hash-chained
`license-audit.jsonl` to the server state directory: each line is an
ed25519-signed record whose `prev_hash` links to the previous line. Current
releases no longer write new records to it. An existing chain is kept as-is
and stays verifiable: the server reads its last line at startup and still
exposes that head at `GET /v1/meta` (`audit_head`), and the record format is
frozen so old chains keep verifying. The verification logic lives in OSS
`lodeline-core::audit`; anyone can check a chain with
`lodeline-sign verify-audit --in <file> --pubkey ed25519:<b64>` (add
`--expect-head <hash>` to assert against a head recorded earlier).
`audit_head.pubkey` is included only when the server's current key signed the
head; if the key has changed since, only `pubkey_id` is reported and the
matching public key must be supplied to the verifier.

The same signing key and primitives also sign the enrollment audit log
(`enrollment-audit.jsonl`, a separate chain with its own record shape).

**What it proves.** Any edit, reordering, deletion, or truncation of the log
breaks a hash or a signature and is detected by the verifier. This fully covers
third-party tampering and accidental corruption.

**What it does NOT prove.** The signing key is auto-generated on the server's
own host, so a determined operator who controls that host can re-sign a forged
chain. The operator is bound only for history *before an externally-observed
head*: the signed head is exposed at `GET /v1/meta` (`audit_head`), and any
external party (monitoring, lodeline-manager, an auditor) that records a head
pins the operator to that history. Capture heads off-box to anchor the chain.
Because no new records are appended, the head of an existing chain no longer
advances.

This is corroborating evidence, not automatic proof. Automatic push-anchoring
and public timestamping are future work.

## Build self-verification (and its limits)

`lodeline doctor --verify-self` hashes the running binary with blake3 and checks it
against a vendor-signed build manifest (`lodeline-sign manifest`), verified with the
compiled-in `LODELINE_BUILD_PUBKEYS` trust anchor. The verification logic lives in OSS
`lodeline-core::manifest`.

**What it catches.** Accidental corruption, in-place/partial tampering, version and
architecture drift, and naive swaps that didn't re-sign — provided the embedded
trust anchor and verifier are intact.

**What it does NOT prove.** The trust anchor is compiled into the binary, so an
attacker who fully replaces the binary can also replace `LODELINE_BUILD_PUBKEYS` and the
verifier itself. Pair this with the externally-anchored, harder-to-forge
`gh attestation verify` (Sigstore-backed build provenance) for defense in depth.

This slice ships the mechanism; `LODELINE_BUILD_PUBKEYS` is empty until a signed release
populates it.
