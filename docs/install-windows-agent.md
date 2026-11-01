# lodeline agent — Install Guide (Windows)

The `lodeline` agent watches AI-tool config and posture files (MCP allowlists,
credential files, agent settings, …), hashes them, and emits **JSONL posture
events**. It measures; it does not block. Events can be read locally, or shipped
to a [`lodeline-server`](install-server.md) by the companion `lodeline-sender`.

On Windows the agent uses a **named pipe** (`\\.\pipe\lodeline-control`) for its
control IPC and stores state under `%ProgramData%\Lodeline` by default. It builds
and runs natively on both **x64** and **ARM64** Windows.

---

## 1. Install

### For end users — download the prebuilt binary (recommended)

**Download `lodeline.exe` from [GitHub Releases](https://github.com/Ju571nK/lodeline/releases)
and run it. That is the whole story.**

- **No Rust, no Visual Studio, no compiler** is required to *run* the agent.
- Binaries are published by CI for both architectures:
  - `lodeline-x86_64-pc-windows-msvc.exe` — the vast majority of Windows PCs.
  - `lodeline-aarch64-pc-windows-msvc.exe` — ARM devices (Surface Pro X, ARM laptops).
- Release binaries are built with a **static CRT** (`-C target-feature=+crt-static`),
  so the `.exe` is self-contained — no Visual C++ Redistributable needed.

The toolchain in the next section is **build-time only** (developers / CI).
End users never touch it. Until a Windows release is published, build from
source as below.

### For developers — build from source

One-time toolchain setup:

1. **Rust** — install via [rustup](https://rustup.rs). The default host triple is
   `x86_64-pc-windows-msvc` (or `aarch64-pc-windows-msvc` on ARM). MSRV 1.88+.
2. **MSVC toolchain** — Visual Studio Build Tools 2022 with the C++ workload
   (the MSVC compiler/linker + Windows SDK). On ARM64 also add the ARM64 build
   tools. From an **elevated** PowerShell:

   ```powershell
   & "C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe" modify --installPath "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.ARM64 --includeRecommended --passive --norestart
   ```

   (`Microsoft.VisualStudio.Workload.VCTools` = C++ build tools + Windows SDK;
   `Microsoft.VisualStudio.Component.VC.Tools.ARM64` = ARM64 target. A reboot may
   be requested — installer exit code `3010` means *success, reboot to finalize*.)

Then build:

```powershell
cargo build --release -p lodeline-agent   # → target\release\lodeline.exe
```

For a self-contained, redistributable binary (no VC++ runtime dependency):

```powershell
$env:RUSTFLAGS = "-C target-feature=+crt-static"
cargo build --release -p lodeline-agent
```

---

## 2. Configure — Windows default paths

A policy file is optional — built-in defaults apply if absent. The agent uses
these Windows-specific default locations:

| Item | Windows default |
|---|---|
| state.db | `%ProgramData%\Lodeline\state.db` |
| events dir | `%ProgramData%\Lodeline\events` |
| control IPC | named pipe `\\.\pipe\lodeline-control` |
| keystore | `%LOCALAPPDATA%\Lodeline\policy-signing-pubkeys.pem` |

Override any of them on the command line:

```powershell
lodeline --state-db C:\lodeline\state.db --events-dir C:\lodeline\events run
```

`%ProgramData%` resolves to `C:\ProgramData`; writing there needs an elevated
context. Running as your own (non-admin) user, point `--state-db` /
`--events-dir` at a writable path.

---

## 3. Run

### Foreground (testing)

```powershell
lodeline doctor                 # check effective config first
lodeline run
```

```powershell
lodeline status                 # components, agent, fleet link; add --json for the data
lodeline show config            # merged effective policy
lodeline show paths             # expanded watch paths
lodeline show risk              # AI Guard risk score per detected AI tool
lodeline show stats             # live heartbeat from the running agent
```

Set the diagnostic log level with `LODELINE_LOG` (e.g. `$env:LODELINE_LOG = "debug"`).

> **Persistent service (Windows Service / Scheduled Task):** TBD — documented
> after validation on the 2-machine test. The agent runs as a normal console
> process today.

---

## 4. Ship events to a server / keystore

`lodeline-sender`, `host_id`, and the keystore are cross-platform — see
[install-macos-agent.md §6–§8](install-macos-agent.md). On Windows the
`sender.yaml` `agent_control` must be the named pipe `\\.\pipe\lodeline-control`
(not a Unix socket path).

---

*Windows path defaults reflect the agent's `default_state_db_path`,
`default_events_dir`, control-pipe, and keystore resolution. Build-from-source
toolchain reference: Rust 1.95 + VS Build Tools 2022 (MSVC 14.44, Windows SDK
10.0.26100). Validated end-to-end (build → run → host_id → native
`read_directory_changes_w` watcher → JSONL events) on Windows 11 ARM64,
2026-05-25.*
