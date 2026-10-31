# Operations notes

## Default paths

| Item        | macOS                              | Windows                              |
|-------------|------------------------------------|--------------------------------------|
| Binary      | /usr/local/bin/lodeline            | %PROGRAMFILES%\Lodeline\lodeline.exe |
| Policy      | /etc/lodeline/policy.yaml          | %ProgramData%\Lodeline\policy.yaml   |
| Events      | /var/log/lodeline/                 | %ProgramData%\Lodeline\events\       |
| State       | /var/lib/lodeline/state.db         | %ProgramData%\Lodeline\state.db      |
| Service id  | com.lodeline.agent (launchd label) | Lodeline (Windows Service name)      |
| Control IPC | /var/run/lodeline/control.sock     | \\.\pipe\lodeline-control            |

## Signal handling

- Unix `SIGINT` / `SIGTERM`, Windows Ctrl-C: stop event producers and new IPC
  connections, drain queued pipeline events, durably flush JSONL, and exit 0.
- Accepted IPC requests have up to five seconds to finish. Stalled requests
  are cancelled and cause a nonzero exit; Unix socket files are removed.
- The overall graceful drain has a 30-second deadline. Timeout or sink failure
  returns nonzero, not a successful flush. Runtime teardown gets one additional
  second for blocking workers.
- A pipeline panic triggers cancellation immediately and a best-effort
  `AgentDying` event before sink closure; exit 101 unless draining times out.
- Use `lodeline reload` for policy reload. `SIGHUP` is not a reload interface.

## Watch-root recovery

- Missing or replaced roots are retried every five seconds. Nonrecursive
  patterns such as `/Applications/*.app/Contents/Info.plist` resolve only
  matching directory components; discovery does not recursively watch all of
  `/Applications`. Symlink directories below a wildcard are not followed.
- After registration, current files are replayed through normal filtering and
  hashing. This recovers current state, not historical changes that occurred
  and disappeared while the root was unavailable. Native and polling backends
  share this behavior; policy reload removes obsolete subscriptions.

## Logs

- JSONL events: as configured above. SIEM consumes.
- Diag log: `tracing` to stderr (captured by launchd / Windows Event Log).
  Configure level via `LODELINE_LOG=debug,lodeline_core=info`.
