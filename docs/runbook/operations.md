# Operations notes

## Default paths

| Item        | macOS                              | Windows                              |
|-------------|------------------------------------|--------------------------------------|
| Binary      | /usr/local/bin/lodeline            | %PROGRAMFILES%\Lodeline\lodeline.exe |
| Policy      | /etc/lodeline/policy.yaml          | %ProgramData%\Lodeline\policy.yaml   |
| Applied     | /var/lib/lodeline/applied/         | the Policy file itself               |
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
- A watch path is matched as a glob against the file an event names. A folder
  path such as `~/.claude/hooks/` matches the folder itself and never a file in
  it; write `~/.claude/hooks/*` to watch the files below it (`*` also crosses
  folder separators, and `**` is rejected at policy load). This holds for every
  pattern you write. The built-in skills and scheduled tasks entries, such as
  `~/.claude/skills/*/SKILL.md`, are the exception: their `*` stands for one
  folder, so `skills/<name>/node_modules/x/SKILL.md` does not match them.
  A watched file or skill folder that is itself a symbolic link is followed, and an edit of
  its target records a file change under the link's path. An agent that runs as root or as a
  Windows service, or that expands paths for several users, follows such a link only when its
  target belongs to the same account as the link (on Windows, when it lies under the home that
  holds the link), and logs one warning for a link it refuses.
- After registration, current files are replayed through normal filtering and
  hashing. This recovers current state, not historical changes that occurred
  and disappeared while the root was unavailable. Native and polling backends
  share this behavior; policy reload removes obsolete subscriptions.

## Logs

- JSONL events: as configured above. SIEM consumes.
- Diag log: `tracing` to stderr (captured by launchd / Windows Event Log).
  Configure level via `LODELINE_LOG=debug,lodeline_core=info`.
