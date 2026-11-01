# Status

`lodeline status` prints one snapshot of the host: which Lodeline binaries are installed, whether the agent answers on its control socket, and whether a sender config makes this a fleet host. It always exits `0`, and it never prints the userinfo, path, or query of a server URL.

## Sub-features

- `status-text` prints the component rows, the agent row, and the fleet row.
- `status-json` prints the same snapshot with `--json`.
- `status-agent-stopped` reports `agent: stopped` when nothing answers on the control socket.
- `status-fleet-none` reports `fleet: not configured` when no sender config exists.
- `status-fleet-configured` reads `server_base_url` from `--sender-config` and keeps only scheme, host, and port.
- `status-fleet-unreadable` reports a config with no usable URL, a FIFO, or a file over 1 MiB as `cannot read`.
- `status-no-secret` keeps URL userinfo and tokens out of stdout and stderr.

## How to get to it (user POV)

- Run `lodeline status` in a terminal.
- Run `lodeline status --json` in a script.
- Run `lodeline status --sender-config <path>` to read the fleet link from a given sender config.
- Run `lodeline --control-socket <path> status` to ask a given socket instead of the default one. The flag goes before `status`.

## Driving it with drive.sh

Preconditions:

- `drive.sh doctor "$RUN"` exits 0.
- No sender config exists under the temp HOME or `$XDG_CONFIG_HOME`.

- **Text.** Run `drive.sh run "$RUN" status-text -- lodeline status`. Exit code `0`. Stdout starts with `Lodeline status <version>` and holds one row each for `lodeline`, `lodeline-sender`, `lodeline-hook`, and `lodeline-mcp`, then an `agent:` row and `[INFO] fleet: not configured (single host)`.
- **JSON.** Run `drive.sh run "$RUN" status-json -- lodeline status --json`. Exit code `0`. `.stdout` holds `"schema_version": 1`, an `"agent"` object, and `"fleet": {` with `"state": "not_configured"`.
- **Agent stopped.** Run `drive.sh run "$RUN" status-stopped -- lodeline --control-socket ../c.sock status`. Stdout holds `[WARN] agent: stopped (start it with `lodeline run`)`. The path is relative so the socket path stays under the OS limit.
- **Seed sender configs.** Run `drive.sh run "$RUN" status-seed -- sh -c 'printf "server_base_url: \"https://svc:hunter2@srv.example:8443/base?token=tok-SECRET-123\"\n" > ../home/sender.yaml; printf "other: 1\n" > ../home/nourl.yaml; mkfifo ../home/fifo.yaml; yes aaaaaaaaaaaaaaa | head -c 1100000 > ../home/big.yaml'`. Exit code `0`.
- **Configured.** Run `drive.sh run "$RUN" status-configured -- lodeline --control-socket ../c.sock status --sender-config ../home/sender.yaml`. Stdout holds `[INFO] fleet: lodeline-server https://srv.example:8443 (from ../home/sender.yaml, link state unknown)`.
- **Configured, JSON.** Run `drive.sh run "$RUN" status-configured-json -- lodeline --control-socket ../c.sock status --json --sender-config ../home/sender.yaml`. `.stdout` holds `"state": "configured"` and `"server_url": "https://srv.example:8443"`.
- **No URL.** Run `drive.sh run "$RUN" status-nourl -- lodeline --control-socket ../c.sock status --sender-config ../home/nourl.yaml`. Exit code `0`. Stdout holds `[WARN] fleet: cannot read ../home/nourl.yaml: no usable server_base_url`.
- **FIFO.** Run `drive.sh run "$RUN" status-fifo -- lodeline --control-socket ../c.sock status --sender-config ../home/fifo.yaml`. It returns without hanging. Stdout holds `cannot read ../home/fifo.yaml: not a regular file`.
- **Oversize.** Run `drive.sh run "$RUN" status-big -- lodeline --control-socket ../c.sock status --sender-config ../home/big.yaml`. Stdout holds `cannot read ../home/big.yaml: larger than 1 MiB`.
- **No secret.** Run `drive.sh run "$RUN" status-leak -- sh -c 'grep -l "hunter2\|SECRET" ../../evidence/status-*.stdout ../../evidence/status-*.stderr || echo no-secret-in-output'`. Stdout is `no-secret-in-output`. Do not grep `status-seed.cmd`, which holds the fixture on purpose.

## Gotchas

- Without `--control-socket`, `status` on macOS reports `agent: unreachable: ... path must be shorter than SUN_LEN`. The default socket sits under the long scratch path. This is a path limit, not a daemon fault. Use the relative socket above to reach `stopped`.
- `agent: running` and the `signed policy` row need a live daemon. The skill forbids `lodeline run`, so the running state is proved only by `cargo test -p lodeline-agent` and `cargo test -p lodeline-diag`, never here.
- `status` finds binaries through the `PATH` of the `env -i` run, which is `target/debug`, `/usr/bin`, and `/bin`. The `[OK]` rows therefore show real install paths of this checkout, and `lodeline-hook` shows `version unknown`. `lodeline-sender` and `lodeline-mcp` show `not found` because `drive.sh new` does not build them.
- `.stdout` holds those real paths. Replace them before you quote it.
- `--sender-config` replaces the default candidates. The default config location is not probed in these recipes.
