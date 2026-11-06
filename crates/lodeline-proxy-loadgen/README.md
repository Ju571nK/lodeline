# lodeline-proxy-loadgen

Test tooling for the Lodeline Proxy performance targets in
[validation.md](../../docs/specs/lodeline-proxy/validation.md). It is not shipped: release archives and OS packages
list their binaries by name, and this crate is not among them.

One binary, three subcommands:

- `serve` runs a synthetic upstream MCP server (Streamable HTTP, revision 2025-11-25, JSON answers). Its one tool,
  `load_echo`, answers `echo:<marker>` and pads the reply to the size the call asks for. `GET /_load/counters` reports
  how many calls it answered.
- `principals` writes N principal tokens, the proxy config that holds their verifiers, and a targets file for the driver.
- `run` drives load at the load server directly and through the proxy, and reports latency, throughput and errors.

[`stack.sh`](stack.sh) sets up a throwaway single-host stack around these:
test PKI, `lodeline-server` as the local control-plane collector, the proxy, and the load server, all on loopback.

## What a run measures

Each lane is one MCP session of one principal: `initialize`, `notifications/initialized` and one `tools/list`, then
`tools/call load_echo` on that session. The direct side opens the same number of sessions on the load server, so both
sides have the same shape.

- **Open loop** (`--rate R --concurrency C`). Call `n` is due at `start + n / R`. Each call is its own task, so a slow
  call never delays the start of the next one. A call waits for a slot of its lane, and that wait counts as latency.
  The lane slots add up to `C`. Latency starts when the call task runs. The delay between the due time and that
  moment comes from the driver's own timer and scheduler. It is reported apart as `send_lag_ms`. `latency_from_due_ms`
  starts at the due time instead, send lag included, so driver lag that grows under CPU contention with the proxy is
  not hidden. When a run's send lag p99 is over 1 ms the summary warns, and the two latencies should be compared.
- **Closed loop** (`--concurrency C` without `--rate`). `C` workers each send the next call when the last one is
  answered. The `ok_per_s` result is the sustainable throughput at that concurrency.
- **Rounds.** Each round runs both sides with fresh sessions. Odd rounds run direct first, even rounds proxied first,
  so neither side always runs first. `round_order` in the report records the order. Each run has a warm-up
  (`--warmup`). Calls due in the warm-up are sent and checked but not measured.
- **Every reply is checked.** A call is `ok` only when the reply is HTTP 200 and the JSON-RPC result echoes the call's
  own id and marker. Everything else gets a class: `http_<status>_<code>` for the proxy's
  `{"error":"<code>"}` answers (`http_429_too_many_requests`, `http_503_audit_unavailable`), `http_<status>` for other
  statuses, `jsonrpc_error_<code>`, `bad_reply`, `timeout` and `transport`. Latency percentiles use `ok` calls and
  timeouts. A timeout counts at its elapsed time, which is at least `--timeout`, so with timeouts p99 and max are lower
  bounds and the summary warns. Other errors are counted next to the latency, not in it: a 429 answers at once and
  would pull the percentiles down.
- **Upstream check.** The driver reads the load server's counters before and after each run. `upstream_tools_calls`
  must equal `ok_all` (successful replies, warm-up included). A difference means a call reached the upstream without
  a good reply, or one reply came without a call.
- **Added latency** is the proxied quantile minus the direct quantile of the same round (p50, p95, p99, max), for both
  latencies. The summary gives the median and range over rounds. This compares two distributions. It is not the added
  time of any single call.
- **Exit status.** `run` exits non-zero when any measured call failed or any run's upstream count differs from its
  `ok_all`. The report is still written. `--allow-errors` accepts measured errors, for runs meant to hit a limit
  (429). An upstream mismatch fails in every case.

Percentiles come from an HDR histogram in microseconds with 3 significant digits. A reported value is the upper
end of its bucket, at most 0.1% above the recorded value.

## Principals

The proxy authenticates each downstream client by a static 256-bit bearer token. The proxy config, which the proxy
fetches from `lodeline-server`, holds only the token's SHA-256 verifier (control-plane.md 5.1 and 5.2). The proxy
admits at most 8 calls in flight per principal, 16 per route and 64 in total (validation.md D-04). It refuses the next
one with 429 at once, because the queue depth is 0. One principal can therefore never carry concurrency 32.

`principals --principals N --routes R` writes:

- `tokens/load-p<i>.token`: one token per principal, mode 0600 on Unix. On Windows the file gets the directory's
  default permissions. Tokens stay on the load host.
- `config.json`: the `config` object for `PUT /v1/proxies/{id}/config`. It has routes `load-r0..` to the load server
  and principals `load-p0..`, each with its verifier. Principal `i` may use only route `i % R`.
- `targets.json`: one lane per principal, with the route URL and the token file.

The driver gives each lane `C / lanes` slots, spread evenly. At concurrency `C`, use at least `C / 8` principals over
at least `C / 16` routes. The defaults (8 principals, 4 routes) cover concurrency 1 to 32 below every limit. At 64
they put exactly 8 calls on each principal and 16 on each route, the limits themselves, so use `PRINCIPALS=16
ROUTES=8`. Concurrency 64 still equals the proxy's total limit.

## Commands

Build once:

```sh
cargo build --release --locked -p lodeline-server -p lodeline-proxy -p lodeline-proxy-loadgen
```

Start the stack. The state directory holds the spool, so put it on the disk under test:

```sh
STATE_DIR=/var/tmp/lodeline-load-state crates/lodeline-proxy-loadgen/stack.sh up /tmp/lodeline-load
```

Fixed offered load, as validation.md asks (100 calls/s, concurrency 32, 30 s warm-up, 300 s measured, 3 alternating
rounds, 1 KiB request, 4 KiB reply):

```sh
target/release/lodeline-proxy-loadgen run \
  --direct http://127.0.0.1:18090/mcp --targets /tmp/lodeline-load/load/targets.json \
  --rate 100 --concurrency 32 --warmup 30 --duration 300 --rounds 3 \
  --note "commit, host class, kernel, filesystem" --out open-100-c32.json
```

Throughput sweep, closed loop, one run per concurrency (start the stack with `PRINCIPALS=16 ROUTES=8` for 64):

```sh
for c in 1 8 32 64; do
  target/release/lodeline-proxy-loadgen run \
    --direct http://127.0.0.1:18090/mcp --targets /tmp/lodeline-load/load/targets.json \
    --concurrency $c --warmup 30 --duration 300 --rounds 3 --out closed-c$c.json
done
```

The summary goes to stdout, the full report to `--out`. Read the proxy's resource use while it runs or at the end,
then stop everything. `down` deletes the work directory, so keep reports outside it. `down` stops only the processes
this stack started, by the pids `up` recorded in `WORK/run` and the proxy's config path. A failed `up` runs `down`
itself.

```sh
crates/lodeline-proxy-loadgen/stack.sh stats /tmp/lodeline-load
crates/lodeline-proxy-loadgen/stack.sh down /tmp/lodeline-load
```

### The proxy cgroup on Linux

validation.md runs the proxy in a 2 vCPU / 512 MiB cgroup, and the load server, the driver and the collector on the
other CPUs. On a 4 vCPU host with systemd, start the proxy in a transient scope and pin the rest with `taskset`:

```sh
PROXY_WRAP="sudo systemd-run --scope --quiet --unit=lodeline-proxy-load --uid=$(id -u) --gid=$(id -g) \
  -p MemoryMax=512M -p MemorySwapMax=0 -p AllowedCPUs=0,1 --" \
LOAD_WRAP="taskset -c 2,3" \
STATE_DIR=/var/tmp/lodeline-load-state crates/lodeline-proxy-loadgen/stack.sh up /tmp/lodeline-load

taskset -c 2,3 target/release/lodeline-proxy-loadgen run ...
```

`stack.sh stats` then also prints the scope's `memory.peak`, where the kernel has it, and `cpuset.cpus.effective`.
`VmHWM` is the proxy's peak RSS in every case. Record CPU model, kernel, filesystem, commit and limits with each
report (`--note`), as validation.md asks.

## Report

`--out` writes `lodeline-proxy-loadgen.report/1` JSON. It has the run parameters, `env` (OS, arch, CPU count), and
for each run: `side`, `round`, `lanes`, `sent`, `measured`, `ok`, `ok_per_s`, `errors`, `warmup_errors`,
`latency_ms` (`count`, `min`, `mean`, `p50`, `p90`, `p95`, `p99`, `p999`, `max`), `latency_from_due_ms`,
`send_lag_ms`, `upstream_tools_calls` and `ok_all`. It also has `round_order`, `added` per round (`added_ms` and
`added_from_due_ms`), `added_summary` and `added_from_due_summary` (median, min and max over rounds), and
`warnings`.

## Limits

- Plain HTTP on loopback only. The TLS listener comparison that validation.md asks for is a separate measurement.
- No SSE, no large bodies, no limit+1 cases, no outage runs (validation.md steps 3 and 4).
- One session per lane for the whole run. A session the proxy ends (idle 15 minutes, restart) is not reopened. Its
  calls then fail as `http_404` and show in the errors.
- CPU, RSS and FD counts come from `stack.sh stats`, not from the driver.
