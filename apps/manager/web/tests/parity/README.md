# Parity recorder

The parity suite sends a fixed table of HTTP requests to a `lodeline-manager` binary and compares
each normalized response with a golden file. The goldens were recorded from the Go implementation
at `Ju571nK/lodeline-manager@e4fb077`, except the ones listed under "Goldens recorded from the
Rust build" below. The Rust port does not have to match Go; the suite is a regression check, so a
run shows every place where the port answers differently from the recorded behavior.

The table has 229 cases over 19 routes: the 18 API routes of the Go router plus the SPA
catch-all. The suite prints the count per route on every run.

| Cases | Route |
|---:|---|
| 4 | `GET /api/health` |
| 29 | `POST /api/v1/auth/login` |
| 2 | `GET /api/v1/auth/methods` |
| 3 | `GET /api/v1/auth/oidc/start` |
| 2 | `GET /api/v1/auth/oidc/callback` |
| 4 | `POST /api/v1/auth/logout` |
| 27 | `GET /api/v1/auth/me` |
| 6 | `GET /api/v1/fleet/meta` |
| 4 | `GET /api/v1/fleet/healthz` |
| 38 | `GET /api/v1/fleet/events` |
| 14 | `GET /api/v1/fleet/events/{event_id}` |
| 11 | `GET /api/v1/fleet/risk` |
| 9 | `GET /api/v1/fleet/compliance` |
| 12 | `GET /api/v1/fleet/hosts` |
| 14 | `GET /api/v1/fleet/hosts/{host_id}` |
| 13 | `POST /api/v1/triage/upsert` |
| 11 | `POST /api/v1/triage/note` |
| 6 | `GET /api/v1/triage/{host_id}/{event_id}` |
| 20 | `GET /*` (SPA and unrouted paths) |

Every route has a success case and an error case, except the two OIDC routes. Their success path
needs an HTTPS OIDC provider, so the Rust port carries over the Go OIDC unit tests instead
(`NO_SUCCESS_CASE` in `cases.ts`).

CI does not run this suite yet. The Rust binary serves every route, and a run against it must pass
every case.

## Files

- `cases.ts`: the table. Rows run in order against one server process, so the triage rows form a
  write sequence. A row can send unrecorded prelude requests first, each with the status it must
  get, for example to fill the login limiter's window.
- `run.parity.ts`: sends each case, records it, and compares it with `goldens/<case>.json`.
- `normalize.ts`: the normalization rules below. `normalize.test.ts` tests them under Vitest.
- `stub-upstream.mjs`: a stand-in for the `lodeline-server` read API, used by the live-mode cases.
- `allowlist.json`: differences the comparison accepts, each with its reason.
- `env.ts`: ports, throwaway test credentials, and the run settings.

## Run against a binary

Build `web/dist` first. The SPA cases compare served files with `web/dist`, so the binary must
embed the same build.

```sh
cd apps/manager/web
npm run build
MANAGER_BIN=/path/to/lodeline-manager npm run parity
```

`MANAGER_BIN` defaults to `../target/release/lodeline-manager`, the same as the e2e config.
`playwright.parity.config.ts` starts four processes: the stub upstream, a manager on the mock
fleet, a manager that reads the stub, and a manager whose upstream port has no listener. They
listen on `127.0.0.1` ports 18281 to 18284, and port 18285 must stay free. Set `PARITY_PORT` to
move the first port. The suite always starts fresh processes and a fresh triage
database, so run the whole table, not a filtered subset. Requests go out over raw `node:http`, so
the server sees each path exactly as the table writes it, `..` and `//` included.

`npx playwright test` with the default config runs only the e2e suite.

## Update the goldens

Record against the Go build:

```sh
PARITY_UPDATE=1 MANAGER_BIN=/path/to/go/lodeline-manager npm run parity
```

`PARITY_UPDATE=1` writes `goldens/<case>.json` for every case and removes goldens that no case
names. Add `PARITY_TESTDATA=1` to also rewrite `apps/manager/testdata/` (see its README). That
step needs the `sqlite3` command.

With either variable set, the suite first reads `version` from `/api/health` and stops unless it
starts with `e4fb077`. `PARITY_ALLOW_ANY_REFERENCE=1` skips that check and prints a warning; use
it only to record from a deliberately changed reference. CI must never set `PARITY_UPDATE`,
`PARITY_TESTDATA` or `PARITY_ALLOW_ANY_REFERENCE`: a CI run compares and writes nothing. The
suite stops at load when `CI` is set together with any of them.

### Goldens recorded from the Rust build

When a Rust change intentionally answers differently from a Go golden, record from the Rust
build with `PARITY_UPDATE=1 PARITY_ALLOW_ANY_REFERENCE=1`, then restore every golden that the
change does not concern (`git checkout -- <file>`), list it in this table, and state the
difference in the PR. These goldens hold Rust behavior:

| Golden | Difference from Go |
|---|---|
| `login-rate-limited-multi-hop` | The limiter keys on the rightmost `X-Forwarded-For` hop that is not a trusted proxy, not the first: the prelude's attempts count for `198.51.100.7`, so `203.0.113.20` is not limited. |
| `login-rate-limited-real-ip` | `X-Real-IP` is not read, so the request counts for its loopback peer, which is exempt. |
| `login-rate-limited-true-client-ip` | `True-Client-IP` is not read, as above. |
| `login-rate-limited-header-precedence` | Only `X-Forwarded-For` counts: the prelude's attempts go to `203.0.113.25`, and the `True-Client-IP` request is a loopback peer's. |

The parity managers run with `TRUSTED_PROXIES=127.0.0.1`, so the recorder is a trusted proxy and
the other limiter cases name their client in `X-Forwarded-For`. The Go reference ignores it.

### Build the Go reference

Build the Go binary from `e4fb077` with this `web/dist` copied to `internal/server/dist`, as
its Makefile `build` target does with its own `web/dist`. The `-ldflags` value stamps the version
that the check reads:

```sh
git -C <lodeline-manager clone> worktree add --detach <dir> e4fb077
rm -rf <dir>/internal/server/dist && cp -r dist <dir>/internal/server/dist
cd <dir> && go build \
  -ldflags "-X github.com/Ju571nK/lodeline-manager/internal/api.Version=$(git describe --always --dirty)" \
  -o <out>/lodeline-manager ./cmd/lodeline-manager
```

## Normalization

Bodies are compared as parsed JSON with sorted keys, so byte-level differences such as Go's
trailing newline, its escaping of `<`, `>` and `&`, and number spelling (`1.0` against `1`) do not
count. Each rule below hides only the
part of a value that changes from run to run.

Where the spelling is the behavior, a case names dot paths in `rawText`, and the record also holds
the text of the value at each path exactly as the server wrote it. The triage snapshot cases use
it: Go stores the client's JSON text and writes it back compacted, with number spelling and string
escapes kept and `<`, `>`, `&`, U+2028 and U+2029 escaped.

The recorder notes when each request ran: from just before it sends to the last body byte. A time
"from a request" lies in that bracket, allowing 2 ms for clock rounding and the value's own
precision (a whole-second value covers its whole second). The recorder waits a few milliseconds
between requests so that no two brackets overlap, and pauses after its own login so that no later
request shares that second.

| Rule | Applies to | Reason |
|---|---|---|
| Mock event IDs become `EVT#<n>` | strings equal to an ID the Go mock derives from the seed | Go builds mock IDs from the seed, which is the process start time. `<n>` is the recipe index, computed by the recorder, not read from the response. |
| Times become `<seed±offset layout>` | RFC 3339 strings in mock-mode bodies, except the keys below | The mock anchors every time at the seed, read from `/api/v1/fleet/healthz` `ts`. |
| Times become `<now#<rank> layout>` | keys `created_at`, `updated_at`, `at`, `timestamp`, from this request | These come from the request clock. Equal instants share a rank within a case. |
| Times become `<now@<case> layout>` | the same keys, from an earlier recorded request | For example, `triage-get` returns the times the upsert and note cases wrote. |
| `.9` layout required | the same keys in `/api/v1/triage/*` bodies | Go writes triage times in a fixed-width layout, and the database sorts on it. A trimmed value stays raw and fails. |
| `expires_at` and cookie `Expires` become `<now+87600h layout>` or `<now@<case>+87600h layout>` | values equal to a request's time plus the TTL | Session expiry follows the clock of the request that issued the session. For `/api/v1/auth/me` that is `recorder-login`, the suite's own login. Other values stay raw. |
| `version` becomes `<version>` | `/api/health`, when non-empty | The build stamps its own version string. An empty one stays raw and fails. |
| IPv4 addresses become `<ipv4 hash>` | strings in bodies, except 127.0.0.1 and the documentation ranges | Keeps mock addresses out of the tree. The hash still changes when the address changes. |
| `Retry-After` becomes `<59..61>` | 429 responses | Go sends the seconds left in the 60 s window plus one, rounded down: 60 for back-to-back requests. Any other value stays raw. |
| Upstream query pairs are decoded and sorted | requests the stub records | `lodeline-server` reads the query as a map, so order and percent-encoding are not part of the contract. The path is kept as sent, percent-encoding included. |
| SPA bodies become `<dist:<name>>` | bodies equal to a file in `web/dist` | `<name>` is the placeholder the case requested (`{asset:js}`, `{asset:css}`) or the path of an unhashed file, so goldens survive SPA edits while still naming the exact file. A hashed file no case asked for shows as `unrequested <path>`. |
| Partial bodies become `<dist:<name> bytes a-b>`, and the `Content-Range` total becomes `<size of <name>>` | 206 responses that match the requested file | Same reason. |
| A recorded `Content-Length` becomes `<size of <name>>` | values equal to the size of the requested file, or of `index.html` for an SPA fallback | Same reason. |
| Listing entries become `<every file in dist/assets, sorted>` | the `spa-assets-dir` body | Only when the entries are exactly the files in `web/dist/assets`, in order. Otherwise they are kept with hashes dropped, sorted, so the diff shows them. |
| Other non-JSON bodies are kept as text, or as a hash above 4 KiB | everything else | |
| Cookie values become `<set>` | `Set-Cookie` | Session tokens change on every login. The name and the attributes are kept, in the order sent and with names in the case sent. |
| The `Expires` rule above applies only to an IMF-fixdate | cookie `Expires` | The form must be `Wed, 04 Nov 2026 22:00:02 GMT` with a weekday that matches the date. Any other form stays raw and fails. |

Every response header is recorded, sorted by name, except `Date`, `Content-Length`,
`Transfer-Encoding`, `Connection` and `Keep-Alive`. `Content-Length` is recorded when the method
is `HEAD` or the body is empty, because then it states a size rather than framing the body.
`Set-Cookie` is recorded parsed, as above. A header sent more than once is recorded as a list. Each request carries `Accept: */*` and
`Accept-Encoding: gzip, deflate, br`, as a browser does, so a server that compresses shows it.

Live-mode cases keep their times raw, because the stub answers with fixed values. The servers
run with `TZ=UTC`, because Go's `/api/v1/auth/me` formats the token expiry in the process time
zone.

Besides the golden comparison, a run fails when:

- the mock seed is not a whole second between the run start and now (Go takes it from the process
  start, truncated to the second);
- a prelude request gets a status other than the one its row names;
- a case with `minMs` or `maxMs` takes longer or shorter (the login failure delay, the 5 s
  upstream timeout, and the upstream retries with a 1 s `Retry-After`);
- a golden has no case, or a case has no golden.

## Allowlist

`allowlist.json` lists the differences that a comparison accepts. Each entry names the cases it
applies to, a rule, and the reason. There are two rules:

- `null-or-absent`, with a dot path into the record (`*` matches any key or index): at that path,
  `null` and a missing key compare equal. Use it only where the SPA type accepts both forms, and
  list only the cases whose bodies carry the field.
- `alternative`, with a partial `record` of `status`, `headers`, `cookies` or `body`: a response
  whose record equals every one of those values exactly compares as the golden. A response that
  matches only some of them still fails, so the golden and the stated alternative both pass and
  nothing in between does. Use it only for an intended difference from Go.

| Cases | Rule | Reason |
|---|---|---|
| `fleet-meta`, `live-meta-fleet`, `live-meta-legacy-license` | `null-or-absent` at `body.audit_head` | Go omits it when missing; the SPA type is `audit_head?: AuditHead \| null`. |
| `fleet-host`, `fleet-host-no-meta`, `live-host` | `null-or-absent` at `body.ai_guard.by_tool.*.controls` | Go omits unreported controls; the SPA type is `controls?: AiGuardControl[] \| null`. |
| `spa-index-html` | `alternative`: 200 with `index.html` | Intended. Go answers 301 to `./`; the Rust port serves the page. |
| `spa-assets-dir` | `alternative`: 200 with `index.html` | Intended. Go lists the directory; the Rust port gives the SPA fallback. |

A later phase that accepts another difference adds an entry here with its reason.

Besides the record comparison, each case checks the four security headers on their own, so a run
shows them even for a response whose record differs.

## Not covered

A passing run says nothing about the following. Each needs its own test in the phase that ports it.

- The fleet cache. The mock data never changes, and the live servers run with
  `FLEET_CACHE_DISABLED=1`, so stale-while-revalidate, single flight and eviction are untested here.
- Startup and config validation: missing or short secrets, bad env values, the 5 s drain. Every
  process here starts with one valid config.
- OIDC-enabled flows. Every manager runs with OIDC off; see `NO_SUCCESS_CASE`.
- The timing of upstream retries other than `upstream-503-retried`'s total time: the 5 s cap and
  the gap between single attempts. `upstream-timeout` shows that a timed-out request is not
  retried.
- The 250 ms login failure delay is checked only as a minimum on the three wrong-credential cases.
  Whether other failure paths wait, or how long the slowest wait is, is not checked.
- `OPTIONS` beyond `login-options`, and repeated query keys beyond `host_id`,
  `fleet-events-duplicate-key` and the `limit` cases of risk, compliance and hosts.
- `Content-Length` of a non-empty `GET` response, and whether a response is chunked.
- Percent-encoded path parameters in mock mode. The live cases show what Go sends upstream.
- Limiter behavior that needs time to pass or many addresses: window reset after 60 s, dropping
  windows that have reset, and the 65,536-address cap. `src/api/ratelimit/tests.rs` covers them
  with an injected clock.
- Connections from client addresses other than 127.0.0.1. The servers listen on 127.0.0.1 only,
  and the test host has no other loopback address, so the other 127/8 address, `::1` and
  `::ffff:127.0.0.1` reach the limiter only through `X-Forwarded-For`. An untrusted peer's
  forwarding headers are covered in `src/api/ratelimit/tests.rs`.
- Request bodies larger than a few hundred bytes, including the 64 KiB and 4 MiB body limits
  and the 30 s body read timeout. `src/api/auth/tests.rs` and `src/api/triage/tests.rs` cover
  them.
