# lodeline-manager

Read-only web console for a `lodeline-server` fleet: a Rust server that embeds a React SPA. It
reads the server's fleet read API and writes only its own triage notes. It replaces the Go
console from [Ju571nK/lodeline-manager](https://github.com/Ju571nK/lodeline-manager), and it
reads that console's session cookies and triage database (see [Moving from the Go
console](#moving-from-the-go-console)).

This folder is its own Cargo workspace. The root workspace does not build it, and
`.github/workflows/manager.yml` tests it.

## Prerequisites

- Rust 1.88 or later. In this repository, rustup picks the toolchain from `rust-toolchain.toml`.
- A C compiler. `rusqlite` builds its bundled SQLite.
- Node.js 20 and npm, to build the SPA.

## Build

Build the SPA first, then the binary:

```sh
cd apps/manager/web
npm ci
npm run build        # writes web/dist

cd ..
LODELINE_MANAGER_REQUIRE_DIST=1 cargo build --release
```

The binary is `target/release/lodeline-manager`, or the same path under `CARGO_TARGET_DIR`.
`build.rs` embeds `web/dist` in it, so the binary is the whole console. Without `web/dist`, it
embeds a page that says to build the web UI, so `cargo test` works without npm.
`LODELINE_MANAGER_REQUIRE_DIST=1` makes a missing `web/dist` a build error. Set it for every
build you deploy.

## Configure

The binary reads only environment variables. It does not load `.env` itself.
[`.env.example`](.env.example) lists every variable with its details. An empty value counts as
unset.

| Variable | Default | What it does |
|---|---|---|
| `ADMIN_USERNAME` | required | The local admin's login name. |
| `ADMIN_PASSWORD_BCRYPT` | required | The local admin's bcrypt hash, `$2a$`, `$2b$` or `$2y$`. |
| `JWT_SECRET` | required | Signs session tokens. At least 32 bytes. |
| `LODELINE_SERVER_BASE_URL` | required unless `MOCK_FLEET=1` | Base URL of `lodeline-server`, with no trailing slash. |
| `LODELINE_SERVER_READ_TOKEN` | required unless `MOCK_FLEET=1` | Bearer token for the server's read API. It must match the server's `LODELINE_SERVER_READ_TOKEN`. |
| `LODELINE_SERVER_CA_PATH` | unset | CA bundle that signed the server's certificate. Unset uses the OS trust store. |
| `LODELINE_SERVER_CLIENT_CERT_PATH`, `LODELINE_SERVER_CLIENT_KEY_PATH` | unset | Client certificate and key for a server that requires mTLS. Set both or neither. The three TLS variables need an `https://` base URL. |
| `MOCK_FLEET` | `0` | `1` serves a built-in mock fleet of 5 hosts and makes no upstream request. |
| `LISTEN_ADDR` | `:8080` | Listen address. `:port` listens on every IPv4 and IPv6 address. |
| `TRIAGE_DB_PATH` | `./var/triage.sqlite` | The triage SQLite file. Its directory must exist and be writable. |
| `JWT_TTL_HOURS` | `12` | Session lifetime in hours. |
| `LODELINE_INSECURE_COOKIE` | unset | `1` drops `Secure` from the session cookie, so a browser keeps it over plain HTTP. Only for local runs. |
| `TRUSTED_PROXIES` | empty | Reverse proxies whose `X-Forwarded-For` the login limiter reads. See [Behind a reverse proxy](#behind-a-reverse-proxy). |
| `FLEET_POLL_INTERVAL_SECONDS` | `5` | How long a cached fleet read stays fresh. After that the cache still answers with the old read, up to 12 times this age, while it refreshes in the background. Fleet metadata and single events stay fresh 12 times longer than other reads. It does not set how often the SPA polls; the SPA's intervals are fixed. |
| `FLEET_CACHE_DISABLED` | `0` | `1` sends every fleet read to `lodeline-server`. |
| `FLEET_CACHE_MAX_ENTRIES` | `512` | Most cached fleet reads kept. |
| `OIDC_*` | unset | Optional organization login. See [docs/operations/oidc.md](docs/operations/oidc.md). |

The process stops with an error that names every missing required variable, or an invalid
one. It ignores `SIGIL_*` names from before the rename and warns about them. On start it prints
`mode=mock-fleet` or `mode=live-fleet`, the listen address and the database path, then logs
each request. On SIGINT or SIGTERM it stops accepting connections and
waits up to 5 seconds for requests in flight.

## Run with the mock fleet

This runs the console on its built-in mock fleet with throwaway credentials, over plain HTTP on
loopback. Sign in as `admin` with `change-me`:

```sh
mkdir -p var
LISTEN_ADDR=127.0.0.1:8080 \
MOCK_FLEET=1 \
LODELINE_INSECURE_COOKIE=1 \
ADMIN_USERNAME=admin \
ADMIN_PASSWORD_BCRYPT="$(htpasswd -bnBC 10 '' 'change-me' | tr -d ':\n')" \
JWT_SECRET="$(openssl rand -hex 32)" \
  target/release/lodeline-manager
```

Then open <http://127.0.0.1:8080>. `htpasswd` comes with Apache's utilities; any bcrypt tool
works. A new `JWT_SECRET` on each start signs everyone out, which is fine for a local run.

## Run against lodeline-server

The server must have its read API on: start it with `LODELINE_SERVER_READ_TOKEN` set
([docs/install-server.md](../../docs/install-server.md)). Give the console the same token and
the server's URL, and keep `JWT_SECRET` and the admin hash in your secret store so they survive
restarts:

```sh
LISTEN_ADDR=127.0.0.1:8080 \
LODELINE_SERVER_BASE_URL=https://fleet.example.com:8443 \
LODELINE_SERVER_READ_TOKEN=... \
TRIAGE_DB_PATH=/var/lib/lodeline-manager/triage.sqlite \
ADMIN_USERNAME=admin \
ADMIN_PASSWORD_BCRYPT='$2y$10$...' \
JWT_SECRET=... \
  target/release/lodeline-manager
```

If the server requires client certificates, also set `LODELINE_SERVER_CLIENT_CERT_PATH` and
`LODELINE_SERVER_CLIENT_KEY_PATH`, and `LODELINE_SERVER_CA_PATH` if a private CA signed the
server's certificate. Leave `LODELINE_INSECURE_COOKIE` unset and put a TLS terminator in front
of the console. The session cookie carries `Secure`, so a browser drops it over plain HTTP and
login seems to fail.

## Sessions and the login limit

- A session is a signed token in the `lodeline_session` cookie (`HttpOnly`, `SameSite=Lax`,
  `Secure` unless `LODELINE_INSECURE_COOKIE=1`). It lasts `JWT_TTL_HOURS`, and an OIDC session
  never outlasts its ID token.
- Sessions are stateless. Logout clears the cookie in that browser but does not revoke the
  token, and a restart does not end sessions. To end every session at once, change
  `JWT_SECRET` and restart every instance.
- Login and the two OIDC routes allow 10 attempts a minute per client address, successful ones
  included, and answer 429 with `Retry-After` after that. No address is exempt, loopback
  included. Behind a reverse proxy, set `TRUSTED_PROXIES`, or every client shares the proxy's
  10 attempts. The limits are per process, so each instance counts on its own.

### Behind a reverse proxy

An IPv6 client is counted by its /64 network. The limiter tracks at
most 65,536 addresses. While that many windows are open, attempts from other addresses share
one extra window with the same limit, and no open window is dropped early. So a sustained flood
of new addresses can hold sign-ins from every address without an open window to 10 a minute
between them, for as long as the flood lasts. Addresses with an open window and existing
sessions are unaffected. An address seen before whose window has reset counts as new.

By default the client address is the connection's peer, and forwarding headers are ignored.
Behind a reverse proxy, every client then shares the proxy's 10 attempts. To count each client
apart, set `TRUSTED_PROXIES` to the proxy's address, `127.0.0.1` for a proxy on the same host
(see `.env.example`). The limiter then reads `X-Forwarded-For` from those peers only, and takes
the rightmost hop that is not a trusted proxy. `True-Client-IP` and `X-Real-IP` are not read.

- The proxy must append the client's address to `X-Forwarded-For`. nginx does not send the
  header by default; add `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` to the
  `location` that proxies the console. Caddy's `reverse_proxy` sends it by default. A request
  that arrives without the header counts for the proxy's own address, so if the proxy never
  sends it, every client shares one window again.
- Write IPv4 entries in plain form, such as `192.0.2.10`. The peer address is compared as IPv4,
  so an IPv4-mapped entry such as `::ffff:192.0.2.10` never matches.
- Do not list `0.0.0.0/0` or `::/0`. Every peer would be trusted, and any client could name its
  own address in the header.

Request bodies are read to at most 64 KiB for login and 4 MiB for the triage routes. A larger
body gets 413. The reader stops at the end of the body's first JSON value. If that value has
not fully arrived within 30 seconds, the request gets 408.

## Moving from the Go console

The variable names and defaults are the Go console's, so the same environment starts this
binary. Keep `JWT_SECRET`: sessions the Go console issued stay valid until they expire. Point
`TRIAGE_DB_PATH` at the Go console's file: this binary reads and extends it without a
migration. OIDC users keep their identity, so triage actions they recorded under Go stay
theirs.

`TRUSTED_PROXIES` is new. If the console runs behind a reverse proxy, set it as in
[Behind a reverse proxy](#behind-a-reverse-proxy). Otherwise every client shares the proxy's 10
logins a minute. Loopback is no longer exempt from the login limit, so a proxy on the same host
is limited like any other client.

Some answers differ from Go's on purpose. The limiter reads only `X-Forwarded-For` and only
from `TRUSTED_PROXIES`, and `/index.html` and `/assets/` serve the SPA instead of a redirect
and a directory listing. The parity README lists every such difference.

## Test

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo +1.88 check --all-targets --locked   # MSRV

cd web
npm run lint          # Biome
npm test -- --run     # Vitest
```

The browser and HTTP suites run against a release binary built as in [Build](#build):

```sh
cd web
npx playwright install chromium   # once
MANAGER_BIN=/path/to/lodeline-manager npm run e2e
MANAGER_BIN=/path/to/lodeline-manager npm run parity
```

`MANAGER_BIN` defaults to `../target/release/lodeline-manager`. The e2e suite starts the binary
on port 18181 on the mock fleet, with a triage database in a temp dir for each run, or at
`E2E_TRIAGE_DB_PATH`. Outside CI it reuses a server that already answers on that port. The
parity suite in `web/tests/parity/` sends a fixed table of requests and compares each answer
with a recorded golden; see [its README](web/tests/parity/README.md). CI runs both on every
change to this folder.
