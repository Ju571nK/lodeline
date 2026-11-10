# lodeline-manager

Read-only web console for a `lodeline-server` fleet: a Rust server that embeds a React SPA. It
reads the server's fleet read API and writes only its own triage notes. It replaces the Go
console from [Ju571nK/lodeline-manager](https://github.com/Ju571nK/lodeline-manager), and it
reads that console's session cookies and triage database (see [Moving from the Go
console](#moving-from-the-go-console)).

This folder is its own Cargo workspace. The root workspace does not build it,
`.github/workflows/manager.yml` tests it, and `.github/workflows/release.yml` ships it with each
release.

## Install from a release

Each release after v0.13.0 has a `lodeline-manager-<version>-<target>.tar.gz` archive (`.zip`
on Windows) for the same targets as the agent: `x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc` and
`aarch64-pc-windows-msvc`. The Linux binaries are static. The archive holds the
`lodeline-manager` binary with the SPA built in, `.env.example`, `LICENSE`, `NOTICE` and a short
`README.md`.

Download the archive and `SHA256SUMS` from the [releases
page](https://github.com/Ju571nK/lodeline/releases), then check both before you run the binary:

```sh
sha256sum --ignore-missing -c SHA256SUMS            # Linux
shasum -a 256 --ignore-missing -c SHA256SUMS        # macOS
gh attestation verify lodeline-manager-<version>-<target>.tar.gz --repo Ju571nK/lodeline
tar -xzf lodeline-manager-<version>-<target>.tar.gz
lodeline-manager-<version>-<target>/lodeline-manager --version
```

The signed `build-manifest.json` also lists the binary's blake3 hash. `lodeline doctor
--verify-self` checks only the `lodeline` binary it runs as, so check the console with
`SHA256SUMS` and the attestation.

Set the required variables in [Configure](#configure): `ADMIN_USERNAME`,
`ADMIN_PASSWORD_BCRYPT`, `JWT_SECRET`, `LODELINE_SERVER_BASE_URL` and
`LODELINE_SERVER_READ_TOKEN`. Then start the binary as in [Run against
lodeline-server](#run-against-lodeline-server). Put a TLS reverse proxy in front of it: the
session cookie is `Secure`, so a browser drops it over plain HTTP and login fails, unless
`LODELINE_INSECURE_COOKIE=1` is set, which is for loopback testing only (see
[Configure](#configure)). Set `TRUSTED_PROXIES` to the proxy's address, `127.0.0.1` for a proxy on the same host. Without it,
every client shares the proxy's 10 logins a minute. See [Behind a reverse
proxy](#behind-a-reverse-proxy).

## Prerequisites

- Rust 1.88 or later. In this repository, rustup picks the toolchain from `rust-toolchain.toml`.
- A C compiler. `rusqlite` builds its bundled SQLite.
- Node.js 20.19+ or 22.12+ and npm, to build the SPA. The SPA tests (`npm test`) need Node.js
  22.13 or later, because they use `JSON.parse` source text and `JSON.rawJSON`. CI uses Node.js 24.

## Build from source

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
unset. The console refuses to start while `JWT_SECRET`, `LODELINE_SERVER_READ_TOKEN` or
`ADMIN_PASSWORD_BCRYPT` holds the public example value from an earlier `.env.example`.

| Variable | Default | What it does |
|---|---|---|
| `ADMIN_USERNAME` | required | The local admin's login name. |
| `ADMIN_PASSWORD_BCRYPT` | required | The local admin's bcrypt hash, `$2a$`, `$2b$` or `$2y$`. |
| `JWT_SECRET` | required | Signs session tokens. At least 32 bytes. |
| `LODELINE_SERVER_BASE_URL` | required unless `MOCK_FLEET=1` | Base URL of `lodeline-server`, with no trailing slash. |
| `LODELINE_SERVER_READ_TOKEN` | required unless `MOCK_FLEET=1` | Bearer token for the server's read API. It must match the server's `LODELINE_SERVER_READ_TOKEN`. |
| `LODELINE_SERVER_CA_PATH` | unset | CA bundle that signed the server's certificate. Unset uses the OS trust store. |
| `LODELINE_SERVER_CLIENT_CERT_PATH`, `LODELINE_SERVER_CLIENT_KEY_PATH` | unset | Client certificate and key for a server that requires mTLS. Set both or neither. The three TLS variables need an `https://` base URL. |
| `MOCK_FLEET` | `0` | `1` serves a built-in mock fleet of 6 hosts and makes no upstream request. |
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

### Proxy reads

The **Proxies** pages read the server's Lodeline Proxy status and invocations (`GET /v1/proxies`,
`GET /v1/proxies/{id}`, `GET /v1/proxy-invocations` and `GET /v1/proxy-invocations/{id}`), and
each proxy's inventory snapshots, drift and re-baseline markers
(`GET /v1/proxies/{id}/inventory-snapshots`, `/drift` and `/rebaseline-markers`). The
server serves these routes only when its `server.yaml` has a `proxy:` section, and a server
with that section always requires mTLS. To read them, configure the console as follows:

1. Set `LODELINE_SERVER_BASE_URL` to the server's `https://` URL.
2. Issue the console a client certificate from the host client CA, the CA in the server's
   `client_ca_path` that also signs agent host certificates
   ([docs/install-server.md](../../docs/install-server.md), section 3). Do not use a certificate
   from the proxy CA (`proxy.ca_path`), a certificate registered to a proxy, or a management
   caller's certificate. The server answers each of those with 404 on these routes, and on
   every fleet route as well, and the console then says that the server did not accept its
   client certificate.
3. Set `LODELINE_SERVER_CLIENT_CERT_PATH` and `LODELINE_SERVER_CLIENT_KEY_PATH` to that
   certificate and its key, and `LODELINE_SERVER_CA_PATH` if a private CA signed the server's
   certificate.
4. Keep `LODELINE_SERVER_READ_TOKEN`. The proxy reads use the same read bearer token as the
   fleet reads.

Without a `proxy:` section, the Proxies page says that proxy reads are not available on the
server, and the fleet pages work as before. A server that predates the inventory routes serves
the proxy pages, and the Inventory section of a proxy says that it does not serve them.

The console only reads proxies. Register, disable and config changes go through the server's
operator CLI and its management credential, which the console never holds.

### Downloads

The **Downloads** page lists the release files in the server's `artifacts_dir`, and a signed-in
user can save one in the browser. The console reads `GET /v1/artifacts` and
`GET /v1/artifacts/{filename}` with `LODELINE_SERVER_READ_TOKEN` and its client certificate, and
streams each file to the browser as it arrives. The read token stays on the console, so nobody
has to put it on a host to fetch the files.

To fill the page, set `artifacts_dir` in the server's `server.yaml` and copy the release files
into that folder ([docs/install-server.md](../../docs/install-server.md), section 5.1). Without
it, the page says that the server serves no release files.

The console passes each file on as the server sends it and does not check it. Before you install
a file, check it against the `SHA256SUMS` on the GitHub release page and its attestation, as
[Install from a release](#install-from-a-release) shows for the console itself. A `SHA256SUMS`
from the Downloads page comes from the same server as the file, so it shows only that the file
arrived intact.

- A file name can hold only ASCII letters, digits, `.`, `_` and `-`, and cannot be `.` or `..`,
  the rule the server uses. The console answers any other name with 400 `bad_filename` and sends
  no request.
- The console does not cache the list, so a reload shows the files that the server holds now.
- A download has no total time limit. It fails when the server sends nothing for 30 s, and the
  browser then reports a failed download. A fleet read still fails after 5 s.

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

## API requests

`POST /api/v1/auth/login`, `/api/v1/triage/upsert` and `/api/v1/triage/note` take only
`Content-Type: application/json`, in any letter case and with or without parameters such as
`charset`. Any other type, `application/*+json` included, or no `Content-Type` gets 415 with
code `unsupported_media_type` before the body is read. The session check on the triage routes
and the login limit answer first, so a refused login still counts as an attempt.

Request bodies are read to at most 64 KiB for login and 4 MiB for the triage routes. A larger
body gets 413. The reader stops at the end of the body's first JSON value. If that value has
not fully arrived within 30 seconds, the request gets 408.

When the console answers before it has read the request body to the end, such as with a 401,
405, 413, 415 or 429, it first reads and drops up to 64 KiB more of the body for at most
1 second. If the body ends within that, the connection stays open for the next request, so an
over-limit body that arrives whole may get its 413 on a connection that stays open. Otherwise
the answer carries `Connection: close`. At most 64 such reads run at once. Past that, or for a
request with an `Expect` header, the answer goes out at once with `Connection: close`.

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

The Go console read login and triage bodies as JSON whatever their `Content-Type`. This binary
answers 415 unless the type is `application/json`, so a script that posts JSON without that
header must add it. The console's own pages already send it.

Some answers differ from Go's on purpose. The limiter reads only `X-Forwarded-For` and only
from `TRUSTED_PROXIES`, the body routes require `application/json`, and `/index.html` and
`/assets/` serve the SPA instead of a redirect and a directory listing. The parity README lists
every such difference.

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

The browser and HTTP suites run against a release binary built as in [Build from source](#build-from-source):

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
