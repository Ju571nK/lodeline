# lodeline-manager

Read-only web console for a `lodeline-server` fleet. This folder holds the Rust port of
[lodeline-manager](https://github.com/Ju571nK/lodeline-manager). Every route of the Go console is
ported, including local and OIDC login. The port is not released yet.

This is its own Cargo workspace. The root workspace does not build it, and
`.github/workflows/manager.yml` tests it.

## Build

```sh
cd apps/manager/web
npm ci
npm run build        # writes web/dist

cd ..
LODELINE_MANAGER_REQUIRE_DIST=1 cargo build --release
```

`build.rs` embeds `web/dist` in the binary. Without `web/dist` it embeds a placeholder page, so
`cargo test` works without npm. `LODELINE_MANAGER_REQUIRE_DIST=1` makes a missing `web/dist` a
build error.

## Run

The binary reads only environment variables. `.env.example` lists all of them. This starts it on
the built-in mock fleet with throwaway credentials:

```sh
LISTEN_ADDR=127.0.0.1:8080 \
MOCK_FLEET=1 \
LODELINE_INSECURE_COOKIE=1 \
ADMIN_USERNAME=admin \
ADMIN_PASSWORD_BCRYPT="$(htpasswd -bnBC 10 '' 'change-me' | tr -d ':\n')" \
JWT_SECRET="$(openssl rand -hex 32)" \
  target/release/lodeline-manager
```

The process stops with an error that names every missing or invalid variable. On SIGINT or
SIGTERM it stops accepting connections and waits up to 5 seconds for requests in flight.

### Behind a reverse proxy

Login and the two OIDC routes allow 10 attempts a minute per client address. No address is
exempt, loopback included. An IPv6 client is counted by its /64 network. The limiter tracks at
most 65,536 addresses. While that many windows are open, attempts from other addresses share
one extra window with the same limit, and no open window is dropped early.

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

## Test

```sh
cargo test
cargo +1.88 check --locked   # MSRV
```

The parity suite in `web/tests/parity/` compares the binary's HTTP answers with the Go
implementation's. See [its README](web/tests/parity/README.md).
