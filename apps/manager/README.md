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

Login and the two OIDC routes allow 10 attempts a minute per client address. Loopback
connections are exempt. The limiter tracks at most 65,536 addresses and drops the oldest
window past that. By default the client address is the connection's peer, and forwarding
headers are ignored. Behind a reverse proxy, set `TRUSTED_PROXIES` to the proxy's addresses or
networks (see `.env.example`). The limiter then reads `X-Forwarded-For` from those peers only,
and takes the rightmost hop that is not a trusted proxy. `True-Client-IP` and `X-Real-IP` are
not read.

Request bodies are read to at most 64 KiB for login and 4 MiB for the triage routes. A larger
body gets 413. A body that has not fully arrived within 30 seconds gets 408.

## Test

```sh
cargo test
cargo +1.88 check --locked   # MSRV
```

The parity suite in `web/tests/parity/` compares the binary's HTTP answers with the Go
implementation's. See [its README](web/tests/parity/README.md).
