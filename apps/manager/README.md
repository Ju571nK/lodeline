# lodeline-manager

Read-only web console for a `lodeline-server` fleet. This folder holds the Rust port of
[lodeline-manager](https://github.com/Ju571nK/lodeline-manager). The port is in progress: the
binary reads its configuration, serves the web UI and `/api/health`, and checks the session
cookie. The other API routes answer `501 Not Implemented` after their method and session
checks, so the console does not work end to end yet.

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

## Test

```sh
cargo test
cargo +1.88 check --locked   # MSRV
```

The parity suite in `web/tests/parity/` compares the binary's HTTP answers with the Go
implementation's. See [its README](web/tests/parity/README.md).
