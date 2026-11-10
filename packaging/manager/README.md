# lodeline-manager

`lodeline-manager` is the web console for a `lodeline-server` fleet. This binary has
the web UI built in, so it is the whole console. Run `lodeline-manager --version` to see its
release.

It reads its configuration from environment variables only. `.env.example` lists every
variable. At least set `ADMIN_USERNAME`, `ADMIN_PASSWORD_BCRYPT`, `JWT_SECRET`,
`LODELINE_SERVER_BASE_URL` and `LODELINE_SERVER_READ_TOKEN`. The console refuses to start with
the example values that earlier `.env.example` files held.

Put a TLS reverse proxy in front of it and set `TRUSTED_PROXIES` to the proxy's address. The
session cookie is `Secure`, so login over plain HTTP fails unless `LODELINE_INSECURE_COOKIE=1`
is set, which is for loopback testing only. See "Configure" in the full guide.

The full guide is at
<https://github.com/Ju571nK/lodeline/blob/main/apps/manager/README.md>.
