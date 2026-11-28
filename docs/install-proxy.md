# lodeline-proxy: Operator and User Guide (Linux)

`lodeline-proxy` is a relay that sits between an AI coding client and one
remote MCP server. It checks who is calling, forwards the call, and writes an
audit record of each call (which method, which tool, what outcome) to
`lodeline-server`. It measures; it does not block. Today it has one mode,
`observe`, and no setting turns blocking on.

This guide takes you from a build to a client that talks through the proxy. It
assumes a running `lodeline-server` with mutual TLS, set up as in
[install-server.md](install-server.md).

---

## 1. Status: read this first

- **Not released.** The proxy is not a release asset: the release workflow
  removes the `lodeline-proxy` packages and leaves the binary out of the
  archives. You build it yourself (section 3).
- **No vendor client was measured through the proxy.** The client snippets in
  section 11 follow each vendor's documentation. They are "documented to accept
  this form; not tested through the proxy".
- **Linux only.** The proxy builds its TLS code for unix only, so there is no
  Windows or macOS service. The first verification target is Rocky Linux 9. Nothing
  was run on x86_64.
- **One mode.** `observe` records and relays. There is no policy, no block list and
  no approval step. It fails closed: when the proxy cannot record a call or has no
  valid config, it refuses the call (section 10).
- **Numbers are defaults, not promises.** The limits in section 12 are first
  values that nobody has measured under load.

---

## 2. Topology and ports

```text
 client (Claude Code, Codex, Cursor)
        |  HTTP POST /mcp/{route_id}   Authorization: Bearer <proxy token>
        v
 lodeline-proxy  --- mTLS HTTPS :8443 ---> lodeline-server
        |                                   (config, audit events, registry)
        |  HTTP(S) POST, upstream credential
        v
 upstream MCP server
```

- **Listener:** `127.0.0.1:8480` by default. A listener on a non-loopback address
  needs `tls_cert_file` and `tls_key_file`. On a loopback listener the `Host`
  header must be a loopback name with the same port, so a client reaches it as
  `http://127.0.0.1:8480` or `http://localhost:8480`.
- **Control plane:** toward the server the proxy makes outbound connections to
  `8443/tcp`.
- **Data plane path:** `/mcp/{route_id}`, where `route_id` is a route from the
  proxy's config. Any other path shape is a 404.

### 2.1 What an upstream may be

A route points at one upstream URL. Two rules apply, and the first example in
this guide meets the first one:

- An `http://` upstream is allowed only for a loopback host
  (`http://127.0.0.1:18080/mcp`). Every address the name resolves to must be loopback.
- An `https://` upstream is refused when its name resolves to a loopback or a
  private address. In practice the proxy refuses private-network upstreams: an
  MCP server inside your own network, even over TLS, is not reachable. The
  setting that would allow it is fixed to off.

The proxy checks the resolved addresses on every request. A refusal is a 502 with
`destination_refused`.

---

## 3. Get the binary

There is no download. Build from source (Rust 1.88 or newer):

```sh
git clone https://github.com/Ju571nK/lodeline.git && cd lodeline
cargo build --release --locked -p lodeline-proxy -p lodeline-server
target/release/lodeline-proxy version
```

`--locked` is needed: without it cargo may resolve a dependency that needs a newer
Rust than 1.88. The binaries alone do not make a service. A host that uses them
without a package must itself create the `lodeline-proxy` user and group,
`/var/lib/lodeline-proxy` (owner `lodeline-proxy`, mode 0700) and a systemd unit
(start from `packaging/systemd/lodeline-proxy.service`, which runs
`/usr/bin/lodeline-proxy`). The rest of this guide assumes the package.

Or build an OS package yourself (needs `cargo install cargo-deb cargo-generate-rpm`):

```sh
packaging/build.sh proxy rpm      # or: packaging/build.sh proxy deb
sudo dnf install ./target/generate-rpm/lodeline-proxy-*.rpm        # RHEL, Rocky
sudo apt install ./target/debian/lodeline-proxy_*.deb              # Debian, Ubuntu
```

The package installs the unit **disabled**, ships no live `/etc/lodeline/proxy.yaml`
(only `proxy.yaml.example`), creates the `lodeline-proxy` user, and never starts
the service. The server host needs `lodeline-server` of the same build.

---

## 4. Certificates

Three kinds of certificate are involved. The names below are examples.

| What | Signed by | Used for |
|---|---|---|
| Server certificate | host CA | the server's TLS (present if you followed install-server.md) |
| Management certificate | host CA | the operator CLI that registers and configures proxies |
| Proxy certificate | **proxy CA** | the proxy's client identity toward the server |

The proxy CA is a second CA. Its subject name must differ from every other CA in
the server's client CA bundle, and the server refuses to start when the names
match.

The steps below make throwaway 7 day certificates with `openssl`, the way the
smoke test runbook does. They are an example only. Certificate lifetime, key
protection and CA handling are your decision. The tool has no command that signs a
certificate.

```sh
mkdir -p ~/proxy-pki && cd ~/proxy-pki && umask 077
# The proxy CA. Its subject name differs from the host CA.
openssl req -x509 -new -newkey rsa:2048 -nodes -keyout proxy-ca.key -out proxy-ca.crt \
  -days 7 -subj "/CN=example-proxy-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash"

# The server must trust both CAs for client certificates.
cat host-ca.crt proxy-ca.crt > client-ca-bundle.pem
```

Give each leaf subject and authority key identifiers; some TLS stacks reject a
leaf without them.

**Management certificate** (signed by the host CA, which you hold):

```sh
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nextendedKeyUsage=clientAuth\n' > client.ext
openssl req -new -newkey rsa:2048 -nodes -keyout mgmt.key -out mgmt.csr -subj "/CN=example-mgmt"
openssl x509 -req -in mgmt.csr -CA host-ca.crt -CAkey host-ca.key \
  -set_serial 0x$(openssl rand -hex 8) -days 7 -extfile client.ext -out mgmt.crt
```

Do not reuse the read API certificate for this. The routes that read proxy data
(`/v1/proxies` and the invocation routes) refuse a management certificate, so reading
them takes a different host certificate. The management audit route is the exception:
`lodeline-server proxy audit` (section 9) takes the management certificate with the read bearer.

**Proxy certificate.** Make the key on the proxy host so it stays there, and sign
the request on the host that holds the proxy CA. The subject alternative name
must have the form `<proxy_id>.proxy.sigil.invalid`. The `sigil` in that suffix is
the old product name and stays on purpose; do not change it. The proxy id is a DNS
label (letters, digits, hyphen).

```sh
# on the proxy host
umask 077
openssl req -new -newkey rsa:2048 -nodes -keyout proxy.key -out proxy.csr -subj "/CN=px-example-01"

# on the host with the proxy CA
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:px-example-01.proxy.sigil.invalid\n' > proxy.ext
openssl x509 -req -in proxy.csr -CA proxy-ca.crt -CAkey proxy-ca.key \
  -set_serial 0x$(openssl rand -hex 8) -days 7 -extfile proxy.ext -out proxy.crt
```

Copy `proxy.crt` and the host CA certificate (as `ca.pem`) back to the proxy host.
The proxy's certificate fingerprint is computed by the server CLI in section 7;
you do not compute it by hand.

---

## 5. Server configuration

Add a `proxy:` section to `server.yaml`. The server must run with mutual
TLS (`tls_cert_path`, `tls_key_path`, `client_ca_path`), and `client_ca_path` must
point at the bundle from section 4.

```yaml
# /etc/lodeline/server.yaml  (the proxy section only)
proxy:
  ca_path: "/etc/lodeline/proxy-ca.crt"
  registry_path: "/var/lib/lodeline-server/proxies.json"
  registry_init: true            # first start only; remove it afterwards
  management_verifiers: "/etc/lodeline/management-verifiers.json"
  config_ttl_seconds: 300        # 60..=900, default 300
```

- `registry_init: true` lets the server create an empty registry on the first
  start. With it off, a missing registry file is a start error, so a lost
  registry never turns into an empty one by accident. Remove the line after the
  first start.
- `management_verifiers` is the file that holds the management tokens. If it is
  absent, the management routes answer 404. If it is present and does not load,
  the server does not start.
- `config_ttl_seconds` is how long a proxy may keep using the config it fetched
  when it cannot reach the server (section 9). The proxy stops forwarding at that
  deadline.

### 5.1 Management tokens

Two scopes are used here: `identity` (register, fingerprint, enable, retire, delete-content) and
`config` (set config, disable). Each token is bound to the management certificate.
`verifier-new` prints the token once on stdout and the file entry on stderr:

```sh
umask 077
lodeline-server proxy verifier-new --scope identity --caller-cert mgmt.crt \
  --key-id op-identity --not-after 2027-06-01T00:00:00Z > mgmt-identity.token 2> identity.entry
lodeline-server proxy verifier-new --scope config --caller-cert mgmt.crt \
  --key-id op-config --not-after 2027-06-01T00:00:00Z > mgmt-config.token 2> config.entry
chmod 600 mgmt-identity.token mgmt-config.token    # already 0600 under the umask
```

Each `.entry` file holds two lines of advice and then a JSON object. Build the
verifier file from the objects, which start at the line `{`:

```sh
{ printf '{"entries":['; sed -n '/^{/,$p' identity.entry; printf ','; sed -n '/^{/,$p' config.entry; printf ']}\n'; } > management-verifiers.json
rm identity.entry config.entry
sudo install -o lodeline -g lodeline -m 0600 management-verifiers.json /etc/lodeline/management-verifiers.json
```

The server refuses a verifier file that is readable by others, owned by another
account, or a symlink. At most 2 unexpired entries per scope are allowed, so a new
token can overlap the old one during rotation. The file is read again at the next
request after it changes. Write a new file and `mv` it over the old one: a file read
half written fails closed, and every management route answers 404 until a valid
file loads.

Restart the server. Start with `registry_init: true`, then remove it.

---

## 6. Proxy bootstrap config

The proxy has a small local config. Everything else (routes, principals, limits per
route) comes from the server. The example in
[`config/proxy.example.yaml`](../config/proxy.example.yaml), packaged as
`/etc/lodeline/proxy.yaml.example`, lists more keys. If you copy it, remove or
comment out `tls_cert_file` and `tls_key_file` for a loopback listener: when they
are set, the files must exist. The config below is the one this guide uses; write it
to `proxy.yaml` in your working folder.

```yaml
# /etc/lodeline/proxy.yaml
proxy_id: "px-example-01"
listen: "127.0.0.1:8480"
control_plane_url: "https://lodeline-server.example.internal:8443"
state_dir: "/var/lib/lodeline-proxy"
client_cert_file: "/etc/lodeline/proxy/client.crt"
client_key_file: "/etc/lodeline/proxy/client.key"
ca_file: "/etc/lodeline/proxy/ca.pem"
credentials:
  example-upstream:
    secret_file: "/etc/lodeline/proxy/example-upstream.secret"
    upstream_origins: ["http://127.0.0.1:18080"]
```

- `credentials` names each upstream secret by a reference. The secret is a file
  that only the `lodeline-proxy` user can read (mode 0600). No secret value is ever
  written in a config. Each reference lists the upstream origins it may be sent
  to (`scheme://host[:port]`, no path; a default port is dropped). A reference with
  no origin is a start error. **The origin of every route's `upstream_url` (section
  7) must be listed here.** If it is not, the server accepts the config but the proxy
  cannot apply it: the fetch ends in `apply_failed`, the proxy forwards nothing, and
  every call is a 401. This example lists the loopback origin of the first route. For
  a public upstream, list `"https://mcp.example.com"` instead. The bootstrap config
  is read at start, so restart the proxy after you change it.
- Unknown keys are errors. Relative paths resolve against the config file's
  directory.
- A route carries one static upstream credential. The proxy replaces the client's
  `Authorization` header with it, so the client's own token never reaches the
  upstream.

```sh
sudo install -o root -g lodeline-proxy -m 0640 proxy.yaml /etc/lodeline/proxy.yaml
sudo install -d -o lodeline-proxy -g lodeline-proxy -m 0750 /etc/lodeline/proxy
sudo install -o lodeline-proxy -g lodeline-proxy -m 0600 proxy.key /etc/lodeline/proxy/client.key
sudo install -o lodeline-proxy -g lodeline-proxy -m 0644 proxy.crt /etc/lodeline/proxy/client.crt
sudo install -o lodeline-proxy -g lodeline-proxy -m 0644 ca.pem /etc/lodeline/proxy/ca.pem
# example-upstream.secret holds the credential the upstream gave you (a file, not an argument)
sudo install -o lodeline-proxy -g lodeline-proxy -m 0600 example-upstream.secret /etc/lodeline/proxy/example-upstream.secret
sudo -u lodeline-proxy lodeline-proxy check-config --config /etc/lodeline/proxy.yaml
# config ok     (exit 0; an invalid config prints "config invalid: ..." and exits 2)
```

### 6.1 A token for a client

Each calling client gets its own principal and its own bearer token. `token new`
prints the token once and its SHA-256 verifier. It stores nothing.

The command reads the bootstrap config and the owner-only key and secret files, so it
must run as the `lodeline-proxy` user. The shell that you run it from writes the
output files, so set `umask 077` first.

```sh
umask 077
sudo -u lodeline-proxy lodeline-proxy token new --config /etc/lodeline/proxy.yaml --principal alice > token-new.out
sed -n 's/^token: //p' token-new.out > alice.token && chmod 600 alice.token
sed -n 's/^verifier_sha256: //p' token-new.out > alice.verifier && rm token-new.out
```

Only the verifier goes into the server config (section 7). Hand `alice.token` to
the client's user and delete your copy. The principal id must match the id
pattern; a name with a space is refused.

---

## 7. Register, fingerprint, configure

The commands below run from a host that has the management certificate. They talk
to the server over HTTPS and read the bearer from a file; no token is ever an
argument.

```sh
CONN=(--server-url https://lodeline-server.example.internal:8443 \
      --cert mgmt.crt --key mgmt.key --ca host-ca.crt)

# 1. a pending entry
lodeline-server proxy register "${CONN[@]}" --token-file mgmt-identity.token \
  --requested-by alice --proxy-id px-example-01 --display-name "Example proxy"

# 2. bind the proxy certificate; the CLI computes the fingerprint
lodeline-server proxy fingerprint "${CONN[@]}" --token-file mgmt-identity.token \
  --proxy-id px-example-01 --cert-file proxy.crt
```

After step 2 the entry is active. Next, the config. Write `config-put.json`, with the
verifier from section 6.1 in place of the placeholder:

```json
{"expected_revision": 0,
 "config": {
  "schema_version": 1,
  "proxy_id": "px-example-01",
  "allowed_origins": [],
  "routes": [{"route_id": "r1", "upstream_id": "example-mcp",
              "upstream_url": "http://127.0.0.1:18080/mcp",
              "upstream_protocol": "2025-11-25",
              "credential_ref": "example-upstream"}],
  "principals": [{"principal_id": "alice", "actor_kind": "non_human",
                  "verifiers": [{"key_id": "alice-k1", "verifier": "<CONTENTS_OF_alice.verifier>"}],
                  "routes": ["r1"]}]}}
```

This first example uses the loopback case of section 2.1. Its origin must be listed
in `upstream_origins` in section 6, which also covers a public `https://` upstream.

```sh
lodeline-server proxy config-put "${CONN[@]}" --token-file mgmt-config.token \
  --proxy-id px-example-01 --file config-put.json
# 200 {"config_hash":"...","request_id":"...","revision":1}
```

The command sends the file as it is. It refuses a file over 1 MiB, a body the
server cannot parse, and a `config.proxy_id` that differs from `--proxy-id`.
A later change needs `"expected_revision"` set to the current revision.

- `allowed_origins: []` refuses every browser `Origin`. Clients that are not
  browsers send none, so the empty list is the right value for the clients in this
  guide.
- `actor_kind` is `non_human`. The proxy takes the principal from its own config, not from
  anything the client reports.
- A principal may use only the routes in its `routes` list. A request for any other
  route answers the same 401 as a wrong token.

---

## 8. Start the proxy

```sh
sudo systemctl enable --now lodeline-proxy
sudo -u lodeline-proxy lodeline-proxy health --config /etc/lodeline/proxy.yaml
```

`health` loads the bootstrap config, so like `token new` it runs as the
`lodeline-proxy` user. It reads the local status file and opens no listener:

```text
alive: true
proxy_id: px-example-01
epoch_id: ...
run_state: ...
config_state: Valid
forwarding: true
ingest_stopped: false
spool: ...
updated_at: ...
```

Give the proxy a few seconds: right after a start it may print the previous
process's status. `config_state: Valid` and `forwarding: true` mean it fetched
its config and relays calls. `alive: false` with `status: unavailable` means no
status file is readable (exit code 1).

The unit runs as `lodeline-proxy`, keeps its state in `/var/lib/lodeline-proxy`
(mode 0700) and waits for `time-sync.target`. It exits with status 2 on an invalid
config and does not restart on it. The SELinux domain for the proxy does not exist
yet, so on Rocky 9 the service runs unconfined. See
[packaging/README.md](../packaging/README.md) for the clock wait on reboot.

A test of the data plane, without a vendor client. The header comes from a file, so
the token is not on the `curl` command line (delete `alice.hdr` afterwards):

```sh
(umask 077; printf 'Authorization: Bearer %s\n' "$(cat alice.token)" > alice.hdr)
curl -sS -i http://127.0.0.1:8480/mcp/r1 \
  -H @alice.hdr \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
```

A wrong or missing token answers `401` with a bare `WWW-Authenticate: Bearer`.

---

## 9. Reading the server side

The server keeps the audit ledger and the proxy's status. Reading it needs the read
bearer of install-server.md section 5 (`LODELINE_SERVER_READ_TOKEN`; save it to
`read.token` with mode 0600) and a host class client certificate, which
is a different credential from the management ones. The management audit (who registered,
configured, disabled) is a CLI call:

```sh
lodeline-server proxy audit --server-url https://lodeline-server.example.internal:8443 \
  --cert mgmt.crt --key mgmt.key --ca host-ca.crt --token-file read.token
```

If the proxy cannot reach the server it keeps relaying until the config TTL
(section 5) ends, and its audit records wait in a local spool. After that deadline
it answers 401 and `health` shows `config_state: Expired`. When the server comes
back the proxy fetches a fresh config and forwarding resumes by itself.

---

## 10. What the proxy cannot see and refuses

Read this before you rely on a record.

**Protocol versions**
- Only protocol revision 2025-11-25 is relayed. A request for 2026-07-28 gets an
  empty 400.
- A client that offers 2025-06-18 works only when the upstream answers
  2025-11-25. An upstream that answers 2025-06-18 gets the session refused: the
  client sees a JSON-RPC error `-32603`, and the proxy ends the upstream session.
- After `initialize`, every request must carry `MCP-Protocol-Version: 2025-11-25`.
  A request without it, or with a different value, gets 400. Clients built on rmcp
  0.16 do not send it, so they do not work.

**Methods**
- `tasks/*` and `resources/subscribe` get `-32601 Method not found`.
- A JSON-RPC batch array is refused with 400.
- The GET stream is `405`. A notification that only a GET stream would carry never
  reaches the client.
- Server to client requests (sampling, elicitation, roots) are relayed inside the
  response stream of the call, but they are not recorded. The audit shows the call,
  not what the server asked the client in the middle of it.
- An MCP server that runs as a local stdio process is not visible: the proxy only
  sees HTTP.
- An upstream that needs per-user OAuth cannot be fronted. A route carries one
  static credential.

**Observe mode still refuses sometimes**

Observe mode does not block calls by policy, but it fails closed. The proxy
refuses a call rather than relay one it cannot record or has no valid config for.
This is the intended behavior, and no setting turns it off today. There are
three cases:

- **The audit spool is full.** A call is refused with 503 `audit_unavailable` and
  never reaches the upstream, because a call that cannot be recorded is not made.
  The spool holds 1 GiB by default and a config may only lower that size (section
  12). To fix it, get the records to the server: check that the server is
  reachable and accepting events (`health` shows `ingest_stopped: true` when it
  refuses them), and that the proxy host has free disk. Calls resume once the
  spool drains.
- **The config TTL has run out.** The proxy keeps using its last config only for
  `config_ttl_seconds` (section 5) after the last successful fetch. After that it
  forwards nothing: every call is a 401 and `health` shows `config_state: Expired`.
  To fix it, keep the server reachable from the proxy host. Forwarding resumes by
  itself after the next successful fetch. To ride out longer outages, raise
  `config_ttl_seconds` on the server (60 to 900).
- **After a restart.** A restarted proxy forwards nothing until it has fetched a
  config from the server, even if it had one before it stopped. Calls are a 401
  until then. Start the server first, or make sure it is reachable when the proxy
  starts.

**Network and platform**
- The upstream rules are in section 2.1.
- `allowed_origins: []` refuses every browser `Origin`.
- Linux only (section 1).

**The route path.** `/mcp/{route_id}` is the path the code serves. A comment in the
code still marks the shape as a candidate, so check this guide against the
release notes if you upgrade.

---

## 11. Clients

For each client below, put the route URL
(`http://127.0.0.1:8480/mcp/r1`) and the principal's token in the client's own
settings. Pass the token through an environment variable. Never paste a token into a
file that goes into version control; a project-scoped file such as `.mcp.json` or
`.cursor/mcp.json` is the one to be careful with.

`lodeline-proxy snippet` prints one entry of this kind for a route, so you do not
copy it by hand for each route. Give it `--client` (`claude-code`, `codex` or
`cursor`), `--name`, `--url` (the proxy listener, for example
`https://proxy.example.internal:8480`), `--route` and `--token-env` (the name of
the variable that holds the token):

```sh
lodeline-proxy snippet --client codex --name docs \
  --url https://proxy.example.internal:8480 --route r1 --token-env LODELINE_PROXY_TOKEN_DOCS
```

The entry goes to stdout and a line naming the client's file goes to stderr. The
command reads no config file, writes no file, makes no request and takes no token;
it refuses a `--token-env` that looks like a token value.

These snippets are **documented by the vendor and not tested through the proxy**.
Vendor pages were read on 2026-11-26, with Claude Code 2.1.332 and codex-cli 0.172.0
installed here (their help output was read for flag names; nothing was run
against a proxy).

Set the variable in the shell that starts the client:

```sh
export LODELINE_PROXY_TOKEN="$(cat ~/alice.token)"
```

### 11.1 Claude Code

Documented at <https://code.claude.com/docs/en/mcp>. Claude Code takes
`type: http` and a `headers` map. The `${VAR}` form in `headers` is expanded
from the environment when the config loads. Use a variable name of your own;
names that Claude Code treats as credentials read as empty in a remote
server's headers.

```sh
claude mcp add --transport http --scope user lodeline-proxy \
  http://127.0.0.1:8480/mcp/r1 --header 'Authorization: Bearer ${LODELINE_PROXY_TOKEN}'
```

The single quotes keep your shell from expanding the variable, so the file keeps
the text `${LODELINE_PROXY_TOKEN}`. The equivalent JSON, in `~/.claude.json` for the
user scope or `.mcp.json` for a project:

```json
{
  "mcpServers": {
    "lodeline-proxy": {
      "type": "http",
      "url": "http://127.0.0.1:8480/mcp/r1",
      "headers": { "Authorization": "Bearer ${LODELINE_PROXY_TOKEN}" }
    }
  }
}
```

An entry with a `url` and no `type` is read as a stdio server and fails. Run
`/mcp` in the client to see the connection.

### 11.2 Codex

Documented at <https://learn.chatgpt.com/docs/extend/mcp?surface=cli>. Codex takes
`url` with `bearer_token_env_var` (the variable's name, not its value) or
`http_headers`. The settings live in `~/.codex/config.toml`, or in
`.codex/config.toml` of a trusted project.

```toml
[mcp_servers.lodeline-proxy]
url = "http://127.0.0.1:8480/mcp/r1"
bearer_token_env_var = "LODELINE_PROXY_TOKEN"
```

The `codex mcp add` command has a flag for this too (`--url` with
`--bearer-token-env-var`):

```sh
codex mcp add lodeline-proxy --url http://127.0.0.1:8480/mcp/r1 \
  --bearer-token-env-var LODELINE_PROXY_TOKEN
```

Codex offers protocol 2025-06-18 in its handshake in the repo's earlier
observation, so it works only when the upstream answers 2025-11-25 (section 10).

### 11.3 Cursor

Status: **documented only**; this snippet was not run, and no Cursor session was
started against a proxy. Sources, read 2026-11-26:
<https://cursor.com/docs/context/mcp> and <https://cursor.com/docs/cli/mcp>. Cursor
takes `url` with `headers`, in `~/.cursor/mcp.json` or `.cursor/mcp.json`, and expands
`${env:NAME}`. The Cursor CLI has MCP commands (`agent mcp list`, `list-tools`,
`login`, `enable`, `disable`) but no command that adds a server, so you write the file
by hand.

```json
{
  "mcpServers": {
    "lodeline-proxy": {
      "url": "http://127.0.0.1:8480/mcp/r1",
      "headers": { "Authorization": "Bearer ${env:LODELINE_PROXY_TOKEN}" }
    }
  }
}
```

Limits to expect with Cursor. Each is marked as the Cursor research record marks it:

- **OAuth discovery on a 401** (reported by Cursor staff, 2026-03). On any 401 Cursor
  may start OAuth discovery, even with a static `Authorization` header and a bare
  `Bearer` challenge. The proxy then sees extra requests to `/.well-known/...` and
  `POST /register`, and a wrong token can show as an OAuth error instead of a plain
  401. The proxy answers those paths with `404 {"error":"not_found"}`, because they
  are not `/mcp/{route_id}`.
- **Empty 400 and SSE fallback** (reported by staff, 2026-09; for an empty body this
  is inferred). Cursor 3.30 release notes (documented) say servers that only support
  a newer stateless handshake now connect. If Cursor sends a modern request first, the
  proxy answers an empty 400. Cursor has been seen to read a 400 on its first request
  as "Streamable HTTP not supported" and fall back to an SSE GET. The proxy answers
  every GET with 405, so the connection would fail. If Cursor retries with
  `initialize` after the 400, the session works. Which one happens is unknown.
- **Retries** (documented in the 3.30 release notes: connections cut off
  mid-response are retried). What is retried is not stated. If Cursor sends a
  `tools/call` again, that is a second call and a second audit record (inferred): the
  proxy does not retry a call itself, and it does not merge a client's resend.
- **GET after `initialize`** (reported): Cursor opens the optional GET stream. A 405
  is the answer the MCP specification allows, and no Cursor source says Cursor
  accepts it (inferred).
- **Environment variables** (reported by a vendor doc and a third party guide): the
  editor needs the variable in its own process environment. A macOS Dock launch may
  not have it, and the header then goes out without the token. One user reported the
  editor and the CLI resolve different spellings (`${env:NAME}` and `${VAR}`); the
  docs do not say.
- **Older CLI builds** (reported, forum log of a 2025.09 build): the CLI offered
  protocol 2025-06-18 in `initialize`. What the current CLI offers is not checked.
  Section 10 says when that works.
- The CLI and the editor are documented to share the config files, not the client
  code, so a CLI result does not prove the editor.

---

## 12. Limits

Defaults live in the proxy. A config may only lower a value. They are first
values for the first deployment, not performance guarantees, and not measured
under load.

| Limit | Default | When it is hit |
|---|---|---|
| request body / header | 1 MiB / 32 KiB | 413 `request_too_large` / 431 `headers_too_large` before the upstream is called |
| one JSON response / one SSE event | 8 MiB / 1 MiB | a length the upstream declares over the limit is refused before streaming with 502 `upstream_response_too_large` (on `initialize`, HTTP 200 with JSON-RPC `-32603`). With no declared length, or for an SSE event over the limit, the stream is cut and the call outcome is unknown. |
| one call, whole response | 64 MiB | the same: a declared length over it is a 502, otherwise the stream is cut |
| concurrent calls: all / per route / per principal | 64 / 16 / 8 | 429 `too_many_requests`, no queue |
| sessions: all / per principal; idle | 256 / 32; 15 min with no call active | 429 `too_many_sessions` on `initialize` / the session ends |
| connect / response idle / whole call | 5 s / 30 s / 120 s | 504 `upstream_timeout` while the proxy waits to connect or for the upstream's response headers. A stream that has started and then stalls, or runs past the whole call limit, is cut. Reading a slow client request body past the call limit is 408 `request_timeout`. |
| shutdown grace | 30 s | calls still open then are recorded as unknown |
| audit event / spool | 16 KiB / 1 GiB | a full spool refuses new calls (503 `audit_unavailable`) |

A session DELETE counts against all three concurrent call limits.

The per-call and per-process bandwidth keys exist in the config, but the proxy does
not shape traffic with them yet. The full list is in `config/proxy.example.yaml`.

---

## 13. Troubleshooting

By the status the client sees:

| Client sees | Meaning and what to do |
|---|---|
| 401, `WWW-Authenticate: Bearer` | wrong, missing or foreign token; unknown route (the same answer on purpose); config not loaded or expired. Run `health`. |
| 400, empty body | protocol rule: no or wrong `MCP-Protocol-Version` after `initialize`, a 2026-07-28 request, a bad session header (section 10) |
| 403 `forbidden` | a browser `Origin` that is not in `allowed_origins`, or a `Host` header the loopback listener does not accept |
| 404 `not_found` | a path that is not `/mcp/{route_id}` |
| 404, empty body | a session the caller may not use, or one that ended |
| 405 | GET, or any method other than POST and DELETE |
| 429 `too_many_requests` or `too_many_sessions` | a concurrency or session limit |
| 502 `destination_refused` | the upstream resolves to an address the proxy refuses (section 2.1) |
| 502 `upstream_unavailable`, `upstream_unresolved` | the upstream is down, or its name does not resolve |
| 502 `upstream_rejected` | the upstream answered 401 or 403 to the stored credential, and the request had no JSON-RPC `id` (a notification) or was a session DELETE |
| HTTP 200 with JSON-RPC error `-32603` | the same upstream 401 or 403 on a request with an `id`: look here when the upstream secret is wrong |
| 502 `upstream_response_too_large`, `upstream_redirect_refused` | a declared response over the limit (section 12; on `initialize` it is HTTP 200 with `-32603` instead); an upstream redirect, which the proxy never follows |
| 503 `audit_unavailable` | the call could not be recorded: the audit spool is full, or writing it failed; see `health` and the server |
| 503 `session_unavailable` | the proxy could not make a session id |
| 504 `upstream_timeout` | no connection or response headers in time (section 12) |
| 408 `request_timeout` | the client sent its request body too slowly |

By `health`:

| Output | Meaning |
|---|---|
| `config_state: None` | no config applied yet; the server holds no config for this proxy id, or the fetch failed |
| `config_state: Valid`, `forwarding: true` | normal |
| `config_state: Expired` | no fresh config within the TTL; check the network and the server |
| `config_state: Disabled` | the proxy was disabled (section 14) |
| `ingest_stopped: true` | the server refuses the audit events; the spool grows |

The proxy logs to the journal: `journalctl -u lodeline-proxy`. `health` does not print
the last update error. The status file `/var/lib/lodeline-proxy/status.json` on the proxy
host holds it as one of `fetch_failed`, `validation_failed`, `stale_revision`,
`apply_failed` or `config_hash_mismatch`. `GET /v1/proxies/{id}` on the server shows
`config_state` and `config_in_sync`, not the error. `apply_failed` right after
`config-put` usually means an upstream origin is missing from `upstream_origins`
(section 6).

---

## 14. Disable, rotate, retire

| Task | Command | Token scope |
|---|---|---|
| stop forwarding | `lodeline-server proxy disable ... --proxy-id px-example-01` | `config` |
| resume | `lodeline-server proxy enable ...` | `identity` |
| remove for good | `lodeline-server proxy retire ...` | `identity` |
| remove one tool's stored content | `lodeline-server proxy delete-content ... --metadata-ref <ref>` | `identity` |

These commands take the same connection flags as section 7. Within one poll interval after
`disable`, the proxy answers 401 and `health` shows `config_state: Disabled`.
Read the result with `lodeline-server proxy audit` (section 9).

**Rotate a client token.** Make a second token for the principal
(`token new`; at most 2 verifiers per principal, and its `key_id` must differ from the
old one), and add its verifier as a second entry in `verifiers`. Keep the whole `config` in the file (routes, `allowed_origins`,
the other principals), set `expected_revision` to the current revision, and run
`config-put`. Move the client to the new token, then `config-put` again without the
old verifier. Run `token new` as in section 6.1.

**Rotate a management token.** Make the new one with `verifier-new`, add its
entry to the verifier file next to the old one, then remove the old entry. Replace
the file with `mv`, as in section 5.1.

**Rotate the proxy certificate.** Sign a new certificate, run
`lodeline-server proxy fingerprint "${CONN[@]}" --token-file mgmt-identity.token
--proxy-id px-example-01 --cert-file proxy.crt` for the new file (`CONN` as in section 7).
The server keeps the old fingerprint active until the proxy connects with the new
certificate. Then replace the files and restart the proxy.

**Teardown of a test.** Stop the unit, `retire` the proxy, delete the token files
and the throwaway keys.

---

## 15. Related documents

- [install-server.md](install-server.md): the server this proxy reports to.
- [packaging/README.md](../packaging/README.md): packages and the unit.
- [Proxy specification](specs/lodeline-proxy/README.md): requirements, decisions and the
  state of the work.
