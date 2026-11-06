#!/usr/bin/env bash
# Throwaway single-host stack for Lodeline Proxy load runs (validation.md):
# lodeline-server as the local control-plane collector, lodeline-proxy, and the
# synthetic load server, all on loopback, with N principals over R routes.
#
#   stack.sh up WORK      PKI, server, principals, config, load server, proxy
#   stack.sh stats WORK   proxy resource use (peak RSS, CPU time, open FDs, spool)
#   stack.sh down WORK    stop everything and delete WORK (tokens and keys live there)
#
# Environment (defaults in brackets):
#   BIN          dir with lodeline-server, lodeline-proxy, lodeline-proxy-loadgen [target/release]
#   PRINCIPALS   [8]   ROUTES [4]   (concurrency C needs C/8 principals and C/16 routes)
#   SERVER_PORT  [18443]   PROXY_PORT [18480]   LOAD_PORT [18090]
#   STATE_DIR    proxy state dir [WORK/proxy-state]; must not exist yet
#   PROXY_WRAP   command prefix for the proxy, e.g. a systemd-run scope (README)
#   LOAD_WRAP    command prefix for the load server and lodeline-server, e.g. taskset -c 2,3
# Needs bash, openssl, python3 and curl. Prints no secret.
set -euo pipefail
umask 077

cmd="${1:?usage: stack.sh up|stats|down WORK}"
W="${2:?usage: stack.sh up|stats|down WORK}"
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
BIN="${BIN:-$ROOT/target/release}"
PRINCIPALS="${PRINCIPALS:-8}"; ROUTES="${ROUTES:-4}"
SERVER_PORT="${SERVER_PORT:-18443}"; PROXY_PORT="${PROXY_PORT:-18480}"; LOAD_PORT="${LOAD_PORT:-18090}"
PID_NAME=px-load
PROXY_WRAP="${PROXY_WRAP:-}"; LOAD_WRAP="${LOAD_WRAP:-}"
die() { echo "stack.sh: $*" >&2; exit 1; }
pids() { pgrep -f "$1" || true; }

up() {
  [ -e "$W" ] && die "$W exists; run: stack.sh down $W"
  for b in lodeline-server lodeline-proxy lodeline-proxy-loadgen; do
    [ -x "$BIN/$b" ] || die "missing $BIN/$b (cargo build --release -p lodeline-server -p lodeline-proxy -p lodeline-proxy-loadgen)"
  done
  mkdir -p "$W/pki" "$W/server/state" "$W/server/events"
  W=$(cd "$W" && pwd)
  local state="${STATE_DIR:-$W/proxy-state}"
  [ -e "$state" ] && die "STATE_DIR $state exists"
  cd "$W/pki"
  for ca in host proxy; do
    openssl req -x509 -new -newkey rsa:2048 -nodes -keyout $ca-ca.key -out $ca-ca.crt -days 2 \
      -subj "/CN=lodeline-load-$ca-ca" -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" 2>/dev/null
  done
  cat host-ca.crt proxy-ca.crt >client-ca-bundle.pem
  local leaf='basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer'
  printf '%s\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n' "$leaf" >server.ext
  printf '%s\nextendedKeyUsage=clientAuth\n' "$leaf" >client.ext
  printf '%s\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:%s.proxy.sigil.invalid\n' "$leaf" "$PID_NAME" >proxy.ext
  mkleaf() {
    openssl req -new -newkey rsa:2048 -nodes -keyout "$2.key" -out "$2.csr" -subj "/CN=$3" 2>/dev/null
    openssl x509 -req -in "$2.csr" -CA "$1.crt" -CAkey "$1.key" -set_serial "0x$(openssl rand -hex 8)" \
      -days 2 -extfile "$4" -out "$2.crt" 2>/dev/null
  }
  mkleaf host-ca server lodeline-load-server server.ext
  mkleaf host-ca mgmt lodeline-load-mgmt client.ext
  mkleaf proxy-ca proxy "$PID_NAME" proxy.ext

  local fp
  fp=$(python3 -B "$ROOT/scripts/proxy-smoke/b3fp.py" mgmt.crt | cut -d' ' -f1)
  "$BIN/lodeline-server" proxy verifier-new --scope identity --caller-fingerprint "$fp" --key-id load-identity \
    >mgmt-identity.token 2>identity-entry.txt
  "$BIN/lodeline-server" proxy verifier-new --scope config --caller-fingerprint "$fp" --key-id load-config \
    >mgmt-config.token 2>config-entry.txt
  python3 -B - identity-entry.txt config-entry.txt >management-verifiers.json <<'EOF'
import json, sys
entries = []
for p in sys.argv[1:]:
    t = open(p).read()
    entries.append(json.loads(t[t.index("{"):]))
print(json.dumps({"entries": entries}))
EOF
  rm -f identity-entry.txt config-entry.txt
  printf 'Authorization: Bearer %s\n' "$(cat mgmt-config.token)" >mgmt-config.hdr

  cat >"$W/server/server.yaml" <<EOF
bind: "127.0.0.1:$SERVER_PORT"
tls_cert_path: "$W/pki/server.crt"
tls_key_path: "$W/pki/server.key"
client_ca_path: "$W/pki/client-ca-bundle.pem"
events_out_dir: "$W/server/events"
policy_bundle_path: "$W/server/state/signed-policy.json"
high_water_path: "$W/server/state/high_water.json"
proxy:
  ca_path: "$W/pki/proxy-ca.crt"
  registry_path: "$W/server/state/proxies.json"
  registry_init: true
  management_verifiers: "$W/pki/management-verifiers.json"
  config_ttl_seconds: 900
EOF
  # shellcheck disable=SC2086
  $LOAD_WRAP "$BIN/lodeline-server" serve --config "$W/server/server.yaml" >"$W/server/server.log" 2>&1 </dev/null &
  local url="https://127.0.0.1:$SERVER_PORT" i
  for i in $(seq 60); do
    curl -s -o /dev/null --cacert host-ca.crt --cert mgmt.crt --key mgmt.key "$url/" && break
    [ "$i" = 60 ] && { tail -5 "$W/server/server.log" >&2; die "server did not start"; }
    /bin/sleep 0.5
  done
  local conn=(--server-url "$url" --cert mgmt.crt --key mgmt.key --ca host-ca.crt --token-file mgmt-identity.token)
  "$BIN/lodeline-server" proxy register "${conn[@]}" --requested-by stack.sh --proxy-id "$PID_NAME" --display-name load >/dev/null
  "$BIN/lodeline-server" proxy fingerprint "${conn[@]}" --proxy-id "$PID_NAME" --cert-file proxy.crt >/dev/null

  "$BIN/lodeline-proxy-loadgen" principals --out "$W/load" --proxy-id "$PID_NAME" --listen "127.0.0.1:$PROXY_PORT" \
    --upstream-url "http://127.0.0.1:$LOAD_PORT/mcp" --credential-ref load-upstream \
    --principals "$PRINCIPALS" --routes "$ROUTES"
  python3 -B -c 'import json,sys; print(json.dumps({"expected_revision": 0, "config": json.load(open(sys.argv[1]))}))' \
    "$W/load/config.json" >"$W/load/config-put.json"
  curl -sS --fail-with-body -o /dev/null --cacert host-ca.crt --cert mgmt.crt --key mgmt.key -H @mgmt-config.hdr \
    -H 'Content-Type: application/json' -X PUT --data-binary @"$W/load/config-put.json" "$url/v1/proxies/$PID_NAME/config"
  echo "config: $PRINCIPALS principals over $ROUTES routes applied on the server"

  openssl rand -hex 32 >"$W/pki/upstream.secret"
  mkdir -p "$state"; chmod 700 "$state"
  cat >"$W/proxy.yaml" <<EOF
proxy_id: "$PID_NAME"
listen: "127.0.0.1:$PROXY_PORT"
control_plane_url: "$url"
state_dir: "$state"
client_cert_file: "$W/pki/proxy.crt"
client_key_file: "$W/pki/proxy.key"
ca_file: "$W/pki/host-ca.crt"
credentials:
  load-upstream:
    secret_file: "$W/pki/upstream.secret"
    upstream_origins: ["http://127.0.0.1:$LOAD_PORT"]
EOF
  "$BIN/lodeline-proxy" check-config --config "$W/proxy.yaml" >/dev/null

  # shellcheck disable=SC2086
  $LOAD_WRAP "$BIN/lodeline-proxy-loadgen" serve --listen "127.0.0.1:$LOAD_PORT" >"$W/load-server.log" 2>&1 </dev/null &
  # shellcheck disable=SC2086
  $PROXY_WRAP "$BIN/lodeline-proxy" run --config "$W/proxy.yaml" >"$W/proxy.log" 2>&1 </dev/null &
  for i in $(seq 60); do
    "$BIN/lodeline-proxy" health --config "$W/proxy.yaml" 2>/dev/null | grep -q '^forwarding: true' && break
    [ "$i" = 60 ] && { tail -5 "$W/proxy.log" >&2; die "proxy is not forwarding"; }
    /bin/sleep 0.5
  done
  echo "proxy: forwarding on 127.0.0.1:$PROXY_PORT, state $state"
  echo "run:   $BIN/lodeline-proxy-loadgen run --direct http://127.0.0.1:$LOAD_PORT/mcp --targets $W/load/targets.json --rate 100 --concurrency 32 --out REPORT.json"
}

stats() {
  local p
  # Anchored: a sudo or systemd-run wrapper carries the same command line.
  p=$(pids "^[^ ]*lodeline-proxy run --config $W/proxy.yaml" | head -1)
  [ -n "$p" ] || die "no proxy running for $W"
  if [ -r "/proc/$p/status" ]; then
    grep -E '^(VmHWM|VmRSS):' "/proc/$p/status" | tr -s ' \t' ' ' | tr '\n' ' '
    awk '{printf "cpu_s=%.2f ", ($14+$15)/100}' "/proc/$p/stat"
    echo "fds=$(find "/proc/$p/fd" -mindepth 1 -maxdepth 1 | wc -l)"
    local cg
    cg="/sys/fs/cgroup$(cut -d: -f3 "/proc/$p/cgroup" | head -1)"
    for f in memory.peak memory.max cpuset.cpus.effective; do
      [ -r "$cg/$f" ] && echo "cgroup $f=$(cat "$cg/$f")"
    done
  else
    ps -o rss=,time= -p "$p" | awk '{print "rss_kib=" $1 " cpu_time=" $2}'
    echo "fds=$(lsof -p "$p" 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"
  fi
  local state
  state=$(sed -n 's/^state_dir: "\(.*\)"$/\1/p' "$W/proxy.yaml")
  echo "spool: $(du -sk "$state" | cut -f1) KiB in state_dir"
}

down() {
  [ -f "$W/proxy.yaml" ] || die "$W is not a stack dir"
  local pat state
  state=$(sed -n 's/^state_dir: "\(.*\)"$/\1/p' "$W/proxy.yaml")
  for pat in "lodeline-proxy run --config $W/proxy.yaml" "lodeline-proxy-loadgen serve --listen 127.0.0.1:$LOAD_PORT" \
    "lodeline-server serve --config $W/server/server.yaml"; do
    # shellcheck disable=SC2046
    [ -n "$(pids "$pat")" ] && kill $(pids "$pat") 2>/dev/null || true
  done
  /bin/sleep 2
  for pat in "lodeline-proxy run --config $W/proxy.yaml" "lodeline-proxy-loadgen serve --listen 127.0.0.1:$LOAD_PORT"; do
    # shellcheck disable=SC2046
    [ -n "$(pids "$pat")" ] && kill -9 $(pids "$pat") 2>/dev/null || true
  done
  rm -rf "$W" "$state"
  echo "down: processes stopped, $W and the proxy state removed"
}

case "$cmd" in
  up) up ;;
  stats) stats ;;
  down) down ;;
  *) die "usage: stack.sh up|stats|down WORK" ;;
esac
