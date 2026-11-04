#!/usr/bin/env bash
# See SKILL.md in this directory. macOS and Linux only.
set -euo pipefail

skill="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo="$(cd "$skill/../../.." && pwd -P)"
base="${TMPDIR:-/tmp}"
base="${base%/}/lodeline-manager-verify"

die() {
  echo "drive.sh: $*" >&2
  exit 2
}

usage() {
  cat >&2 <<'USAGE'
usage: drive.sh new
       drive.sh doctor <run>
       drive.sh e2e <run> <label> [playwright args...]
       drive.sh api <run> <label> <METHOD> <path> [json-body]
       drive.sh db <run> <label> <sql>
       drive.sh cleanup <run>
USAGE
  exit 2
}

case "$base" in
  "$repo"/*) die "TMPDIR is inside the repo, so evidence would land in the tree" ;;
esac

set_paths() {
  run_dir="$base/$1"
  scratch="$run_dir/scratch"
  evidence="$run_dir/evidence"
}

select_run() {
  [[ "${1:-}" =~ ^[0-9]{8}-[0-9]{6}-[0-9]+$ ]] || die "bad run id: ${1:-<none>}"
  set_paths "$1"
  [ -d "$run_dir" ] || die "no such run: $run_dir"
}

require_live_scratch() {
  [ -e "$scratch/pid" ] || die "scratch already cleaned up: $scratch"
}

claim_label() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] || die "bad label: $1"
  [ ! -e "$evidence/$1.cmd" ] || die "evidence label already used: $1"
}

http() {
  curl -q -sS --noproxy '*' --max-time 10 "$@"
}

url() {
  echo "http://127.0.0.1:$(cat "$scratch/port")$1"
}

# A matching start time rules out a recycled pid.
is_server_up() {
  [ -e "$scratch/pid" ] &&
    [ "$(ps -o lstart= -p "$(sed -n 1p "$scratch/pid")" 2>/dev/null || true)" = "$(sed -n 2p "$scratch/pid")" ]
}

stop_server() {
  is_server_up || return 0
  local pid
  pid="$(sed -n 1p "$scratch/pid")"
  kill "$pid"
  for _ in $(seq 1 12); do
    kill -0 "$pid" 2>/dev/null || break
    /bin/sleep 0.5
  done
  if kill -0 "$pid" 2>/dev/null; then kill -9 "$pid"; fi
  echo "stopped server pid $pid"
}

cmd_new() {
  local id hash port
  id="$(date +%Y%m%d-%H%M%S)-$$"
  set_paths "$id"
  mkdir -p "$evidence" "$scratch"

  touch "$scratch/built"
  if ! (cd "$repo/web" && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && npm run build &&
    cd .. && LODELINE_MANAGER_REQUIRE_DIST=1 cargo build --release --locked) \
    >"$evidence/build.log" 2>&1; then
    tail -n 20 "$evidence/build.log" >&2
    die "build failed; see $evidence/build.log"
  fi
  echo "${CARGO_TARGET_DIR:-$repo/target}/release/lodeline-manager" >"$scratch/bin"

  hash="$(sed -n "s/^const TEST_ADMIN_HASH = '\(.*\)';$/\1/p" "$repo/web/playwright.config.ts")"
  [ -n "$hash" ] || die "TEST_ADMIN_HASH not found in web/playwright.config.ts"
  port="$(node -e "const s=require('net').createServer().listen(0,'127.0.0.1',()=>{console.log(s.address().port);s.close()})")"
  echo "$port" >"$scratch/port"

  # env -i keeps a real LODELINE_SERVER_* or OIDC_* variable in the caller's shell away from the binary.
  (
    cd "$scratch"
    env -i "PATH=/usr/bin:/bin" "HOME=$scratch" "LISTEN_ADDR=127.0.0.1:$port" MOCK_FLEET=1 \
      "TRIAGE_DB_PATH=$scratch/triage.sqlite" ADMIN_USERNAME=admin "ADMIN_PASSWORD_BCRYPT=$hash" \
      "JWT_SECRET=$(openssl rand -hex 32)" LODELINE_INSECURE_COOKIE=1 \
      "$(cat "$scratch/bin")" >"$evidence/server.stdout" 2>"$evidence/server.stderr" </dev/null &
    { echo "$!"; ps -o lstart= -p "$!"; } >"$scratch/pid"
  )

  local ready=0
  for _ in $(seq 1 60); do
    is_server_up || break
    if http -f -o /dev/null "$(url /api/health)" 2>/dev/null; then
      ready=1
      break
    fi
    /bin/sleep 0.5
  done
  if [ "$ready" != 1 ]; then
    stop_server >&2
    die "server did not become ready; see $evidence/server.stderr"
  fi

  {
    git -C "$repo" rev-parse HEAD
    git -C "$repo" status --short .
    echo "binary $(cat "$scratch/bin")"
    echo "port $port"
    http "$(url /api/health)"
  } >"$evidence/build.txt"
  echo "$id"
}

test_login_user() {
  http -f -o /dev/null -c "$scratch/doctor-cookies" -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"test-password"}' "$(url /api/v1/auth/login)" &&
    http -b "$scratch/doctor-cookies" "$(url /api/v1/auth/me)" | jq -r .username
}

check() {
  if "${@:2}"; then
    echo "[OK]   $1"
  else
    echo "[FAIL] $1"
    fail=1
  fi
}

cmd_doctor() {
  select_run "${1:-}"
  require_live_scratch
  local fail=0 pid port want chrome
  pid="$(sed -n 1p "$scratch/pid")"
  port="$(cat "$scratch/port")"
  want="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$repo/Cargo.toml" | head -n 1)"
  chrome="$(cd "$repo/web" && node -e "console.log(require('playwright-core').chromium.executablePath())")"
  check "pid $pid is the server this run started" is_server_up
  check "port $port is held by pid $pid" test "$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)" = "$pid"
  check "/api/health reports build $want" test "$(http "$(url /api/health)" | jq -r .version)" = "$want"
  check "server runs in mock-fleet mode with its SQLite file in scratch" \
    grep -q "mode=mock-fleet addr=127.0.0.1:$port db=$scratch/triage.sqlite" "$evidence/server.stderr"
  check "no source changed since the build" test -z "$(find "$repo/src" "$repo/web/src" "$repo/web/public" \
    "$repo/build.rs" "$repo/Cargo.toml" "$repo/Cargo.lock" "$repo/testdata/mock-fleet.json" \
    "$repo/web/index.html" "$repo/web/package-lock.json" -type f -newer "$scratch/built")"
  check "test login resolves to admin" test "$(test_login_user)" = admin
  check "Chromium for this Playwright version is installed" test -x "$chrome"
  rm -f "$scratch/doctor-cookies"
  echo "[INFO] url: $(url /)"
  echo "[INFO] evidence: $evidence"
  return "$fail"
}

cmd_e2e() {
  select_run "${1:-}"
  require_live_scratch
  [ $# -ge 2 ] || usage
  local label="$2" code=0
  shift 2
  claim_label "$label"
  { printf 'playwright test '; printf '%q ' "$@"; echo; } >"$evidence/$label.cmd"
  (
    cd "$repo/web"
    exec env -u CI "PORT=$(cat "$scratch/port")" "LODELINE_VERIFY_OUTPUT=$evidence/$label" \
      "E2E_AUTH_STATE=$scratch/auth.json" \
      npx --no-install playwright test --config "$skill/playwright.verify.config.mts" "$@"
  ) >"$evidence/$label.stdout" 2>"$evidence/$label.stderr" || code=$?
  echo "$code" >"$evidence/$label.exit"
  echo "--- $label exit=$code artifacts=$evidence/$label"
  tail -n 40 "$evidence/$label.stdout"
  if [ -s "$evidence/$label.stderr" ]; then
    echo "--- stderr"
    tail -n 20 "$evidence/$label.stderr"
  fi
  return "$code"
}

cmd_api() {
  select_run "${1:-}"
  require_live_scratch
  [ $# -ge 4 ] && [ $# -le 5 ] || usage
  local label="$2" method="$3" path="$4" body="${5:-}" status
  case "$path" in /*) ;; *) die "path must start with /: $path" ;; esac
  claim_label "$label"
  local args=(-D "$scratch/headers" -o "$evidence/$label.body" -w '%{http_code}'
    -b "$scratch/cookies" -c "$scratch/cookies" -X "$method")
  [ -z "$body" ] || args+=(-H 'Content-Type: application/json' --data-raw "$body")
  printf '%s %s\n%s\n' "$method" "$path" "$body" >"$evidence/$label.cmd"
  status="$(http "${args[@]}" "$(url "$path")")"
  echo "$status" >"$evidence/$label.status"
  # The session JWT stays in scratch. Case-insensitive so a server that lowercases headers is covered.
  sed -E 's/^([Ss][Ee][Tt]-[Cc][Oo][Oo][Kk][Ii][Ee]: [^=]+=)[^;]*/\1<session>/' "$scratch/headers" \
    >"$evidence/$label.headers"
  echo "--- $label $method $path status=$status"
  head -c 2000 "$evidence/$label.body"
  echo
}

cmd_db() {
  select_run "${1:-}"
  require_live_scratch
  [ $# -eq 3 ] || usage
  local label="$2" sql="$3"
  case "${sql#"${sql%%[![:space:]]*}"}" in .*) die "sql must not start with a sqlite dot-command: $sql" ;; esac
  claim_label "$label"
  echo "$sql" >"$evidence/$label.cmd"
  sqlite3 -readonly -header "$scratch/triage.sqlite" "$sql" | tee "$evidence/$label.rows"
}

cmd_cleanup() {
  select_run "${1:-}"
  stop_server
  rm -rf "$scratch"
  echo "scratch removed; evidence kept at $evidence"
  ls "$evidence"
}

case "${1:-}" in
  new) cmd_new ;;
  doctor | e2e | api | db | cleanup)
    c="$1"
    shift
    "cmd_$c" "$@"
    ;;
  *) usage ;;
esac
