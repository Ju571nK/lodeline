#!/usr/bin/env bash
# See SKILL.md in this directory. macOS and Linux only.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
bin="$repo/target/debug"
base="${TMPDIR:-/tmp}"
base="${base%/}/lodeline-verify"
packages=(-p lodeline-agent -p lodeline-hook -p lodeline-signer -p lodeline-server)
binaries=(lodeline lodeline-hook lodeline-sign lodeline-server)

die() {
  echo "drive.sh: $*" >&2
  exit 2
}

usage() {
  cat >&2 <<'USAGE'
usage: drive.sh new
       drive.sh doctor <run>
       drive.sh run <run> <label> -- <command> [args...]
       drive.sh bg <run> <label> -- <command> [args...]
       drive.sh cleanup <run>
USAGE
  exit 2
}

# The binaries fall back to /var/run, /var/lib and /etc as root, and no variable overrides that.
[ "$(id -u)" != 0 ] || die "refusing to run as root"

case "$base" in
  "$repo"/*) die "TMPDIR is inside the repo, so evidence would land in the tree" ;;
esac

select_run() {
  [[ "${1:-}" =~ ^[0-9]{8}-[0-9]{6}-[0-9]+$ ]] || die "bad run id: ${1:-<none>}"
  run_dir="$base/$1"
  scratch="$run_dir/scratch"
  evidence="$run_dir/evidence"
  [ -d "$run_dir" ] || die "no such run: $run_dir"
}

sandbox_env() {
  sandbox=(
    "HOME=$scratch/home"
    "USER=verify"
    "LANG=C.UTF-8"
    "PATH=$bin:/usr/bin:/bin"
    "TMPDIR=$scratch/tmp"
    "XDG_CONFIG_HOME=$scratch/config"
    "XDG_DATA_HOME=$scratch/data"
    "XDG_STATE_HOME=$scratch/state"
    "XDG_RUNTIME_DIR=$scratch/run"
    # Without these, lodeline-hook prefers /var/run/lodeline/*.sock whenever that path exists.
    "LODELINE_HOOK_SOCKET=$scratch/run/hook.sock"
    "LODELINE_HOOK_DECIDE_SOCKET=$scratch/run/hook-decide.sock"
  )
}

claim_label() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] || die "bad label: $1"
  [ ! -e "$evidence/$1.cmd" ] || die "evidence label already used: $1"
}

cmd_new() {
  (cd "$repo" && cargo build --locked "${packages[@]}")
  local id
  id="$(date +%Y%m%d-%H%M%S)-$$"
  run_dir="$base/$id"
  mkdir -p "$run_dir/evidence"
  for d in home project config data state run tmp pids; do
    mkdir -p "$run_dir/scratch/$d"
  done
  touch "$run_dir/scratch/built"
  git -C "$repo" rev-parse HEAD >"$run_dir/evidence/build.txt"
  git -C "$repo" status --short >>"$run_dir/evidence/build.txt"
  for b in "${binaries[@]}"; do
    "$bin/$b" --version >>"$run_dir/evidence/build.txt"
  done
  echo "$id"
}

cmd_doctor() {
  select_run "${1:-}"
  sandbox_env
  local fail=0 want got newer
  [ -d "$scratch/home" ] || die "scratch already cleaned up: $scratch"
  want="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml")"
  for b in "${binaries[@]}"; do
    got="$("$bin/$b" --version 2>/dev/null | awk '{print $NF}')" || got=""
    if [ "$got" = "$want" ]; then
      echo "[OK]   $b $got"
    else
      echo "[FAIL] $b reports '${got:-missing}', workspace is $want"
      fail=1
    fi
  done
  newer="$(find "$repo/crates" "$repo/Cargo.toml" "$repo/Cargo.lock" -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.lock' \) -newer "$scratch/built" | wc -l | tr -d ' ')"
  if [ "$newer" = 0 ]; then
    echo "[OK]   no source changed since the build"
  else
    echo "[FAIL] $newer source file(s) changed since the build; start a new run"
    fail=1
  fi
  # lodeline doctor prints the state.db path it resolved, so this tests the real resolution.
  local report
  report="$(cd "$scratch/project" && env -i "${sandbox[@]}" "$bin/lodeline" doctor 2>&1)" || true
  if [[ "$report" == *"$scratch/state/"* ]]; then
    echo "[OK]   lodeline resolves state.db inside $scratch"
  else
    echo "[FAIL] lodeline does not resolve state.db inside $scratch"
    fail=1
  fi
  local p
  for p in "$scratch"/pids/*; do
    [ -e "$p" ] || continue
    if [ "$(ps -o lstart= -p "$(sed -n 1p "$p")" 2>/dev/null || true)" = "$(sed -n 2p "$p")" ]; then
      echo "[OK]   ${p##*/} is up with pid $(sed -n 1p "$p")"
    else
      echo "[FAIL] ${p##*/} has exited; see $evidence/${p##*/}.stderr"
      fail=1
    fi
  done
  echo "[INFO] evidence: $evidence"
  return "$fail"
}

cmd_run() {
  select_run "${1:-}"
  local label="${2:-}"
  [ "${3:-}" = "--" ] && [ $# -ge 4 ] || usage
  shift 3
  claim_label "$label"
  sandbox_env
  printf '%q ' "$@" >"$evidence/$label.cmd"
  echo >>"$evidence/$label.cmd"
  local code=0
  (cd "$scratch/project" && exec env -i "${sandbox[@]}" "$@") \
    >"$evidence/$label.stdout" 2>"$evidence/$label.stderr" || code=$?
  echo "$code" >"$evidence/$label.exit"
  echo "--- $label exit=$code stdout=$(wc -c <"$evidence/$label.stdout" | tr -d ' ') bytes"
  head -n 40 "$evidence/$label.stdout"
  if [ -s "$evidence/$label.stderr" ]; then
    echo "--- stderr"
    head -n 20 "$evidence/$label.stderr"
  fi
  return "$code"
}

cmd_bg() {
  select_run "${1:-}"
  local label="${2:-}"
  [ "${3:-}" = "--" ] && [ $# -ge 4 ] || usage
  shift 3
  claim_label "$label"
  sandbox_env
  printf '%q ' "$@" >"$evidence/$label.cmd"
  echo >>"$evidence/$label.cmd"
  (
    cd "$scratch/project"
    env -i "${sandbox[@]}" "$@" >"$evidence/$label.stdout" 2>"$evidence/$label.stderr" </dev/null &
    { echo "$!"; ps -o lstart= -p "$!"; } >"$scratch/pids/$label"
  )
  echo "$label started with pid $(sed -n 1p "$scratch/pids/$label")"
}

cmd_cleanup() {
  select_run "${1:-}"
  local p pid
  for p in "$scratch"/pids/*; do
    [ -e "$p" ] || continue
    pid="$(sed -n 1p "$p")"
    # A matching start time rules out a recycled pid.
    if [ "$(ps -o lstart= -p "$pid" 2>/dev/null || true)" = "$(sed -n 2p "$p")" ]; then
      kill "$pid"
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$pid" 2>/dev/null || break
        /bin/sleep 0.5
      done
      kill -0 "$pid" 2>/dev/null && kill -9 "$pid"
      echo "stopped ${p##*/} pid $pid"
    fi
  done
  rm -rf "$scratch"
  echo "scratch removed; evidence kept at $evidence"
  ls "$evidence"
}

case "${1:-}" in
  new) cmd_new ;;
  doctor | run | bg | cleanup)
    c="$1"
    shift
    "cmd_$c" "$@"
    ;;
  *) usage ;;
esac
