#!/bin/sh
# install.sh의 프로파일→BINARIES 매핑을 dry-run으로 검증 (#134).
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SH="$ROOT/install.sh"

run() { LODELINE_PROFILE="$1" LODELINE_PROFILE_DRYRUN=1 sh "$SH" 2>/dev/null; }

fail=0
assert_eq() { # $1=desc $2=expected $3=actual
  if [ "$2" != "$3" ]; then printf 'FAIL: %s\n  want: %s\n  got:  %s\n' "$1" "$2" "$3"; fail=1
  else printf 'ok: %s\n' "$1"; fi
}

assert_eq "personal subset" "lodeline lodeline-mcp lodeline-hook" "$(run personal)"
assert_eq "fleet superset" "lodeline lodeline-mcp lodeline-hook lodeline-sender lodeline-server lodeline-sign" "$(run fleet)"
assert_eq "default is personal" "lodeline lodeline-mcp lodeline-hook" "$(LODELINE_PROFILE_DRYRUN=1 sh "$SH" 2>/dev/null)"

if LODELINE_PROFILE=bogus LODELINE_PROFILE_DRYRUN=1 sh "$SH" >/dev/null 2>&1; then
  echo "FAIL: bogus profile should exit non-zero"; fail=1
else echo "ok: bogus profile rejected"; fi

# platform -> release target mapping (#171: aarch64 Linux must resolve, not err).
tgt() { LODELINE_UNAME_S="$1" LODELINE_UNAME_M="$2" LODELINE_TARGET_DRYRUN=1 sh "$SH" 2>/dev/null; }
assert_eq "linux x86_64 target"  "x86_64-unknown-linux-musl"  "$(tgt Linux x86_64)"
assert_eq "linux aarch64 target" "aarch64-unknown-linux-musl" "$(tgt Linux aarch64)"
assert_eq "linux arm64 target"   "aarch64-unknown-linux-musl" "$(tgt Linux arm64)"
assert_eq "macos arm64 target"   "aarch64-apple-darwin"       "$(tgt Darwin arm64)"

if tgt Darwin x86_64 >/dev/null 2>&1; then
  echo "FAIL: intel mac should exit non-zero"; fail=1
else echo "ok: intel mac rejected"; fi

# base URL resolution (#182): default = GitHub Releases; LODELINE_BASE_URL overrides.
# LODELINE_URL_DRYRUN prints "<base>/<asset>" then "<base>/SHA256SUMS"; take line 1.
asset_url() { # $1=base-url-or-empty
  LODELINE_UNAME_S=Linux LODELINE_UNAME_M=x86_64 LODELINE_VERSION=v0.6.2 \
    LODELINE_BASE_URL="$1" LODELINE_URL_DRYRUN=1 sh "$SH" 2>/dev/null | head -1
}
assert_eq "default base = github releases" \
  "https://github.com/Ju571nK/lodeline/releases/download/v0.6.2/lodeline-0.6.2-x86_64-unknown-linux-musl.tar.gz" \
  "$(asset_url '')"
assert_eq "LODELINE_BASE_URL overrides base" \
  "https://srv.example:8443/v1/artifacts/lodeline-0.6.2-x86_64-unknown-linux-musl.tar.gz" \
  "$(asset_url 'https://srv.example:8443/v1/artifacts')"

# LODELINE_BASE_TOKEN without LODELINE_BASE_URL must fail closed.
if LODELINE_UNAME_S=Linux LODELINE_UNAME_M=x86_64 LODELINE_VERSION=v0.6.2 \
   LODELINE_BASE_TOKEN=x LODELINE_URL_DRYRUN=1 sh "$SH" >/dev/null 2>&1; then
  echo "FAIL: LODELINE_BASE_TOKEN without LODELINE_BASE_URL should exit non-zero"; fail=1
else echo "ok: LODELINE_BASE_TOKEN requires LODELINE_BASE_URL"; fi

# LODELINE_BASE_URL without LODELINE_VERSION must fail closed (no GitHub 'latest').
if LODELINE_UNAME_S=Linux LODELINE_UNAME_M=x86_64 \
   LODELINE_BASE_URL=https://srv.example/v1/artifacts LODELINE_URL_DRYRUN=1 sh "$SH" >/dev/null 2>&1; then
  echo "FAIL: LODELINE_BASE_URL without LODELINE_VERSION should exit non-zero"; fail=1
else echo "ok: LODELINE_BASE_URL requires LODELINE_VERSION"; fi

# #188 — Claude allowlist offer (personal only), via LODELINE_ALLOWLIST_DRYRUN.
snip="$(LODELINE_PROFILE=personal LODELINE_ALLOWLIST_DRYRUN=1 sh "$SH" 2>&1)"
case "$snip" in
  *'"allow": ["Bash(lodeline:*)"]'*'Bash(lodeline run:*)'*'Bash(lodeline-hook:*)'*)
    echo "ok: personal allowlist snippet (broad allow + deny run/hook)" ;;
  *) echo "FAIL: personal allowlist snippet missing expected rules"; printf '%s\n' "$snip"; fail=1 ;;
esac
fleet_snip="$(LODELINE_PROFILE=fleet LODELINE_ALLOWLIST_DRYRUN=1 sh "$SH" 2>&1)"
case "$fleet_snip" in
  *"skipped (profile=fleet)"*) echo "ok: fleet profile does not offer allowlist" ;;
  *) echo "FAIL: fleet should skip the allowlist offer"; fail=1 ;;
esac

# #188 — the jq merge must be idempotent + order-preserving + non-clobbering.
if command -v jq >/dev/null 2>&1; then
  jqd="$(mktemp -d)"; sj="$jqd/settings.json"
  echo '{"permissions":{"allow":["Bash(ls:*)"]},"keep":1}' > "$sj"
  JQM='.permissions = (.permissions // {}) | .permissions.allow = ((.permissions.allow // []) + (["Bash(lodeline:*)"] - (.permissions.allow // []))) | .permissions.deny = ((.permissions.deny // []) + (["Bash(lodeline run:*)","Bash(lodeline-hook:*)"] - (.permissions.deny // [])))'
  jq "$JQM" "$sj" > "$sj.t" && mv "$sj.t" "$sj"
  jq "$JQM" "$sj" > "$sj.t" && mv "$sj.t" "$sj"   # twice → idempotent
  a="$(jq '.permissions.allow|length' "$sj")"; d="$(jq '.permissions.deny|length' "$sj")"; k="$(jq -r '.keep' "$sj")"
  first="$(jq -r '.permissions.allow[0]' "$sj")"
  if [ "$a" = 2 ] && [ "$d" = 2 ] && [ "$k" = 1 ] && [ "$first" = "Bash(ls:*)" ]; then
    echo "ok: jq merge idempotent + preserves existing allow/keys"
  else echo "FAIL: jq merge (allow=$a deny=$d keep=$k first=$first)"; fail=1; fi
  rm -rf "$jqd"
else echo "ok: jq absent — merge test skipped"; fi

exit $fail
