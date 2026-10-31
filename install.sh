#!/bin/sh
# Lodeline installer (macOS / Linux). Downloads the prebuilt binaries from the
# latest GitHub release, verifies their SHA-256 checksum, and installs them.
#
#   curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Ju571nK/lodeline/main/install.sh | sh
#
# Environment overrides:
#   LODELINE_VERSION       pin a release tag (default: latest), e.g. v0.1.0
#   LODELINE_INSTALL_DIR   install directory (default: $HOME/.local/bin)
#   LODELINE_PROFILE       personal (default) | fleet
#                       personal = lodeline + lodeline-mcp + lodeline-hook (local self-assessment)
#                       fleet    = + lodeline-sender + lodeline-server + lodeline-sign
#   LODELINE_BASE_URL      fetch the artifacts from here instead of GitHub Releases,
#                       e.g. an air-gapped lodeline-server: https://lodeline.example:8443/v1/artifacts
#                       (#182). Requires LODELINE_VERSION (no "latest" resolution off GitHub).
#   LODELINE_BASE_TOKEN    bearer token sent as `Authorization: Bearer` to LODELINE_BASE_URL
#                       (the lodeline-server read token). Requires LODELINE_BASE_URL.
#
# Provenance: every release archive also carries a GitHub build-provenance
# attestation. To verify it (optional, needs the gh CLI):
#   gh attestation verify <archive> --repo Ju571nK/lodeline
set -eu

REPO="Ju571nK/lodeline"
INSTALL_DIR="${LODELINE_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf 'lodeline-install: %s\n' "$1" >&2; }
err() { printf 'lodeline-install: error: %s\n' "$1" >&2; exit 1; }

PROFILE="${LODELINE_PROFILE:-personal}"
case "$PROFILE" in
  personal) BINARIES="lodeline lodeline-mcp lodeline-hook" ;;
  fleet)    BINARIES="lodeline lodeline-mcp lodeline-hook lodeline-sender lodeline-server lodeline-sign" ;;
  *) err "unknown LODELINE_PROFILE '$PROFILE' (expected: personal | fleet)" ;;
esac

# dry-run hook: print the resolved binary set and exit before any network I/O.
# Used by tests/install_profile_test.sh to verify profile->binaries mapping.
if [ "${LODELINE_PROFILE_DRYRUN:-}" = "1" ]; then
  printf '%s\n' "$BINARIES"
  exit 0
fi

# --- #188: personal-profile Claude Code allowlist offer ---------------------
# An AI agent (Claude Code) driving lodeline improvises flagged commands, so each
# distinct command string is a fresh approval and "don't ask again" never
# sticks. Offer (opt-in) to add a read-only allowlist to ~/.claude/settings.json.
# Broad `Bash(lodeline:*)` allow kills the prompt storm; an explicit deny keeps the
# privileged `lodeline run` (daemon) and `lodeline-hook` (enforce) from being silently
# granted to the agent — Claude Code evaluates deny before allow, so deny wins.
LODELINE_ALLOW_RULE='Bash(lodeline:*)'

claude_settings_path() { printf '%s/.claude/settings.json' "$HOME"; }

print_allowlist_snippet() {
  _s="$(claude_settings_path)"
  cat >&2 <<EOF
lodeline-install: to stop your AI agent prompting on every lodeline command, add this
lodeline-install: read-only allowlist to $_s ('lodeline run'/'lodeline-hook' stay denied):

  { "permissions": {
      "allow": ["$LODELINE_ALLOW_RULE"],
      "deny": ["Bash(lodeline run:*)", "Bash(lodeline-hook:*)"]
  } }

lodeline-install: with jq (creates the file if missing):
  S="$_s"; mkdir -p "\$(dirname "\$S")"; [ -f "\$S" ] || echo '{}' > "\$S"; \\
  jq '.permissions.allow=((.permissions.allow//[])+["$LODELINE_ALLOW_RULE"]-(.permissions.allow//[])) | .permissions.deny=((.permissions.deny//[])+["Bash(lodeline run:*)","Bash(lodeline-hook:*)"]-(.permissions.deny//[]))' "\$S" > "\$S.tmp" && mv "\$S.tmp" "\$S"
EOF
}

# Idempotent, order-preserving merge into permissions.allow/deny via jq.
merge_allowlist() {
  _s="$1"
  mkdir -p "$(dirname "$_s")" || return 1
  _existing='{}'
  [ -f "$_s" ] && _existing="$(cat "$_s")"
  printf '%s' "$_existing" | jq \
    --arg allow "$LODELINE_ALLOW_RULE" \
    '.permissions = (.permissions // {})
     | .permissions.allow = ((.permissions.allow // []) + ([$allow] - (.permissions.allow // [])))
     | .permissions.deny  = ((.permissions.deny  // []) + (["Bash(lodeline run:*)","Bash(lodeline-hook:*)"] - (.permissions.deny // [])))' \
    > "$_s.tmp.$$" 2>/dev/null && mv "$_s.tmp.$$" "$_s"
}

offer_claude_allowlist() {
  [ "$PROFILE" = "personal" ] || return 0
  _s="$(claude_settings_path)"
  # Consent needs a real terminal. curl | sh has no stdin TTY, so read /dev/tty;
  # if there's no controlling terminal (CI/cron), never edit — just print.
  if ! { exec 3</dev/tty; } 2>/dev/null; then
    print_allowlist_snippet
    return 0
  fi
  printf 'lodeline-install: add a read-only lodeline allowlist to %s so your AI agent\n' "$_s" >&2
  printf "lodeline-install: doesn't prompt on every lodeline command? ('lodeline run'/'lodeline-hook' stay denied) [y/N] " >&2
  _ans=''
  read -r _ans <&3 || _ans=''
  exec 3<&- 2>/dev/null || true
  case "$_ans" in
    y | Y | yes | YES)
      if ! command -v jq >/dev/null 2>&1; then
        say "jq not found ($(pkg_hint jq)); add the allowlist manually:"
        print_allowlist_snippet
      elif merge_allowlist "$_s"; then
        say "added read-only lodeline allowlist to $_s (allow Bash(lodeline:*); deny lodeline run + lodeline-hook)"
      else
        say "could not edit $_s; add the allowlist manually:"
        print_allowlist_snippet
      fi
      ;;
    *) say "skipped the allowlist; add it later if you want:" && print_allowlist_snippet ;;
  esac
}

# dry-run hook: show what the allowlist offer would add (personal) without any
# prompt/edit. Used by tests/install_profile_test.sh.
if [ "${LODELINE_ALLOWLIST_DRYRUN:-}" = "1" ]; then
  if [ "$PROFILE" = "personal" ]; then
    print_allowlist_snippet
  else
    printf 'allowlist offer: skipped (profile=%s)\n' "$PROFILE" >&2
  fi
  exit 0
fi

# --- tooling ---------------------------------------------------------------
# Minimal RHEL-family / container images often ship without `tar` (and even
# `curl`); a bare "missing required tool" leaves the user guessing. Suggest the
# one-liner for the host's package manager (#179).
pkg_hint() { # $1 = tool/package name
  if   command -v dnf     >/dev/null 2>&1; then echo "install it: sudo dnf install -y $1"
  elif command -v apt-get >/dev/null 2>&1; then echo "install it: sudo apt-get install -y $1"
  elif command -v yum     >/dev/null 2>&1; then echo "install it: sudo yum install -y $1"
  elif command -v apk     >/dev/null 2>&1; then echo "install it: sudo apk add $1"
  elif command -v zypper  >/dev/null 2>&1; then echo "install it: sudo zypper install -y $1"
  elif command -v pacman  >/dev/null 2>&1; then echo "install it: sudo pacman -S $1"
  elif command -v brew    >/dev/null 2>&1; then echo "install it: brew install $1"
  else echo "install $1 with your package manager"; fi
}
need() { # $1 = command, $2 = package providing it (defaults to $1)
  command -v "$1" >/dev/null 2>&1 || err "missing required tool: $1 — $(pkg_hint "${2:-$1}")"
}
need uname coreutils
need tar tar
need mktemp coreutils

# A bearer token only makes sense against a LODELINE_BASE_URL artifact server;
# requiring the pair keeps the token from ever being sent to GitHub's API (#182).
if [ -n "${LODELINE_BASE_TOKEN:-}" ] && [ -z "${LODELINE_BASE_URL:-}" ]; then
  err "LODELINE_BASE_TOKEN requires LODELINE_BASE_URL (it authenticates to your lodeline-server)"
fi

if command -v curl >/dev/null 2>&1; then
  if [ -n "${LODELINE_BASE_TOKEN:-}" ]; then
    dl() { curl --proto '=https' --tlsv1.2 -fsSL -H "Authorization: Bearer ${LODELINE_BASE_TOKEN}" "$1"; }
  else
    dl() { curl --proto '=https' --tlsv1.2 -fsSL "$1"; }
  fi
elif command -v wget >/dev/null 2>&1; then
  if [ -n "${LODELINE_BASE_TOKEN:-}" ]; then
    dl() { wget -qO- --header="Authorization: Bearer ${LODELINE_BASE_TOKEN}" "$1"; }
  else
    dl() { wget -qO- "$1"; }
  fi
else
  err "need curl or wget — $(pkg_hint curl)"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha_check() { sha256sum -c "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  sha_check() { shasum -a 256 -c "$1"; }
else
  err "need sha256sum or shasum to verify the download — $(pkg_hint coreutils)"
fi

# --- detect platform -------------------------------------------------------
# LODELINE_UNAME_S / LODELINE_UNAME_M let the tests drive platform detection without
# spoofing uname; unset in normal use.
os="${LODELINE_UNAME_S:-$(uname -s)}"
arch="${LODELINE_UNAME_M:-$(uname -m)}"
case "$os/$arch" in
  Linux/x86_64 | Linux/amd64)
    target="x86_64-unknown-linux-musl" ;;
  Darwin/arm64 | Darwin/aarch64)
    target="aarch64-apple-darwin" ;;
  Darwin/x86_64)
    err "Intel Macs aren't supported — build from source: https://github.com/$REPO#build-from-source" ;;
  Linux/aarch64 | Linux/arm64)
    # Static musl ARM64 — runs on Graviton/Ampere and RHEL/Rocky 9 aarch64 (#171).
    target="aarch64-unknown-linux-musl" ;;
  *)
    err "unsupported platform '$os/$arch' — see https://github.com/$REPO#installation" ;;
esac

# dry-run hook: print the resolved release target and exit before any network
# I/O. Used by tests/install_profile_test.sh to verify platform->target mapping.
if [ "${LODELINE_TARGET_DRYRUN:-}" = "1" ]; then
  printf '%s\n' "$target"
  exit 0
fi

# --- resolve version -------------------------------------------------------
ver="${LODELINE_VERSION:-}"
if [ -z "$ver" ]; then
  # A custom artifact server has no GitHub "latest" API; require an explicit pin.
  [ -z "${LODELINE_BASE_URL:-}" ] \
    || err "set LODELINE_VERSION when using LODELINE_BASE_URL (no 'latest' resolution off GitHub)"
  ver="$(dl "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
          | grep -m1 '"tag_name"' | cut -d'"' -f4 || true)"
  [ -n "$ver" ] || err "could not resolve the latest release (set LODELINE_VERSION to pin one)"
fi
verN="${ver#v}"
asset="lodeline-${verN}-${target}.tar.gz"
# Default base = GitHub Releases (`.../download/<tag>`); LODELINE_BASE_URL points at
# a lodeline-server artifact endpoint (`.../v1/artifacts`) instead. Both resolve the
# asset + SHA256SUMS as `<base>/<name>`, so the rest of the flow is unchanged (#182).
base="${LODELINE_BASE_URL:-https://github.com/$REPO/releases/download/$ver}"

# dry-run hook: print the resolved asset + checksum URLs and exit before any
# download. Used by tests/install_profile_test.sh to verify base resolution.
if [ "${LODELINE_URL_DRYRUN:-}" = "1" ]; then
  printf '%s\n' "$base/$asset"
  printf '%s\n' "$base/SHA256SUMS"
  exit 0
fi

# --- download + verify -----------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "downloading $asset ($ver)"
dl "$base/$asset"    > "$tmp/$asset"      || err "download failed: $base/$asset"
dl "$base/SHA256SUMS" > "$tmp/SHA256SUMS" || err "download failed: $base/SHA256SUMS"

say "verifying checksum"
grep " $asset\$" "$tmp/SHA256SUMS" > "$tmp/expected.sha256" 2>/dev/null \
  || grep "  *$asset\$" "$tmp/SHA256SUMS" > "$tmp/expected.sha256" \
  || err "no checksum entry for $asset in SHA256SUMS"
( cd "$tmp" && sha_check expected.sha256 >/dev/null 2>&1 ) \
  || err "checksum verification FAILED for $asset — refusing to install"

# --- install ---------------------------------------------------------------
tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$INSTALL_DIR"
for b in $BINARIES; do
  src="$tmp/lodeline-${verN}-${target}/$b"
  [ -f "$src" ] || err "archive is missing expected binary: $b"
  cp "$src" "$INSTALL_DIR/$b"
  chmod 0755 "$INSTALL_DIR/$b"
done

say "installed into $INSTALL_DIR: $BINARIES"
say "profile: $PROFILE — start the agent with 'lodeline run' (lodeline-mcp/lodeline-hook need the running daemon)"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "note: add $INSTALL_DIR to your PATH to run 'lodeline' directly" ;;
esac
say "next: lodeline doctor"

# #188 — personal profile only: opt-in Claude Code allowlist (defined above).
offer_claude_allowlist
