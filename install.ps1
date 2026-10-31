<#
.SYNOPSIS
  Lodeline installer (Windows). Downloads the prebuilt binaries from the latest
  GitHub release, verifies their SHA-256 checksum, and installs them.

  irm https://raw.githubusercontent.com/Ju571nK/lodeline/main/install.ps1 | iex

  Environment overrides:
    LODELINE_VERSION       pin a release tag (default: latest), e.g. v0.6.1
    LODELINE_INSTALL_DIR   install directory (default: %LOCALAPPDATA%\Programs\lodeline)
    LODELINE_PROFILE       personal (default) | fleet
                        personal = lodeline + lodeline-mcp + lodeline-hook (local self-assessment)
                        fleet    = + lodeline-sender + lodeline-server + lodeline-sign
    LODELINE_BASE_URL      fetch artifacts from here instead of GitHub Releases, e.g.
                        an air-gapped lodeline-server: https://lodeline.example:8443/v1/artifacts
                        (requires LODELINE_VERSION — no "latest" resolution off GitHub).
    LODELINE_BASE_TOKEN    bearer token sent to LODELINE_BASE_URL (the server read token);
                        requires LODELINE_BASE_URL.

  Provenance: every release archive also carries a GitHub build-provenance
  attestation. To verify it (optional, needs the gh CLI):
    gh attestation verify <archive> --repo Ju571nK/lodeline

  This is the Windows counterpart to install.sh; the two keep parity (#172).
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # the progress UI throttles Invoke-WebRequest
# Windows PowerShell 5.1 defaults to TLS 1.0; GitHub requires 1.2+.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$Repo = 'Ju571nK/lodeline'

function Say($m) { [Console]::Error.WriteLine("lodeline-install: $m") }
function Die($m) { [Console]::Error.WriteLine("lodeline-install: error: $m"); exit 1 }

# --- resolve profile -------------------------------------------------------
$profileName = if ($env:LODELINE_PROFILE) { $env:LODELINE_PROFILE } else { 'personal' }
switch ($profileName) {
  'personal' { $binaries = @('lodeline', 'lodeline-mcp', 'lodeline-hook') }
  'fleet'    { $binaries = @('lodeline', 'lodeline-mcp', 'lodeline-hook', 'lodeline-sender', 'lodeline-server', 'lodeline-sign') }
  default    { Die "unknown LODELINE_PROFILE '$profileName' (expected: personal | fleet)" }
}

# dry-run hook: print the resolved binary set and exit before any network I/O.
# Mirrors install.sh; used by tests to verify profile->binaries mapping.
if ($env:LODELINE_PROFILE_DRYRUN -eq '1') {
  Write-Output ($binaries -join ' ')
  exit 0
}

# --- #188: personal-profile Claude Code allowlist offer (mirrors install.sh) ---
# Broad `Bash(lodeline:*)` allow stops the per-command prompt storm; an explicit
# deny keeps `lodeline run` (daemon) and `lodeline-hook` (enforce) from being silently
# granted to the agent (Claude Code evaluates deny before allow).
$LodelineAllowRule = 'Bash(lodeline:*)'
$LodelineDenyRules = @('Bash(lodeline run:*)', 'Bash(lodeline-hook:*)')

function Get-ClaudeSettingsPath { Join-Path $env:USERPROFILE '.claude\settings.json' }

function Show-AllowlistSnippet {
  $s = Get-ClaudeSettingsPath
  [Console]::Error.WriteLine(@"
lodeline-install: to stop your AI agent prompting on every lodeline command, add this
lodeline-install: read-only allowlist to $s ('lodeline run'/'lodeline-hook' stay denied):

  { "permissions": {
      "allow": ["$LodelineAllowRule"],
      "deny": ["Bash(lodeline run:*)", "Bash(lodeline-hook:*)"]
  } }
"@)
}

# Idempotent, order-preserving merge into permissions.allow/deny via native JSON.
function Merge-LodelineAllowlist($path) {
  $dir = Split-Path -Parent $path
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  $cfg = $null
  if (Test-Path $path) {
    $raw = Get-Content -Raw -Path $path -ErrorAction SilentlyContinue
    if ($raw -and $raw.Trim()) { try { $cfg = $raw | ConvertFrom-Json } catch { $cfg = $null } }
  }
  if ($null -eq $cfg) { $cfg = [pscustomobject]@{} }
  if (-not $cfg.PSObject.Properties['permissions'] -or $null -eq $cfg.permissions) {
    $cfg | Add-Member -NotePropertyName permissions -NotePropertyValue ([pscustomobject]@{}) -Force
  }
  $perm = $cfg.permissions
  if (-not $perm.PSObject.Properties['allow']) { $perm | Add-Member -NotePropertyName allow -NotePropertyValue @() }
  if (-not $perm.PSObject.Properties['deny'])  { $perm | Add-Member -NotePropertyName deny  -NotePropertyValue @() }
  $a = @($perm.allow); if ($a -notcontains $LodelineAllowRule) { $a += $LodelineAllowRule }; $perm.allow = $a
  $dn = @($perm.deny); foreach ($r in $LodelineDenyRules) { if ($dn -notcontains $r) { $dn += $r } }; $perm.deny = $dn
  $json = $cfg | ConvertTo-Json -Depth 10
  # PS 5.1 unwraps single-element arrays on serialize; force allow/deny to arrays.
  $json = [regex]::Replace($json, '("(?:allow|deny)"\s*:\s*)("(?:[^"\\]|\\.)*")(\s*[,\r\n}])', '$1[$2]$3')
  Set-Content -Path $path -Value $json -Encoding UTF8
}

function Invoke-AllowlistOffer {
  if ($profileName -ne 'personal') { return }
  $s = Get-ClaudeSettingsPath
  if (-not [Environment]::UserInteractive) { Show-AllowlistSnippet; return }
  [Console]::Error.Write("lodeline-install: add a read-only lodeline allowlist to $s so your AI agent doesn't prompt on every lodeline command? ('lodeline run'/'lodeline-hook' stay denied) [y/N] ")
  $ans = Read-Host
  if ($ans -match '^(y|yes)$') {
    try {
      Merge-LodelineAllowlist $s
      Say "added read-only lodeline allowlist to $s (allow Bash(lodeline:*); deny lodeline run + lodeline-hook)"
    } catch {
      Say "could not edit $s; add the allowlist manually:"; Show-AllowlistSnippet
    }
  } else {
    Say "skipped the allowlist; add it later if you want:"; Show-AllowlistSnippet
  }
}

# dry-run hook: show what the offer would add (personal) without prompt/edit.
if ($env:LODELINE_ALLOWLIST_DRYRUN -eq '1') {
  if ($profileName -eq 'personal') { Show-AllowlistSnippet }
  else { [Console]::Error.WriteLine("allowlist offer: skipped (profile=$profileName)") }
  exit 0
}

# --- detect platform -------------------------------------------------------
# LODELINE_ARCH_OVERRIDE lets the tests drive arch detection without spoofing the
# OS; unset in normal use. Values match RuntimeInformation.OSArchitecture.
$archName = if ($env:LODELINE_ARCH_OVERRIDE) {
  $env:LODELINE_ARCH_OVERRIDE
} else {
  [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
}
switch ($archName) {
  'X64'   { $target = 'x86_64-pc-windows-msvc' }
  'Arm64' { $target = 'aarch64-pc-windows-msvc' }
  default { Die "unsupported architecture '$archName' — see https://github.com/$Repo#installation" }
}

# dry-run hook: print the resolved release target and exit before any network I/O.
if ($env:LODELINE_TARGET_DRYRUN -eq '1') {
  Write-Output $target
  exit 0
}

# A bearer token only makes sense against a LODELINE_BASE_URL artifact server;
# requiring the pair keeps it from ever reaching GitHub's API (#182).
if ($env:LODELINE_BASE_TOKEN -and -not $env:LODELINE_BASE_URL) {
  Die "LODELINE_BASE_TOKEN requires LODELINE_BASE_URL (it authenticates to your lodeline-server)"
}

# --- resolve version -------------------------------------------------------
$ver = $env:LODELINE_VERSION
if (-not $ver) {
  if ($env:LODELINE_BASE_URL) {
    Die "set LODELINE_VERSION when using LODELINE_BASE_URL (no 'latest' resolution off GitHub)"
  }
  try {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
      -Headers @{ 'User-Agent' = 'lodeline-install' }
    $ver = $rel.tag_name
  } catch {
    Die "could not resolve the latest release (set LODELINE_VERSION to pin one)"
  }
}
if (-not $ver) { Die "could not resolve the latest release (set LODELINE_VERSION to pin one)" }
$verN = $ver -replace '^v', ''
$asset = "lodeline-$verN-$target.zip"
# Default base = GitHub Releases; LODELINE_BASE_URL points at a lodeline-server
# artifact endpoint (.../v1/artifacts) instead. Both resolve <base>/<name>. (#182)
$base = if ($env:LODELINE_BASE_URL) { $env:LODELINE_BASE_URL } else { "https://github.com/$Repo/releases/download/$ver" }

# Bearer header sent to a LODELINE_BASE_URL artifact server, if any.
$dlHeaders = @{}
if ($env:LODELINE_BASE_TOKEN) { $dlHeaders['Authorization'] = "Bearer $($env:LODELINE_BASE_TOKEN)" }

# dry-run hook: print the resolved asset + checksum URLs and exit before any
# download. Mirrors install.sh LODELINE_URL_DRYRUN; used by the parity test.
if ($env:LODELINE_URL_DRYRUN -eq '1') {
  Write-Output "$base/$asset"
  Write-Output "$base/SHA256SUMS"
  exit 0
}

# --- download + verify -----------------------------------------------------
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("lodeline-install-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  $zip = Join-Path $tmp $asset
  $sums = Join-Path $tmp 'SHA256SUMS'

  Say "downloading $asset ($ver)"
  try { Invoke-WebRequest -Uri "$base/$asset"  -OutFile $zip  -Headers $dlHeaders -UseBasicParsing }
  catch { Die "download failed: $base/$asset" }
  try { Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sums -Headers $dlHeaders -UseBasicParsing }
  catch { Die "download failed: $base/SHA256SUMS" }

  Say "verifying checksum"
  $expected = $null
  foreach ($line in Get-Content $sums) {
    # sha256sum format: "<hex>  <filename>"
    $parts = $line -split '\s+', 2
    if ($parts.Count -eq 2 -and $parts[1].Trim() -eq $asset) { $expected = $parts[0].Trim(); break }
  }
  if (-not $expected) { Die "no checksum entry for $asset in SHA256SUMS" }
  $actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash
  if ($actual -ine $expected) {
    Die "checksum verification FAILED for $asset — refusing to install"
  }

  # --- install -------------------------------------------------------------
  $unpack = Join-Path $tmp 'unpack'
  Expand-Archive -Path $zip -DestinationPath $unpack -Force
  $inner = Join-Path $unpack "lodeline-$verN-$target"

  $installDir = if ($env:LODELINE_INSTALL_DIR) { $env:LODELINE_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\lodeline' }
  New-Item -ItemType Directory -Force -Path $installDir | Out-Null

  foreach ($b in $binaries) {
    $src = Join-Path $inner "$b.exe"
    if (-not (Test-Path $src)) { Die "archive is missing expected binary: $b.exe" }
    Copy-Item -Path $src -Destination (Join-Path $installDir "$b.exe") -Force
  }

  Say "installed into $installDir`: $($binaries -join ' ')"
  Say "profile: $profileName — start the agent with 'lodeline run' (lodeline-mcp/lodeline-hook need the running daemon)"

  # --- PATH ----------------------------------------------------------------
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($userPath -split ';') -notcontains $installDir) {
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $installDir } else { $userPath.TrimEnd(';') + ';' + $installDir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Say "added $installDir to your user PATH (open a new terminal to pick it up)"
  }
  # Make 'lodeline' resolvable in the current session too.
  if (($env:Path -split ';') -notcontains $installDir) {
    $env:Path = $env:Path.TrimEnd(';') + ';' + $installDir
  }

  Say "next: lodeline doctor"
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# #188 — personal profile only: opt-in Claude Code allowlist (defined above).
Invoke-AllowlistOffer
