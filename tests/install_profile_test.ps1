#!/usr/bin/env pwsh
# install.ps1의 프로파일->binaries / 플랫폼->target 매핑을 dry-run으로 검증 (#172).
# install_profile_test.sh의 PowerShell 짝. 네트워크 없이 매핑 로직만 확인한다.
#   pwsh tests/install_profile_test.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$ps1 = Join-Path $root 'install.ps1'

$fail = 0
function Assert-Eq($desc, $expected, $actual) {
  if ($expected -ne $actual) {
    Write-Host "FAIL: $desc`n  want: $expected`n  got:  $actual"
    $script:fail = 1
  } else {
    Write-Host "ok: $desc"
  }
}

# profile -> binaries
function Profile-Run($p) {
  $env:LODELINE_PROFILE = $p
  $env:LODELINE_PROFILE_DRYRUN = '1'
  try { (& pwsh -NoProfile -File $ps1).Trim() } finally {
    Remove-Item Env:LODELINE_PROFILE -ErrorAction SilentlyContinue
    Remove-Item Env:LODELINE_PROFILE_DRYRUN -ErrorAction SilentlyContinue
  }
}
Assert-Eq 'personal subset'    'lodeline lodeline-mcp lodeline-hook' (Profile-Run 'personal')
Assert-Eq 'fleet superset'     'lodeline lodeline-mcp lodeline-hook lodeline-sender lodeline-server lodeline-sign' (Profile-Run 'fleet')

$env:LODELINE_PROFILE_DRYRUN = '1'
$defaultBins = (& pwsh -NoProfile -File $ps1).Trim()
Remove-Item Env:LODELINE_PROFILE_DRYRUN -ErrorAction SilentlyContinue
Assert-Eq 'default is personal' 'lodeline lodeline-mcp lodeline-hook' $defaultBins

$env:LODELINE_PROFILE = 'bogus'; $env:LODELINE_PROFILE_DRYRUN = '1'
& pwsh -NoProfile -File $ps1 *> $null
if ($LASTEXITCODE -eq 0) { Write-Host 'FAIL: bogus profile should exit non-zero'; $fail = 1 }
else { Write-Host 'ok: bogus profile rejected' }
Remove-Item Env:LODELINE_PROFILE, Env:LODELINE_PROFILE_DRYRUN -ErrorAction SilentlyContinue

# arch -> release target (#172: both Windows targets resolve)
function Target-Run($arch) {
  $env:LODELINE_ARCH_OVERRIDE = $arch
  $env:LODELINE_TARGET_DRYRUN = '1'
  try { (& pwsh -NoProfile -File $ps1).Trim() } finally {
    Remove-Item Env:LODELINE_ARCH_OVERRIDE -ErrorAction SilentlyContinue
    Remove-Item Env:LODELINE_TARGET_DRYRUN -ErrorAction SilentlyContinue
  }
}
Assert-Eq 'x64 target'   'x86_64-pc-windows-msvc'  (Target-Run 'X64')
Assert-Eq 'arm64 target' 'aarch64-pc-windows-msvc' (Target-Run 'Arm64')

$env:LODELINE_ARCH_OVERRIDE = 'X86'; $env:LODELINE_TARGET_DRYRUN = '1'
& pwsh -NoProfile -File $ps1 *> $null
if ($LASTEXITCODE -eq 0) { Write-Host 'FAIL: x86 (32-bit) should exit non-zero'; $fail = 1 }
else { Write-Host 'ok: 32-bit x86 rejected' }
Remove-Item Env:LODELINE_ARCH_OVERRIDE, Env:LODELINE_TARGET_DRYRUN -ErrorAction SilentlyContinue

# base URL resolution (#182): default = GitHub Releases; LODELINE_BASE_URL overrides.
function Asset-Url($baseUrl) {
  $env:LODELINE_ARCH_OVERRIDE = 'X64'; $env:LODELINE_VERSION = 'v0.6.2'
  $env:LODELINE_URL_DRYRUN = '1'
  if ($baseUrl) { $env:LODELINE_BASE_URL = $baseUrl }
  try { (& pwsh -NoProfile -File $ps1)[0] } finally {
    Remove-Item Env:LODELINE_ARCH_OVERRIDE, Env:LODELINE_VERSION, Env:LODELINE_URL_DRYRUN, Env:LODELINE_BASE_URL -ErrorAction SilentlyContinue
  }
}
Assert-Eq 'default base = github releases' `
  'https://github.com/Ju571nK/lodeline/releases/download/v0.6.2/lodeline-0.6.2-x86_64-pc-windows-msvc.zip' `
  (Asset-Url $null)
Assert-Eq 'LODELINE_BASE_URL overrides base' `
  'https://srv.example:8443/v1/artifacts/lodeline-0.6.2-x86_64-pc-windows-msvc.zip' `
  (Asset-Url 'https://srv.example:8443/v1/artifacts')

$env:LODELINE_ARCH_OVERRIDE = 'X64'; $env:LODELINE_VERSION = 'v0.6.2'; $env:LODELINE_BASE_TOKEN = 'x'; $env:LODELINE_URL_DRYRUN = '1'
& pwsh -NoProfile -File $ps1 *> $null
if ($LASTEXITCODE -eq 0) { Write-Host 'FAIL: LODELINE_BASE_TOKEN without LODELINE_BASE_URL should exit non-zero'; $fail = 1 }
else { Write-Host 'ok: LODELINE_BASE_TOKEN requires LODELINE_BASE_URL' }
Remove-Item Env:LODELINE_ARCH_OVERRIDE, Env:LODELINE_VERSION, Env:LODELINE_BASE_TOKEN, Env:LODELINE_URL_DRYRUN -ErrorAction SilentlyContinue

$env:LODELINE_ARCH_OVERRIDE = 'X64'; $env:LODELINE_BASE_URL = 'https://srv.example/v1/artifacts'; $env:LODELINE_URL_DRYRUN = '1'
& pwsh -NoProfile -File $ps1 *> $null
if ($LASTEXITCODE -eq 0) { Write-Host 'FAIL: LODELINE_BASE_URL without LODELINE_VERSION should exit non-zero'; $fail = 1 }
else { Write-Host 'ok: LODELINE_BASE_URL requires LODELINE_VERSION' }
Remove-Item Env:LODELINE_ARCH_OVERRIDE, Env:LODELINE_BASE_URL, Env:LODELINE_URL_DRYRUN -ErrorAction SilentlyContinue

# #188 — Claude allowlist offer (personal only), via LODELINE_ALLOWLIST_DRYRUN.
function Allowlist-Snip($prof) {
  $env:LODELINE_PROFILE = $prof; $env:LODELINE_ALLOWLIST_DRYRUN = '1'
  try { (& pwsh -NoProfile -File $ps1 2>&1 | Out-String) } finally {
    Remove-Item Env:LODELINE_PROFILE, Env:LODELINE_ALLOWLIST_DRYRUN -ErrorAction SilentlyContinue
  }
}
$snip = Allowlist-Snip 'personal'
if ($snip -match '"allow": \["Bash\(lodeline:\*\)"\]' -and $snip -match 'Bash\(lodeline run:\*\)' -and $snip -match 'Bash\(lodeline-hook:\*\)') {
  Write-Host 'ok: personal allowlist snippet (broad allow + deny run/hook)'
} else { Write-Host 'FAIL: personal allowlist snippet missing expected rules'; Write-Host $snip; $fail = 1 }
$fsnip = Allowlist-Snip 'fleet'
if ($fsnip -match 'skipped \(profile=fleet\)') { Write-Host 'ok: fleet profile does not offer allowlist' }
else { Write-Host 'FAIL: fleet should skip the allowlist offer'; $fail = 1 }

# #188 — Merge-LodelineAllowlist must be idempotent, order-preserving, non-clobbering.
# Dot-source only the function block by extracting it is overkill; instead exercise
# the same native-JSON merge logic the installer uses, asserting array output.
$td = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $td | Out-Null
$sj = Join-Path $td 'settings.json'
'{"permissions":{"allow":["Bash(ls:*)"]},"keep":1}' | Set-Content -Path $sj -Encoding UTF8
$merge = {
  param($path)
  $cfg = (Get-Content -Raw $path | ConvertFrom-Json)
  if (-not $cfg.PSObject.Properties['permissions']) { $cfg | Add-Member -NotePropertyName permissions -NotePropertyValue ([pscustomobject]@{}) -Force }
  $perm = $cfg.permissions
  if (-not $perm.PSObject.Properties['allow']) { $perm | Add-Member -NotePropertyName allow -NotePropertyValue @() }
  if (-not $perm.PSObject.Properties['deny'])  { $perm | Add-Member -NotePropertyName deny  -NotePropertyValue @() }
  $a = @($perm.allow); if ($a -notcontains 'Bash(lodeline:*)') { $a += 'Bash(lodeline:*)' }; $perm.allow = $a
  $dn = @($perm.deny); foreach ($r in @('Bash(lodeline run:*)','Bash(lodeline-hook:*)')) { if ($dn -notcontains $r) { $dn += $r } }; $perm.deny = $dn
  $json = $cfg | ConvertTo-Json -Depth 10
  $json = [regex]::Replace($json, '("(?:allow|deny)"\s*:\s*)("(?:[^"\\]|\\.)*")(\s*[,\r\n}])', '$1[$2]$3')
  Set-Content -Path $path -Value $json -Encoding UTF8
}
& $merge $sj; & $merge $sj   # twice → idempotent
$res = (Get-Content -Raw $sj | ConvertFrom-Json)
if (@($res.permissions.allow).Count -eq 2 -and @($res.permissions.deny).Count -eq 2 -and $res.keep -eq 1 -and @($res.permissions.allow)[0] -eq 'Bash(ls:*)') {
  Write-Host 'ok: native merge idempotent + preserves existing allow/keys'
} else { Write-Host "FAIL: native merge (allow=$(@($res.permissions.allow).Count) deny=$(@($res.permissions.deny).Count))"; $fail = 1 }
Remove-Item -Recurse -Force $td -ErrorAction SilentlyContinue

exit $fail
