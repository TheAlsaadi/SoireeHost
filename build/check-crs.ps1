<#
.SYNOPSIS
  Checks the vendored OWASP Core Rule Set against its official release (S-71, ADR-0008).

.DESCRIPTION
  Downloads the archive named in build/crs.lock, refuses it unless its SHA-256 matches
  the lock, extracts only the files the lock lists, and fails if internal/waf/crs does
  not hold exactly those files, byte for byte. With -Update it writes the listed files
  into internal/waf/crs instead of comparing (used when moving to a new release).
#>
[CmdletBinding()]
param([switch]$Update)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$lock = @{}
$files = @()
foreach ($line in Get-Content -LiteralPath "build/crs.lock") {
  if ($line -match '^\s*(#|$)') { continue }
  if ($line -notmatch '^([a-z0-9]+)=(.+)$') { throw "malformed line in build/crs.lock: $line" }
  if ($Matches[1] -eq "file") { $files += $Matches[2] } else { $lock[$Matches[1]] = $Matches[2] }
}
foreach ($k in "version", "url", "sha256") {
  if (-not $lock.ContainsKey($k)) { throw "build/crs.lock has no $k" }
}
if ($files.Count -eq 0) { throw "build/crs.lock lists no files" }
if ($lock.url -notmatch '^https://github\.com/coreruleset/coreruleset/releases/download/') {
  throw "the rule set must come from the official coreruleset release: $($lock.url)"
}
foreach ($f in $files) {
  if ($f -notmatch '^(LICENSE|rules/REQUEST-9[0-9]{2}-[A-Z0-9-]+\.conf|rules/[a-z0-9-]+\.data)$') {
    throw "unexpected file name in build/crs.lock: $f"
  }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("soireehost-crs-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
  $archive = Join-Path $work "crs.tar.gz"
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -UseBasicParsing -Uri $lock.url -OutFile $archive
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
  if ($hash -ne $lock.sha256) { throw "CRS archive SHA-256 is $hash, expected $($lock.sha256)" }
  Write-Host "CRS $($lock.version) archive matches build/crs.lock"

  $prefix = "coreruleset-$($lock.version)/"
  $out = Join-Path $work "x"
  New-Item -ItemType Directory -Path $out | Out-Null
  # only the listed members: the archive also holds files antivirus quarantines
  $members = $files | ForEach-Object { $prefix + $_ }
  # Windows' own bsdtar: a Git or MSYS tar on PATH reads "C:" as a remote host
  $tar = Join-Path $env:SystemRoot "System32/tar.exe"
  & $tar -xzf $archive -C $out @members
  if ($LASTEXITCODE -ne 0) { throw "extracting the listed files failed" }

  $dest = Join-Path $repo "internal/waf/crs"
  if ($Update) {
    if (Test-Path $dest) { Get-ChildItem -LiteralPath $dest -Recurse -File | Where-Object { $_.Name -ne "README.md" } | Remove-Item -Force }
    foreach ($f in $files) {
      $target = Join-Path $dest $f
      New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
      Copy-Item -LiteralPath (Join-Path $out ($prefix + $f)) -Destination $target
    }
    Write-Host "wrote $($files.Count) files to internal/waf/crs"
    return
  }

  $bad = @()
  foreach ($f in $files) {
    $want = Join-Path $out ($prefix + $f)
    $have = Join-Path $dest $f
    if (-not (Test-Path -LiteralPath $have)) { $bad += "missing: $f"; continue }
    $a = (Get-FileHash -Algorithm SHA256 -LiteralPath $want).Hash
    $b = (Get-FileHash -Algorithm SHA256 -LiteralPath $have).Hash
    if ($a -ne $b) { $bad += "differs from the release: $f" }
  }
  $listed = @{}
  foreach ($f in $files) { $listed[$f] = $true }
  foreach ($item in Get-ChildItem -LiteralPath $dest -Recurse -File) {
    $rel = $item.FullName.Substring($dest.Length + 1).Replace('\', '/')
    if ($rel -eq "README.md") { continue }
    if (-not $listed.ContainsKey($rel)) { $bad += "not in build/crs.lock: $rel" }
  }
  if ($bad.Count -gt 0) {
    $bad | ForEach-Object { Write-Host "::error title=CRS check::$_" }
    throw "internal/waf/crs does not match CRS $($lock.version)"
  }
  Write-Host "internal/waf/crs matches CRS $($lock.version): $($files.Count) files"
}
finally {
  Remove-Item -Recurse -Force -LiteralPath $work -ErrorAction SilentlyContinue
}
