<#
.SYNOPSIS
  Downloads the pinned cloudflared release and checks it (S-71).
.DESCRIPTION
  Reads version, asset and SHA-256 from build/cloudflared.lock, downloads the
  asset from the official GitHub release of cloudflare/cloudflared into
  internal/tunnel/embed/cloudflared.exe (ignored by git), and deletes it
  again unless its SHA-256 matches the lock. Builds with the "cloudflared"
  tag embed that file. TLS is verified as usual; nothing is skipped.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$lock = @{}
foreach ($line in Get-Content (Join-Path $root "build/cloudflared.lock")) {
  if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
  $k, $v = $line -split '=', 2
  $lock[$k.Trim()] = $v.Trim()
}
foreach ($k in "version", "asset", "sha256") {
  if (-not $lock.ContainsKey($k) -or -not $lock[$k]) { throw "build/cloudflared.lock has no $k" }
}
if ($lock.version -notmatch '^\d{4}\.\d{1,2}\.\d{1,3}$') { throw "unexpected version '$($lock.version)'" }
if ($lock.asset -ne "cloudflared-windows-amd64.exe") { throw "unexpected asset '$($lock.asset)'" }
if ($lock.sha256 -notmatch '^[0-9a-f]{64}$') { throw "unexpected sha256 '$($lock.sha256)'" }

$dir = Join-Path $root "internal/tunnel/embed"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$out = Join-Path $dir "cloudflared.exe"

if (Test-Path $out) {
  $have = (Get-FileHash $out -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($have -eq $lock.sha256) {
    Write-Host "cloudflared $($lock.version) already present and verified"
    exit 0
  }
  Remove-Item -Force $out
}

$url = "https://github.com/cloudflare/cloudflared/releases/download/$($lock.version)/$($lock.asset)"
Write-Host "Downloading $url"
$tmp = "$out.download"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
$got = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLowerInvariant()
if ($got -ne $lock.sha256) {
  Remove-Item -Force $tmp
  throw "cloudflared SHA-256 mismatch: got $got, want $($lock.sha256)"
}
Move-Item -Force $tmp $out
Write-Host "cloudflared $($lock.version) verified (sha256=$got)"
