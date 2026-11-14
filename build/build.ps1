<#
.SYNOPSIS
  Builds soireehost.exe: bindings, frontend checks and build, then the Go binary.
.PARAMETER Version
  Semantic version to stamp into the binary. Defaults to 0.0.0-dev.
.PARAMETER Dev
  Build without the "production" tag (developer tools on). Never use for releases.
.PARAMETER SkipChecks
  Skip frontend type check, lint and tests (for quick local rebuilds only).
.PARAMETER Cloudflared
  Download the pinned cloudflared, check its SHA-256 and embed it (S-71).
  CI and release builds always use it; without it the binary has no tunnel.
#>
[CmdletBinding()]
param(
  [string]$Version = "0.0.0-dev",
  [switch]$Dev,
  [switch]$SkipChecks,
  [switch]$Cloudflared
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if ($Version -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$') {
  throw "Version '$Version' is not a valid semantic version"
}

function Invoke-Step([string]$Name, [scriptblock]$Block) {
  Write-Host "==> $Name"
  & $Block
  if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE" }
}

Invoke-Step "Generate Wails bindings" { wails3 generate bindings -ts ./... }

Push-Location frontend
try {
  Invoke-Step "Install frontend packages" { npm.cmd ci --ignore-scripts --no-fund --no-audit }
  if (-not $SkipChecks) {
    Invoke-Step "Type check" { npm.cmd run check }
    Invoke-Step "Lint" { npm.cmd run lint }
    Invoke-Step "Frontend tests" { npm.cmd test }
  }
  Invoke-Step "Build frontend" { npm.cmd run build }
  # vite empties dist/; restore the placeholder that keeps go:embed valid in a clean clone
  New-Item -ItemType File -Force -Path "dist/.gitkeep" | Out-Null
}
finally {
  Pop-Location
}

$env:CGO_ENABLED = "0"
$env:GOFLAGS = "-mod=readonly"
$tagList = @()
if (-not $Dev) { $tagList += "production" }
if ($Cloudflared) {
  Invoke-Step "Fetch and verify cloudflared" { & powershell -NoProfile -File (Join-Path $PSScriptRoot "fetch-cloudflared.ps1") }
  $tagList += "cloudflared"
}
$tags = $tagList -join ","
$ldflags = "-s -w -H windowsgui -X github.com/TheAlsaadi/SoireeHost/internal/version.Version=$Version"

New-Item -ItemType Directory -Force -Path bin | Out-Null
Invoke-Step "Build soireehost.exe" {
  go build -trimpath -tags "$tags" -ldflags "$ldflags" -o bin/soireehost.exe ./cmd/soireehost
}

$hash = (Get-FileHash bin/soireehost.exe -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "Built bin/soireehost.exe ($Version) sha256=$hash"
