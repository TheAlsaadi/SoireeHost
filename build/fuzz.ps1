<#
.SYNOPSIS
  Runs every Go fuzz target in the module, one at a time, for -Duration each.
#>
[CmdletBinding()]
param([string]$Duration = "10m")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Set-Location (Split-Path -Parent $PSScriptRoot)

$pkgs = go list ./...
if ($LASTEXITCODE -ne 0) { throw "go list failed" }

$ran = 0
foreach ($pkg in $pkgs) {
  $targets = go test -list '^Fuzz' $pkg | Where-Object { $_ -match '^Fuzz' }
  foreach ($t in $targets) {
    Write-Host "==> $pkg $t ($Duration)"
    go test -run '^$' -fuzz "^$t`$" -fuzztime $Duration $pkg
    if ($LASTEXITCODE -ne 0) { throw "fuzz target $pkg $t failed" }
    $ran++
  }
}
Write-Host "Ran $ran fuzz target(s)"
if ($ran -eq 0) { throw "no fuzz targets found" }
