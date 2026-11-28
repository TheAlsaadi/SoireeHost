<#
.SYNOPSIS
  Checks statement coverage per package against docs/TEST_PLAN.md (review
  finding GOE-5). Reads a Go coverage profile; no service is involved.
.DESCRIPTION
  go test '-coverprofile=coverage.out' ./...
  powershell -File build\check-coverage.ps1 -Profile coverage.out
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Profile)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# The plan's target is 85% for each of these. A floor below 85 is a recorded
# gap (docs/HANDOFF.md, "Findings for after rc.1"): raise it as tests are
# added, never lower it.
$floors = [ordered]@{
  "internal/config"    = 85.0
  "internal/sitecheck" = 85.0
  "internal/secrets"   = 83.0
  "internal/update"    = 85.0
  "internal/ipc"       = 80.0
  "internal/audit"     = 85.0
}
$module = "github.com/TheAlsaadi/SoireeHost/"

# a block's statements count once, and as covered if any entry ran it
$blocks = @{}
foreach ($line in [IO.File]::ReadLines((Resolve-Path $Profile).Path)) {
  if ($line -notmatch '^(\S+:\S+) (\d+) (\d+)$') { continue }
  $key = $Matches[1]
  if (-not $blocks.ContainsKey($key)) { $blocks[$key] = @([int]$Matches[2], $false) }
  if ($Matches[3] -ne "0") { $blocks[$key][1] = $true }
}
if ($blocks.Count -eq 0) { throw "no coverage data in $Profile" }

$total = @{}
$covered = @{}
foreach ($e in $blocks.GetEnumerator()) {
  $file = $e.Key.Substring(0, $e.Key.LastIndexOf(':'))
  $pkg = $file.Substring(0, $file.LastIndexOf('/')).Replace($module, "")
  $total[$pkg] += $e.Value[0]
  if ($e.Value[1]) { $covered[$pkg] += $e.Value[0] }
}

$failed = @()
foreach ($pkg in $floors.Keys) {
  if (-not $total.ContainsKey($pkg)) { $failed += "$pkg is not in the profile"; continue }
  $pct = 100.0 * [double]$covered[$pkg] / $total[$pkg]
  $text = "{0}: {1} of statements, floor {2}" -f $pkg, $pct.ToString("0.0'%'", [Globalization.CultureInfo]::InvariantCulture), "$($floors[$pkg])%"
  Write-Output $text
  if ($env:GITHUB_ACTIONS) { Write-Output "::notice title=Coverage::$($text -replace '%', '%25')" }
  if ($pct -lt $floors[$pkg]) { $failed += $text }
}
if ($failed.Count -gt 0) {
  foreach ($f in $failed) {
    if ($env:GITHUB_ACTIONS) { Write-Output "::error title=Coverage below the floor::$($f -replace '%', '%25')" }
  }
  throw "coverage check failed: $($failed -join '; ')"
}
