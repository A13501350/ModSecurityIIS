# Launcher for the ModSecurityIIS Pester smoke test.
#
# Keeps the old `-Msi` contract so the CI call (./scripts/ci-smoke.ps1 -Msi $msi)
# and local runs keep working unchanged; all assertions now live in the Pester
# file. We bootstrap Pester here (it is not preinstalled on windows-latest) so
# the test runs identically locally and in CI.

[CmdletBinding()]
param(
    # MSI to install before testing. Omit to test an already installed module.
    [string]$Msi,
    [string]$SiteRoot  = "C:\inetpub\modsectest",
    [string]$ConfRoot  = "C:\inetpub\modsec",
    [int]   $Port      = 18080,
    [string]$SiteName  = "ModSecTest",
    [string]$PoolName  = "ModSecTestPool"
)

$ErrorActionPreference = "Stop"

# Pester v5 is not shipped on the GitHub windows-latest image.
if (-not (Get-Module -ListAvailable -Name Pester)) {
    Write-Host "Installing Pester module..."
    Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module Pester -MinimumVersion 5.0.0 -ErrorAction Stop

$testFile = Join-Path $PSScriptRoot "smoke.Tests.ps1"
if (-not (Test-Path $testFile)) { throw "smoke test not found: $testFile" }

# Invoke-Pester -Path is the reliable single-file invocation (the -Script
# @{ Path=...; Parameters=... } form fails to discover a single-file
# container in Pester 5.9). The test reads $env:MODSEC_IIS_SMOKE_MSI for the
# MSI path; the other params keep their in-file defaults.
$env:MODSEC_IIS_SMOKE_MSI = $Msi

try {
    $result = Invoke-Pester -Path $testFile -PassThru -Output Detailed
} catch {
    Write-Host "Invoke-Pester failed: $_"
    exit 1
}

# Guard against the "0 tests found" trap: a non-terminating Pester error can
# otherwise slip through and report PASSED while BeforeAll (site creation) never ran.
if (-not $result -or $result.TotalCount -eq 0) {
    Write-Host "SMOKE TEST FAILED: Pester ran 0 tests (check the test path / discovery)."
    exit 1
}
if ($result.FailedCount -gt 0) {
    Write-Host "SMOKE TEST FAILED ($($result.FailedCount) failed)."
    exit 1
}
Write-Host "SMOKE TEST PASSED ($($result.TotalCount) tests)."
exit 0
