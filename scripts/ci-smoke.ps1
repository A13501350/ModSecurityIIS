# Launcher for the ModSecurityIIS Pester smoke test (tests/iis/smoke.Tests.ps1).
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

$testFile = Join-Path $PSScriptRoot "..\tests\iis\smoke.Tests.ps1"
if (-not (Test-Path $testFile)) { throw "smoke test not found: $testFile" }

$result = Invoke-Pester -Script @{
    Path = $testFile
    Parameters = @{
        Msi       = $Msi
        SiteRoot  = $SiteRoot
        ConfRoot  = $ConfRoot
        Port      = $Port
        SiteName  = $SiteName
        PoolName  = $PoolName
    }
} -PassThru -Output Detailed

if ($result.FailedCount -gt 0) {
    Write-Host "SMOKE TEST FAILED ($($result.FailedCount) failed)."
    exit 1
}
Write-Host "SMOKE TEST PASSED."
exit 0
