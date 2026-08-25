# Deploys ModSecurityIIS to a local IIS server. Run from an ELEVATED
# PowerShell on the target machine:
#
#   .\scripts\deploy-modsecurityiis.ps1 -DllDir .\build
#
# What it does:
#   1. Copies modsecurityiis.dll + libModSecurity.dll into the IIS directory.
#   2. Installs the configuration schema (ModSecurity.xml) so IIS can read
#      <system.webServer/ModSecurity>.
#   3. Registers the "ModSecurity" Application event source, pointing its
#      message files at our DLL (the mc.exe-compiled messages live there).
#   4. Registers the native module with appcmd (default, unlocked).
#
# A WiX-based MSI does not exist yet; this script is the supported install path.

[CmdletBinding()]
param(
    # Directory containing modsecurityiis.dll + libModSecurity.dll
    [string]$DllDir = ".\build",

    # Where to place the DLLs. Defaults to the inetsrv ROOT on purpose:
    # modsecurityiis.dll imports libModSecurity.dll, and the loader resolves
    # dependencies starting from the *process executable* directory
    # (w3wp.exe -> inetsrv), NOT from the loading DLL's own folder -- a
    # subdirectory would break unless added to the system PATH.
    [string]$InstallDir = "$env:windir\System32\inetsrv"
)

$ErrorActionPreference = "Stop"

# --- sanity checks -----------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run from an elevated (Administrator) PowerShell."
}

$dll     = Join-Path $DllDir "modsecurityiis.dll"
$engine  = Join-Path $DllDir "libModSecurity.dll"
$schema  = Join-Path $PSScriptRoot "..\ModSecurity.xml"
foreach ($f in @($dll, $engine, $schema)) {
    if (-not (Test-Path $f)) { throw "Required file not found: $f" }
}

$iisRoot = "$env:windir\System32\inetsrv"
$appcmd  = Join-Path $iisRoot "appcmd.exe"
if (-not (Test-Path $appcmd)) { throw "IIS (appcmd.exe) not found -- is IIS installed?" }

# --- 1) binaries -------------------------------------------------------------
New-Item -ItemType Directory -Force $InstallDir | Out-Null
Copy-Item $dll    $InstallDir -Force
Copy-Item $engine $InstallDir -Force

# Stage any Conan dynamic dependencies (e.g. libmaxminddb.dll, lmdb.dll) next
# to the engine. ConanCenter packages are static by default, but if any was
# built shared, w3wp would fail to load it. Mirrors the CI smoke staging:
# resolve every non-system import and copy it from the build/Conan dirs.
$dumpbin = Get-Command dumpbin -ErrorAction SilentlyContinue
if ($dumpbin) {
    $deps = & dumpbin /dependents $engine 2>&1 | Out-String
    $systemDeps = @("kernel32","user32","advapi32","ws2_32","iphlpapi",
                    "bcrypt","crypt32","msvcrt","ucrtbase","vcruntime140",
                    "vcruntime140_1","msvcp140","ntdll","ole32","shell32")
    foreach ($m in [regex]::Matches($deps, "(?im)^\s*(\S+\.dll)\s*$")) {
        $dep  = $m.Groups[1].Value
        $base = ($dep -replace "\.dll$", "")
        if ($base -like "api-ms-win-crt*") { continue }
        if ($systemDeps -contains $base) { continue }
        if (Test-Path (Join-Path $env:windir "System32\$dep")) { continue }
        $roots = @($DllDir, "$env:USERPROFILE\.conan2",
                   "$env:GITHUB_WORKSPACE\build") |
                 Where-Object { $_ -and (Test-Path $_) }
        $found = if ($roots) {
            Get-ChildItem $roots -Recurse -Filter $dep -ErrorAction SilentlyContinue |
                Select-Object -First 1
        } else { $null }
        if ($found) {
            Copy-Item $found.FullName $InstallDir -Force
            Write-Host "  staged dependency: $dep"
        } else {
            Write-Warning "Dependency $dep not found -- module load may fail."
        }
    }
} else {
    Write-Warning ("dumpbin not found; skipped dynamic dependency staging. " +
                   "If lmdb/libmaxminddb were built shared, copy their DLLs " +
                   "to $InstallDir manually.")
}

Write-Host "[1/4] DLLs copied to $InstallDir"

# --- 2) config schema --------------------------------------------------------
$schemaDir = Join-Path $iisRoot "config\schema"
New-Item -ItemType Directory -Force $schemaDir | Out-Null
Copy-Item $schema (Join-Path $schemaDir "ModSecurity.xml") -Force
Write-Host "[2/4] Schema installed ($schemaDir\ModSecurity.xml)"

# --- 3) event source ---------------------------------------------------------
# Without this key, ReportEventA still works but Event Viewer shows
# "The description for Event ID 1 cannot be found".
$evtKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\ModSecurity"
if (-not (Test-Path $evtKey)) { New-Item $evtKey -Force | Out-Null }
Set-ItemProperty $evtKey -Name "EventMessageFile" -Value (Join-Path $InstallDir "modsecurityiis.dll")
Set-ItemProperty $evtKey -Name "TypesSupported"   -Value 7   # Error|Warning|Information
Write-Host "[3/4] Event source 'ModSecurity' registered"

# --- 4) native module registration ------------------------------------------
$moduleName = "ModSecurityIIS"
$image = Join-Path $InstallDir "modsecurityiis.dll"
$existing = & $appcmd list modules /name:$moduleName 2>$null
if ($existing) {
    Write-Host "[4/4] Module '$moduleName' already registered -- skipping."
} else {
    & $appcmd install module /name:$moduleName /image:$image /add:true
    if ($LASTEXITCODE -ne 0) { throw "appcmd install module failed." }
    Write-Host "[4/4] Module registered."
}

Write-Host ""
Write-Host "Done. Enable per site/application via:"
Write-Host '  <system.webServer>'
Write-Host '    <ModSecurity enabled="true" configFile="C:\inetpub\modsecurity.conf" />'
Write-Host '  </system.webServer>'
Write-Host "Recycle the application pool (or run iisreset) after config changes."
