# Deploys ModSecurityIIS to a local IIS server. Run from an ELEVATED
# PowerShell on the target machine:
#
#   .\scripts\deploy-modsecurityiis.ps1 -DllDir .\build
#   .\scripts\deploy-modsecurityiis.ps1 -Uninstall
#
# What it does:
#   1. Copies modsecurityiis.dll + libModSecurity.dll into the IIS directory.
#   2. Installs the configuration schema (ModSecurity.xml) so IIS can read
#      <system.webServer/ModSecurity>.
#   3. Registers the "ModSecurity" Application event source, pointing its
#      message files at our DLL (the mc.exe-compiled messages live there).
#   4. Registers the native module with IIS.
#
# For unattended/packaged deployment use the MSI instead (iis\build_msi.bat);
# this script is the developer box path.

[CmdletBinding()]
param(
    # Directory containing modsecurityiis.dll + libModSecurity.dll
    [string]$DllDir = ".\build",

    # Where to place the DLLs. Defaults to the inetsrv ROOT on purpose:
    # modsecurityiis.dll imports libModSecurity.dll, and the loader resolves
    # dependencies starting from the *process executable* directory
    # (w3wp.exe -> inetsrv), NOT from the loading DLL's own folder -- a
    # subdirectory would break unless added to the system PATH.
    [string]$InstallDir = "$env:windir\System32\inetsrv",

    # Reverses the install: unregisters the module, drops the schema and the
    # event source, then deletes the DLLs (a running w3wp.exe keeps them
    # locked, so this warns instead of failing).
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

# --- sanity checks -----------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run from an elevated (Administrator) PowerShell."
}

$iisRoot = "$env:windir\System32\inetsrv"
$appcmd  = Join-Path $iisRoot "appcmd.exe"
if (-not (Test-Path $appcmd)) { throw "IIS (appcmd.exe) not found -- is IIS installed?" }

$moduleName = "ModSecurityIIS"
$image      = Join-Path $InstallDir "modsecurityiis.dll"
$evtKey     = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\ModSecurity"

# Modern registration path: the WebAdministration cmdlets. They are missing
# from PowerShell 7 unless the Windows PowerShell module path is available, so
# fall back to appcmd, which ships with IIS itself.
if (-not (Get-Command New-WebGlobalModule -ErrorAction SilentlyContinue)) {
    Import-Module WebAdministration -ErrorAction SilentlyContinue | Out-Null
}
$webAdmin = [bool](Get-Command New-WebGlobalModule -ErrorAction SilentlyContinue)

function Register-Module {
    if ($webAdmin) {
        if (Get-WebGlobalModule -Name $moduleName -ErrorAction SilentlyContinue) {
            Write-Host "  module '$moduleName' already registered -- skipping."
            return
        }
        New-WebGlobalModule -Name $moduleName -Image $image
        # New-WebGlobalModule only writes <globalModules>; the module also has
        # to appear in <modules> so it runs in sites.
        Add-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
            -Filter "system.webServer/modules" -Value @{ name = $moduleName }
    } else {
        & $appcmd install module /name:$moduleName /image:$image /add:true
        if ($LASTEXITCODE -ne 0) { throw "appcmd install module failed." }
    }
}

function Unregister-Module {
    if ($webAdmin) {
        Remove-WebGlobalModule -Name $moduleName -ErrorAction SilentlyContinue
        Remove-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
            -Filter "system.webServer/modules" `
            -AtElement @{ name = $moduleName } -ErrorAction SilentlyContinue
    } else {
        & $appcmd uninstall module /module.name:$moduleName
    }
}

if ($Uninstall) {
    Write-Host "[1/3] Unregistering module '$moduleName' ..."
    Unregister-Module

    Write-Host "[2/3] Removing schema and event source ..."
    Remove-Item (Join-Path $iisRoot "config\schema\ModSecurity.xml") -Force -ErrorAction SilentlyContinue
    Remove-Item $evtKey -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "[3/3] Removing DLLs from $InstallDir ..."
    foreach ($f in @("modsecurityiis.dll", "libModSecurity.dll")) {
        $target = Join-Path $InstallDir $f
        if (-not (Test-Path $target)) { continue }
        try { Remove-Item $target -Force -ErrorAction Stop }
        catch { Write-Warning "$f is in use (stop IIS first) -- left in place." }
    }
    Write-Host ""
    Write-Host "Uninstalled. Restart the IIS config stack (iisreset) to drop the section."
    exit 0
}

# --- sanity checks -----------------------------------------------------------
$dll     = Join-Path $DllDir "modsecurityiis.dll"
$engine  = Join-Path $DllDir "libModSecurity.dll"
$schema  = Join-Path $PSScriptRoot "..\ModSecurity.xml"
foreach ($f in @($dll, $engine, $schema)) {
    if (-not (Test-Path $f)) { throw "Required file not found: $f" }
}

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
if (-not (Test-Path $evtKey)) { New-Item $evtKey -Force | Out-Null }
Set-ItemProperty $evtKey -Name "EventMessageFile" -Value (Join-Path $InstallDir "modsecurityiis.dll")
Set-ItemProperty $evtKey -Name "TypesSupported"   -Value 7   # Error|Warning|Information
Write-Host "[3/4] Event source 'ModSecurity' registered"

# --- 4) native module registration ------------------------------------------
Register-Module
Write-Host "[4/4] Module '$moduleName' registered."

Write-Host ""
Write-Host "Done. Enable per site/application via:"
Write-Host '  <system.webServer>'
Write-Host '    <ModSecurity enabled="true" configFile="C:\inetpub\modsecurity.conf" />'
Write-Host '  </system.webServer>'
Write-Host "Recycle the application pool (or run iisreset) after config changes."
