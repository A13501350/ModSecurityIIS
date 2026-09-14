# ARR request-body forward verification for ModSecurityIIS.
#
# Reproduces the defect the bench harness found (bench/README.md, "Known
# defects" -> "v3: 100 KiB request bodies stall through ARR"): a ~100 KiB POST
# through the connector's reverse-proxy (URL Rewrite + ARR -> backend) stalls
# or is truncated, while a 1 KiB POST on the same path is fine. The shipped
# smoke test (scripts/smoke.Tests.ps1 6b) posts 100 KiB DIRECTLY to the
# connector's own site (no ARR, no backend) so it never exercises this path.
#
# What this script proves, end to end:
#   1. The connector's OnBeginRequest drains the request body
#      (DriveBodyRead, src/ModSecurityIIS.cpp:635) and re-inserts it via
#      InsertEntityBody (:753) -- unconditionally, regardless of
#      SecRequestBodyAccess (OnBeginRequest:1070 calls it directly).
#   2. ARR then reverse-proxies the request to a backend that echoes the body.
#   3. A 100 KiB body must come back intact (length match) and within a hard
#      timeout (no stall). A 1 KiB control must pass too.
#
# Signals:
#   - STALL   : curl --max-time elapses with no response (exit 28).
#   - TRUNCATED: response length < bytes sent.
#   - PASS    : both control and target return 200 with intact echo.
#
# Run locally (elevated, Go on PATH):
#   ./scripts/arr-body-probe.ps1 -Msi <path-to.msi>
# or, against an already-installed module:
#   $env:MODSEC_IIS_ARR_MSI = ""; ./scripts/arr-body-probe.ps1
#
# The CI workflow .github/workflows/arr-body-probe.yml drives this on
# windows-latest (builds/reuses the MSI, sets up Go, runs this).

[CmdletBinding()]
param(
    # MSI path. Empty = test an already-installed module. The launcher / CI
    # passes it via $env:MODSEC_IIS_ARR_MSI (Invoke-Pester-style -Path cannot
    # forward args, but we invoke this script directly so -Msi works too).
    [string]$Msi = ($env:MODSEC_IIS_ARR_MSI ?? ""),
    [string]$ConfRoot  = "C:\inetpub\modsec-arr",
    [string]$SiteRoot  = "C:\inetpub\modsec-arr\www",
    [string]$SiteName  = "ArrBodyProbe",
    [string]$PoolName  = "ArrBodyProbePool",
    [int]   $Port      = 18090,
    [int]   $BackendPort = 8088,
    [string]$BackendExe = "go",
    [int]   $ControlBytes = 1024,
    [int]   $TargetBytes  = 102400,   # 100 KiB
    [int]   $TimeoutSec   = 30
)

$ErrorActionPreference = "Stop"

$appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
$curl   = "$env:windir\System32\curl.exe"

function Write-Verdict {
    param([string]$Name, [string]$Status, [string]$Detail = "")
    $line = "[$Name] $Status"
    if ($Detail) { $line += " -- $Detail" }
    Write-Host $line
}

# ---------------------------------------------------------------------------
# 0) preconditions
# ---------------------------------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Must run elevated."
}

# Go echo backend (relative to repo root; resolve from this script's parent's
# parent so it works regardless of CWD).
$repoRoot   = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$backendSrc = Join-Path $repoRoot "scripts\arr-echo-backend\main.go"
if (-not (Test-Path $backendSrc)) { throw "echo backend not found: $backendSrc" }
if (-not (Get-Command $BackendExe -ErrorAction SilentlyContinue)) {
    throw "Go toolchain not on PATH (needed to run the echo backend)."
}

# ---------------------------------------------------------------------------
# 1) ensure IIS
# ---------------------------------------------------------------------------
$features = Get-WindowsFeature Web-Static-Content, Web-Default-Doc, `
                               Web-Http-Errors, Web-Filtering -ErrorAction SilentlyContinue
if ($features | Where-Object { -not $_.Installed }) {
    Write-Host "Installing missing IIS features..."
    Install-WindowsFeature Web-Static-Content, Web-Default-Doc, `
                           Web-Http-Errors, Web-Filtering | Out-Null
}
if ((Get-Service W3SVC).Status -ne "Running") { Start-Service W3SVC }

# ---------------------------------------------------------------------------
# 2) install the MSI (optional)
# ---------------------------------------------------------------------------
if ($Msi) {
    if (-not (Test-Path $Msi)) { throw "MSI not found: $Msi" }
    $log = Join-Path (Get-Location).Path "arr-msi-install.log"
    Write-Host "== Installing $Msi =="
    $p = Start-Process msiexec.exe -Wait -PassThru `
         -ArgumentList @("/i", (Resolve-Path $Msi).Path, "/qn", "/norestart", "/l*v", $log)
    if ($p.ExitCode -ne 0) { throw "msiexec failed (exit=$($p.ExitCode)); log: $log" }
    # Schema file under inetsrv\config\schema must be visible to the config
    # system before the ModSecurity section can be set.
    & iisreset /stop 2>&1 | Out-Null; Start-Sleep -Seconds 2
    & iisreset /start 2>&1 | Out-Null
    foreach ($i in 1..30) {
        if ((Get-Service W3SVC).Status -eq "Running") { break }
        Start-Sleep -Seconds 1
    }
}

# ---------------------------------------------------------------------------
# 3) engine config (mirrors production: request-body inspection ON)
# ---------------------------------------------------------------------------
New-Item -ItemType Directory -Force $ConfRoot | Out-Null
New-Item -ItemType Directory -Force (Join-Path $ConfRoot "data") | Out-Null
$modsecConf = @"
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
# Quiet: this probe measures transport, not detection.
SecAuditEngine Off
SecAuditLogType Serial
SecTmpDir $ConfRoot\data
SecDataDir $ConfRoot\data
"@
Set-Content (Join-Path $ConfRoot "modsecurity-arr.conf") $modsecConf -Encoding Ascii

# ---------------------------------------------------------------------------
# 4) reverse proxy: URL Rewrite + ARR -> echo backend
# ---------------------------------------------------------------------------
Write-Host "== Installing ARR + URL Rewrite =="
choco install urlrewrite iis-arr -y --no-progress | Out-Null
& $appcmd set config /section:system.webServer/proxy /enabled:true
if ($LASTEXITCODE -ne 0) { throw "Failed to enable ARR proxy." }

# Start the echo backend.
$backendUrl = "http://127.0.0.1:$BackendPort"
$goArgs = @("run", $backendSrc, "-addr", "127.0.0.1:$BackendPort")
$beProc = Start-Process -FilePath $BackendExe -ArgumentList $goArgs `
                        -WindowStyle Hidden -PassThru
Write-Host "== echo backend started (pid $($beProc.Id)) =="
$ready = $false
foreach ($i in 1..30) {
    try {
        $r = & $curl -s --max-time 3 "$backendUrl/healthz"
        if ("$r" -eq "ok") { $ready = $true; break }
    } catch { Start-Sleep -Seconds 1 }
    Start-Sleep -Seconds 1
}
if (-not $ready) {
    if (-not $beProc.HasExited) { $beProc.Kill() }
    throw "echo backend did not become ready on $backendUrl."
}
Write-Host "== echo backend ready on $backendUrl =="

# ---------------------------------------------------------------------------
# 5) site that proxies to the backend, with ModSecurity enabled
# ---------------------------------------------------------------------------
New-Item -ItemType Directory -Force $SiteRoot | Out-Null
Set-Content (Join-Path $SiteRoot "hello.txt") "hello from arr probe" -Encoding Ascii

& $appcmd delete site    $SiteName 2>$null | Out-Null
& $appcmd delete apppool $PoolName 2>$null | Out-Null
& $appcmd add apppool /name:$PoolName
& $appcmd set apppool $PoolName /processModel.loadUserProfile:false
& $appcmd add site /name:$SiteName /physicalPath:$SiteRoot "/bindings:http/*:$($Port):"
& $appcmd set app "$SiteName/" /applicationPool:$PoolName

$poolId = "IIS AppPool\$PoolName"
icacls "$ConfRoot\data" /grant "${poolId}:(OI)(CI)M" | Out-Null

$webConfig = Join-Path $SiteRoot "web.config"
@"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <ModSecurity enabled="true" configFile="$ConfRoot\modsecurity-arr.conf" responseBodyBlock="false" />
    <rewrite>
      <rules>
        <rule name="ToEchoBackend" stopProcessing="true">
          <match url="(.*)" />
          <action type="Rewrite" url="$backendUrl/{R:1}" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
"@ | Set-Content $webConfig -Encoding Ascii

# Ensure the section is declared (the MSI declares it, but be defensive: an
# already-installed module path may not have run the MSI installer's schema).
$secOk = $false
for ($try = 1; $try -le 5; $try++) {
    $out = & $appcmd set config $SiteName /section:ModSecurity `
        /enabled:true /configFile:"$ConfRoot\modsecurity-arr.conf" /commit:site 2>&1
    if ($LASTEXITCODE -eq 0) { $secOk = $true; break }
    Write-Warning "set ModSecurity section attempt $try failed: $out"
    Start-Sleep -Seconds 3
}
if (-not $secOk) {
    if (-not $beProc.HasExited) { $beProc.Kill() }
    throw "ModSecurity section could not be configured for site '$SiteName'."
}

& $appcmd start site $SiteName
& iisreset /stop  2>&1 | Out-Null; Start-Sleep -Seconds 2
& iisreset /start 2>&1 | Out-Null
foreach ($i in 1..30) {
    if ((Get-Service W3SVC).Status -eq "Running") { break }
    Start-Sleep -Seconds 1
}

$probeUrl = "http://127.0.0.1:$Port/echo"

# ---------------------------------------------------------------------------
# 6) probes
# ---------------------------------------------------------------------------
function New-BodyFile([int]$Bytes, [string]$Marker) {
    $pad = "Z" * [Math]::Max(0, $Bytes - $Marker.Length)
    $body = $Marker + $pad
    $f = Join-Path $ConfRoot "body-$Bytes.bin"
    Set-Content -Path $f -Value $body -NoNewline -Encoding ascii
    return $f
}

function Invoke-BodyProbe([string]$Name, [int]$Bytes, [string]$Marker) {
    $f = New-BodyFile $Bytes $Marker
    $resp = Join-Path $ConfRoot "resp-$Bytes.bin"
    $codeFile = Join-Path $ConfRoot "code-$Bytes.txt"
    & $curl -s --max-time $TimeoutSec -X POST `
            -H "Content-Type: application/octet-stream" `
            --data-binary "@$f" "$probeUrl" `
            -o $resp -w "%{http_code}" | Set-Content $codeFile
    $code = (Get-Content $codeFile -ErrorAction SilentlyContinue).Trim()
    $got  = if (Test-Path $resp) { (Get-Item $resp).Length } else { 0 }
    if ($code -eq "" -or $LASTEXITCODE -eq 28) {
        # curl exit 28 == --max-time exceeded => STALL.
        Write-Verdict $Name "STALL" "no response within ${TimeoutSec}s (curl exit $LASTEXITCODE)"
        return @{ Name = $Name; Ok = $false; Status = "STALL" }
    }
    if ($code -ne "200") {
        Write-Verdict $Name "FAIL" "HTTP $code (expected 200)"
        return @{ Name = $Name; Ok = $false; Status = "HTTP $code" }
    }
    if ($got -lt $Bytes) {
        Write-Verdict $Name "TRUNCATED" "echoed $got of $Bytes bytes"
        return @{ Name = $Name; Ok = $false; Status = "TRUNCATED" }
    }
    Write-Verdict $Name "PASS" "echoed $got of $Bytes bytes, HTTP $code"
    return @{ Name = $Name; Ok = $true; Status = "PASS" }
}

$control = Invoke-BodyProbe "control-1KiB" $ControlBytes "arrctl=1&pad="
$target  = Invoke-BodyProbe "target-100KiB" $TargetBytes "arrbodyprobe=1&pad="

# ---------------------------------------------------------------------------
# 7) cleanup + verdict
# ---------------------------------------------------------------------------
if (-not $beProc.HasExited) { $beProc.Kill() }
& $appcmd delete site $SiteName 2>$null | Out-Null
& $appcmd delete apppool $PoolName 2>$null | Out-Null

$allOk = $control.Ok -and $target.Ok
Write-Host "=============================================="
if ($allOk) {
    Write-Host "ARR body-forward VERIFICATION: PASS (control + 100KiB both intact)."
    exit 0
} else {
    Write-Host "ARR body-forward VERIFICATION: FAIL"
    Write-Host "  control  : $($control.Status)"
    Write-Host "  target   : $($target.Status)"
    Write-Host ""
    Write-Host "If target is STALL/TRUNCATED, this reproduces the bench-harness defect"
    Write-Host "(bench/README.md: 'v3: 100 KiB request bodies stall through ARR')."
    Write-Host "Diagnostics: $ConfRoot (body-*.bin, resp-*.bin, code-*.txt)"
    exit 1
}
