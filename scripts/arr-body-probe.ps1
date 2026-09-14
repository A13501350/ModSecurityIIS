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
#   ./scripts/arr-body-probe.ps1 -Msi <path-to.msi> -Freb   # also capture IIS FREB traces
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
    [int]   $TimeoutSec   = 30,
    # Concurrency phase (mirrors the bench harness's load generator). The
    # reported stall is load/concurrency dependent ("c=16 partially works
    # around it"), so a single-request probe is not enough to reproduce it.
    [int]   $LoadClients    = 16,
    [int]   $LoadReps       = 4,
    # Opt-in IIS Failed Request Tracing (FREB). Off by default; enable via -Freb
    # or $env:MODSEC_IIS_FREB=1. When on, the connector+ARR pipeline is traced
    # and stalled 100 KiB POSTs are captured so the blocking stage can be pinned
    # (connector body-read vs ARR forward). See Enable-Freb / Get-FrebSummary.
    [switch]$Freb
)

$ErrorActionPreference = "Stop"

$frebOn  = $Freb -or ($env:MODSEC_IIS_FREB -eq '1') -or ($env:MODSEC_IIS_FREB -ieq 'true')
$frebDir = Join-Path $ConfRoot "freb"

$appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
$curl   = "$env:windir\System32\curl.exe"

function Write-Verdict {
    param([string]$Name, [string]$Status, [string]$Detail = "")
    $line = "[$Name] $Status"
    if ($Detail) { $line += " -- $Detail" }
    Write-Host $line
}

# ---------------------------------------------------------------------------
# FREB (IIS Failed Request Tracing) -- correct, per-site enabling.
#
# Unlike the prior global applicationHost.config hand-edit (scripts/ci-crs.ps1
# 7a) that wrote the trace rule server-wide (tracing every site and wedging the
# box into a servicing-pending state after iisreset), this scopes the rule to
# the probe site only via appcmd /commit:site (=> <location path="SiteName">).
# It is also enabled BEFORE the probes run, so the stalls are actually captured.
# ---------------------------------------------------------------------------
function Enable-Freb {
    param([string]$SiteName, [string]$Dir, [string]$Appcmd)
    Write-Host "[FREB] enabling IIS Failed Request Tracing (per-site, before probes)"
    New-Item -ItemType Directory -Force $Dir -ErrorAction SilentlyContinue | Out-Null

    # 1) Windows feature (IIS-HttpTracing). -NoRestart: W3SVC reloads it on the
    #    restart we perform after all site config is committed (see step 5).
    try {
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpTracing -All `
            -NoRestart -ErrorAction Stop | Out-Null
        Write-Host "[FREB] IIS-HttpTracing feature enabled."
    } catch {
        Write-Warning ("[FREB] feature via cmdlet failed: {0}; trying dism" -f $_.Exception.Message)
        & dism /Online /Enable-Feature /FeatureName:IIS-HttpTracing /All /NoRestart 2>&1 | Write-Host
    }

    # 2) Turn on trace-failed-request logging for THIS site only (/commit:site).
    & $Appcmd set config $SiteName `
        /section:system.webServer/tracing/traceFailedRequestsLogging `
        /enabled:true /directory:"$Dir" /maxLogFiles:50 /commit:site 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("[FREB] traceFailedRequestsLogging set failed (exit {0})" -f $LASTEXITCODE)
    }

    # 3) Per-site trace rule. WWW Server provider, Verbose. Capture stalls
    #    (timeTaken >= 25s -- our curl stall is 30s) and every 2xx-5xx so a
    #    truncated 200 is caught too. Healthy fast 200s that finish < 25s would
    #    still be traced (200-599 covers all completions); that is intentional
    #    for a debug run so no symptom is missed.
    $areas = "RequestNotifications,Modules,Security,Filter,StaticFile,Rewrite,RequestRouting"
    $rule  = "[path='*',traceAreas='{WWW Server&$areas}',verbosity='Verbose',failureDefinitions='{statusCodes=200-599,timeTaken=00:00:25}']"
    & $Appcmd set config $SiteName `
        /section:system.webServer/tracing/traceFailedRequests /+$rule /commit:site 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("[FREB] appcmd rule add failed (exit {0}); falling back to <location> XML edit" -f $LASTEXITCODE)
        Set-FrebRuleViaXml -SiteName $SiteName -Dir $Dir -Areas $areas
    } else {
        Write-Host "[FREB] per-site trace rule added (statusCodes=200-599, timeTaken>=25s)."
    }
}

# Fallback: write the per-site rule under <location path="SiteName"> in
# applicationHost.config (NOT the global <system.webServer>/<tracing> node).
function Set-FrebRuleViaXml {
    param([string]$SiteName, [string]$Dir, [string]$Areas)
    $ah = "$env:windir\System32\inetsrv\config\applicationHost.config"
    [xml]$doc = Get-Content $ah
    $loc = @($doc.configuration.location) | Where-Object { $_.path -eq $SiteName } | Select-Object -First 1
    if (-not $loc) {
        $loc = $doc.configuration.AppendChild($doc.CreateElement("location"))
        $loc.SetAttribute("path", $SiteName)
    }
    $sws = $loc."system.webServer"
    if (-not $sws) { $sws = $loc.AppendChild($doc.CreateElement("system.webServer")) }
    $tracing = $sws.tracing
    if (-not $tracing) { $tracing = $sws.AppendChild($doc.CreateElement("tracing")) }

    $tfrl = $tracing.traceFailedRequestsLogging
    if (-not $tfrl) { $tfrl = $tracing.AppendChild($doc.CreateElement("traceFailedRequestsLogging")) }
    $tfrl.SetAttribute("enabled", "true")
    $tfrl.SetAttribute("directory", $Dir)
    $tfrl.SetAttribute("maxLogFiles", "50")

    $tfr = $tracing.traceFailedRequests
    if (-not $tfr) { $tfr = $tracing.AppendChild($doc.CreateElement("traceFailedRequests")) }
    $tfr.RemoveAll()
    $add = $doc.CreateElement("add"); $add.SetAttribute("path", "*")
    $ta = $doc.CreateElement("traceAreas")
    $prov = $doc.CreateElement("add")
    $prov.SetAttribute("provider", "WWW Server")
    $prov.SetAttribute("areas", $Areas)
    $prov.SetAttribute("verbosity", "Verbose")
    [void]$ta.AppendChild($prov)
    [void]$add.AppendChild($ta)
    $fd = $doc.CreateElement("failureDefinitions")
    $fd.SetAttribute("statusCodes", "200-599")
    $fd.SetAttribute("timeTaken", "00:00:25")
    [void]$add.AppendChild($fd)
    [void]$tfr.AppendChild($add)
    $doc.Save($ah)
    Write-Host "[FREB] per-site trace rule written via applicationHost.config <location> fallback."
}

# Parse captured FREB XML files and surface, for each traced request, the URL
# (which carries our probe markers) plus the LAST pipeline notification/module
# -- that last event is where the request was when tracing fired, i.e. the
# blocking stage. Slowest (stalls) are printed first.
function Get-FrebSummary {
    param([string]$Dir)
    Write-Host "`n========== FREB trace summary ($Dir) =========="
    $files = @(Get-ChildItem $Dir -Recurse -Filter fr*.xml -ErrorAction SilentlyContinue)
    if ($files.Count -eq 0) {
        Write-Host "[FREB] no trace files captured (was FREB enabled and did traffic flow?)."
        return
    }
    Write-Host ("[FREB] {0} trace file(s) captured." -f $files.Count)
    $rows = foreach ($f in $files) {
        try { [xml]$x = Get-Content $f.FullName } catch { continue }
        $fr = $x.failedRequest
        $url    = if ($fr.url) { $fr.url } else { "?" }
        $status = if ($fr.statusCode) { $fr.statusCode } else { $fr.Event.statusCode }
        $tt     = if ($fr.timeTaken) { $fr.timeTaken } else { $fr.Event.timeTaken }
        $trig   = $fr.triggeredByNotification
        $events = @($fr.Event)
        $last   = $events | Select-Object -Last 1
        [pscustomobject]@{
            File              = $f.Name
            Url               = $url
            Status            = $status
            TimeTaken         = $tt
            TriggeredBy       = $trig
            LastNotification  = if ($last) { $last.Notification } else { "?" }
            LastModule        = if ($last) { $last.ModuleName } else { "?" }
            Reason            = if ($last) { $last.Reason } else { "" }
            ErrorCode         = if ($last) { $last.ErrorCode } else { "" }
        }
    }
    $rows = $rows | Sort-Object {
        try { [TimeSpan]::Parse($_.TimeTaken) } catch { [TimeSpan]::Zero }
    } -Descending
    foreach ($r in $rows) {
        $tag = ""
        if ($r.Url -match '/echo') { $tag += " [ECHO-BODY]" }
        if ("$r.Status" -match '^5') { $tag += " [5xx]" }
        Write-Host ("[FREB] {0,-22} status={1,-4} tt={2,-14} last={3}/{4}{5}" -f `
            $r.File, $r.Status, $r.TimeTaken, $r.LastNotification, $r.LastModule, $tag)
        if ($r.TriggeredBy) { Write-Host ("        triggeredBy: {0}" -f $r.TriggeredBy) }
        if ($r.Reason)      { Write-Host ("        reason     : {0}" -f $r.Reason) }
        if ($r.ErrorCode)   { Write-Host ("        errorCode  : {0}" -f $r.ErrorCode) }
    }
    Write-Host "[FREB] interpretation:"
    Write-Host "[FREB]   last=RQ_BEGIN_REQUEST / ModSecurityIIS  => connector body-read blocked (DriveBodyRead/InsertEntityBody)."
    Write-Host "[FREB]   last=ApplicationRequestRouting / routing notification => ARR forward to backend blocked."
    Write-Host "[FREB]   markers in URL: arrctl (1KiB control), arrbodyprobe (100KiB), arrload=16 (concurrency)."
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

# ---------------------------------------------------------------------------
# 5b) opt-in FREB -- enable per-site BEFORE the probes so stalled 100 KiB
#     POSTs are captured (pinpoints connector body-read vs ARR forward).
# ---------------------------------------------------------------------------
if ($frebOn) {
    Write-Host "[FREB] enabling per-site Failed Request Tracing (before probes)"
    Enable-Freb -SiteName $SiteName -Dir $frebDir -Appcmd $appcmd
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

# Fires $Clients concurrent clients, each sending $Reps sequential 100 KiB
# POSTs through the ARR proxy. Mirrors the bench harness's load generator.
# The reported stall is concurrency/load dependent, so this is the phase that
# actually reproduces it (a single request is healthy -- see the probes above).
function Invoke-ConcurrencyProbe([string]$Name, [int]$Clients, [int]$Reps, [int]$Bytes, [string]$Marker) {
    $f = New-BodyFile $Bytes $Marker
    $jobs = @()
    for ($i = 0; $i -lt $Clients; $i++) {
        $jobs += Start-ThreadJob -ScriptBlock {
            param($curlExe, $url, $body, $timeout, $reps, $bytes)
            $stall = 0; $trunc = 0; $pass = 0
            for ($k = 0; $k -lt $reps; $k++) {
                $resp = [System.IO.Path]::GetTempFileName()
                & $curlExe -s --max-time $timeout -X POST `
                    -H "Content-Type: application/octet-stream" `
                    --data-binary "@$body" $url -o $resp -w "%{http_code}" 2>$null
                $code = $LASTEXITCODE
                $len  = if (Test-Path $resp) { (Get-Item $resp).Length } else { 0 }
                if ($code -eq 28 -or $len -eq 0) { $stall++ }
                elseif ($len -lt $bytes) { $trunc++ }
                else { $pass++ }
            }
            return @{ stall = $stall; trunc = $trunc; pass = $pass }
        } -ArgumentList $curl, $probeUrl, $f, $TimeoutSec, $Reps, $Bytes
    }
    $results = $jobs | Receive-Job -Wait -AutoRemoveJob
    $stall = 0; $trunc = 0; $pass = 0
    foreach ($r in $results) { $stall += $r.stall; $trunc += $r.trunc; $pass += $r.pass }
    $total = $stall + $trunc + $pass
    $status = if ($stall -eq 0 -and $trunc -eq 0) { "PASS" } else { "STALL/TRUNC" }
    Write-Verdict $Name $status "pass=$pass stall=$stall truncated=$trunc of $total (clients=$Clients reps=$Reps)"
    return @{ Name = $Name; Ok = ($stall -eq 0 -and $trunc -eq 0); Status = $status;
              Pass = $pass; Stall = $stall; Trunc = $trunc; Total = $total }
}

$control = Invoke-BodyProbe "control-1KiB" $ControlBytes "arrctl=1&pad="
$target  = Invoke-BodyProbe "target-100KiB" $TargetBytes "arrbodyprobe=1&pad="

Write-Host "--- concurrency phase (load generator) ---"
$c1  = Invoke-ConcurrencyProbe "load-c1"  1          $LoadReps $TargetBytes "arrload=1&pad="
$c16 = Invoke-ConcurrencyProbe "load-c16" $LoadClients $LoadReps $TargetBytes "arrload=16&pad="

# ---------------------------------------------------------------------------
# 6b) FREB trace summary (opt-in) -- pinpoint the blocking stage for stalls
# ---------------------------------------------------------------------------
if ($frebOn) {
    Get-FrebSummary -Dir $frebDir
}

# ---------------------------------------------------------------------------
# 7) cleanup + verdict
# ---------------------------------------------------------------------------
if (-not $beProc.HasExited) { $beProc.Kill() }
& $appcmd delete site $SiteName 2>$null | Out-Null
& $appcmd delete apppool $PoolName 2>$null | Out-Null

$allOk = $control.Ok -and $target.Ok -and $c1.Ok -and $c16.Ok
Write-Host "=============================================="
if ($allOk) {
    Write-Host "ARR body-forward VERIFICATION: PASS"
    Write-Host "  single-request : control + 100KiB intact"
    Write-Host "  concurrency     : c=1 and c=$LoadClients healthy (no stall/truncation under load)"
    exit 0
} else {
    Write-Host "ARR body-forward VERIFICATION: FAIL"
    Write-Host "  control  : $($control.Status)"
    Write-Host "  target   : $($target.Status)"
    Write-Host "  load-c1  : pass=$($c1.Pass) stall=$($c1.Stall) trunc=$($c1.Trunc) of $($c1.Total)"
    Write-Host "  load-c16 : pass=$($c16.Pass) stall=$($c16.Stall) trunc=$($c16.Trunc) of $($c16.Total)"
    Write-Host ""
    Write-Host "Any STALL/TRUNC under load reproduces the bench-harness defect"
    Write-Host "(bench/README.md: 'v3: 100 KiB request bodies stall through ARR')."
    Write-Host "Diagnostics: $ConfRoot (body-*.bin, resp-*.bin, code-*.txt)"
    exit 1
}
