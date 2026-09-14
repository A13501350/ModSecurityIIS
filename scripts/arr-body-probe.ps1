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

# Guard: a parameter-binding mistake (e.g. positional array splat) could land a
# file path (the MSI) in $ConfRoot. Keep it a real config root.
if ($ConfRoot -and ($ConfRoot -like '*.msi' -or (Test-Path $ConfRoot -PathType Leaf))) {
    Write-Warning ("[guard] ConfRoot '{0}' is not a directory; resetting to C:\inetpub\modsec-arr" -f $ConfRoot)
    $ConfRoot = "C:\inetpub\modsec-arr"
}

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
# The tracing section is LOCKED for delegation by default (overrideModeDefault
# Deny in applicationHost.config), so writing it at site/<location> level fails
# (appcmd exit 2/1413) and hand-editing a <location> tracing node yields a
# "Configuration error" that breaks the whole site (every request -> HTTP 000).
# The fix is to UNLOCK the tracing section for the site first, then set it
# per-site via appcmd /commit:site. If that still fails we fall back to a
# SERVER-GLOBAL rule (valid at server level), which traces every site but does
# not corrupt the config. FREB is enabled BEFORE the probes so stalls are
# captured.
# ---------------------------------------------------------------------------
function Enable-Freb {
    param([string]$SiteName, [string]$Dir, [string]$Appcmd)
    Write-Host "[FREB] enabling IIS Failed Request Tracing (per-site, before probes)"
    New-Item -ItemType Directory -Force $Dir -ErrorAction SilentlyContinue | Out-Null
    # The worker process writes the trace files; grant it write on the dir.
    try { icacls "$Dir" /grant "IIS_IUSRS:(OI)(CI)F" | Out-Null } catch { }

    # 1) Windows feature. Use the Server-Manager path (Install-WindowsFeature
    #    Web-Http-Tracing) FIRST: it registers the tracing section with the
    #    config system reliably. The DISM feature name (IIS-HttpTracing) can
    #    leave the box servicing-pending with "Unknown config section
    #    system.webServer/tracing" (v7 evidence) even after a W3SVC restart.
    $tracingFeat = Get-WindowsFeature Web-Http-Tracing -ErrorAction SilentlyContinue
    if ($tracingFeat -and -not $tracingFeat.Installed) {
        Install-WindowsFeature Web-Http-Tracing | Out-Null
        Write-Host "[FREB] Web-Http-Tracing feature installed."
    } elseif ($tracingFeat -and $tracingFeat.Installed) {
        Write-Host "[FREB] Web-Http-Tracing already installed."
    } else {
        try {
            Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpTracing -All `
                -NoRestart -ErrorAction Stop | Out-Null
            Write-Host "[FREB] IIS-HttpTracing feature enabled (DISM path)."
        } catch {
            Write-Warning ("[FREB] feature via cmdlet failed: {0}; trying dism" -f $_.Exception.Message)
            & dism /Online /Enable-Feature /FeatureName:IIS-HttpTracing /All /NoRestart 2>&1 | Write-Host
        }
    }

    # 2) Restart W3SVC+WAS so the freshly enabled feature's module is loaded
    #    before we touch tracing config.
    & iisreset /stop  2>&1 | Out-Null; Start-Sleep -Seconds 3
    & iisreset /start 2>&1 | Out-Null
    foreach ($i in 1..30) {
        if ((Get-Service W3SVC).Status -eq "Running") { break }
        Start-Sleep -Seconds 1
    }
    Start-Sleep -Seconds 3

    # 3) Verify the config system knows the REAL section. NOTE:
    #    "system.webServer/tracing" alone is a sectionGROUP and is unknown to
    #    appcmd on EVERY IIS (verified locally) -- the sections are
    #    tracing/traceFailedRequests and tracing/traceProviderDefinitions, and
    #    traceFailedRequestsLogging is an ELEMENT of the site definition inside
    #    system.applicationHost/sites (not a section at all).
    $null = & $Appcmd list config /section:system.webServer/tracing/traceFailedRequests 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("[FREB] config system does not know section " +
               "system.webServer/tracing/traceFailedRequests (exit {0}); " +
               "feature registration did not land." -f $LASTEXITCODE)
    }
    Write-Host "[FREB] tracing section is known to the config system."

    # 4) OFFICIAL cmdlet (learn.microsoft.com, WebAdministration/
    #    Enable-WebRequestTracing): enables request tracing for the site AND
    #    creates the trace rule in one shot. -StatusCodes "200-599" traces every
    #    completion (a truncated 200 is caught; stalls land via their eventual
    #    ARR 502 or long timeTaken). Non-fatal: if the cmdlet path fails we warn
    #    and continue -- the probes themselves must always run.
    try {
        Import-Module WebAdministration -ErrorAction Stop
        Enable-WebRequestTracing -Name $SiteName -Directory $Dir -MaxLogFiles 50 `
            -StatusCodes "200-599"
        Write-Host "[FREB] Enable-WebRequestTracing applied."
    } catch {
        Write-Warning ("[FREB] Enable-WebRequestTracing failed: {0}" -f $_.Exception.Message)
        return
    }

    # 5) Read the config back so the log shows what the config system sees.
    $rb = & $Appcmd list config "$SiteName" /section:system.webServer/tracing/traceFailedRequests 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("[FREB] could not read back tracing config (exit {0})." -f $LASTEXITCODE)
    } else {
        Write-Host "[FREB] tracing config read-back:"
        $rb | ForEach-Object { Write-Host "  $_" }
    }
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
    # Event structure (verified against a real trace): each <Event> carries
    # <EventData><Data Name="ModuleName">...</Data></EventData> and a friendly
    # event name in <RenderingInfo><Opcode>NAME</Opcode></RenderingInfo>.
    # Notification/ModuleName are NOT attributes. For stalls the interesting
    # value is the last NOTIFY_MODULE_START's module (the module that was
    # entered and never completed).
    $rows = foreach ($f in $files) {
        try { [xml]$x = Get-Content $f.FullName } catch { continue }
        $fr = $x.failedRequest
        $events = @($fr.Event)
        $lastOp = ""; $lastMod = ""; $lastModStart = ""
        foreach ($e in $events) {
            $op = $e.RenderingInfo.Opcode
            if ($op) { $lastOp = $op }
            $m = @($e.EventData.Data) | Where-Object { $_.Name -eq 'ModuleName' } |
                     Select-Object -First 1
            if ($m -and $m.InnerText) {
                $lastMod = $m.InnerText
                if ($op -eq 'NOTIFY_MODULE_START') { $lastModStart = $m.InnerText }
            }
        }
        [pscustomobject]@{
            File           = $f.Name
            Url            = if ($fr.url) { $fr.url } else { "?" }
            Status         = if ($fr.statusCode) { $fr.statusCode } else { "?" }
            TimeTakenMs    = if ($fr.timeTaken) { [long]$fr.timeTaken } else { 0 }
            FailureReason  = if ($fr.failureReason) { $fr.failureReason } else { "" }
            LastEvent      = $lastOp
            LastModule     = $lastMod
            LastModStart   = $lastModStart
        }
    }
    $rows = $rows | Sort-Object TimeTakenMs -Descending
    foreach ($r in $rows) {
        $tag = ""
        if ($r.Url -match '/echo') { $tag += " [ECHO-BODY]" }
        if ("$($r.Status)" -match '^5') { $tag += " [5xx]" }
        Write-Host ("[FREB] {0,-14} status={1,-4} tt={2,-8} last={3}/{4}{5}" -f `
            $r.File, $r.Status, $r.TimeTakenMs, $r.LastEvent, $r.LastModule, $tag)
        if ($r.LastModStart)  { Write-Host ("        lastModuleEntered: {0}" -f $r.LastModStart) }
        if ($r.FailureReason) { Write-Host ("        failureReason    : {0}" -f $r.FailureReason) }
    }
    Write-Host "[FREB] interpretation:"
    Write-Host "[FREB]   lastModuleEntered=ModSecurityIIS (no NOTIFY_MODULE_END) => connector body-read blocked."
    Write-Host "[FREB]   trailing ARR/rewrite events without response entity  => ARR forward to backend blocked."
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
# 0b) body-trace (diag branch instrumentation). The connector (this branch)
#     logs every entity-body state transition when MODSEC_IIS_BODY_TRACE=1 and
#     MODSEC_IIS_TRACE_FILE are set in the w3wp environment. Set them at
#     machine level before any iisreset so the worker processes inherit them.
# ---------------------------------------------------------------------------
[Environment]::SetEnvironmentVariable("MODSEC_IIS_BODY_TRACE", "1", "Machine")
[Environment]::SetEnvironmentVariable("MODSEC_IIS_TRACE_FILE",
    (Join-Path $ConfRoot "data\body-trace.log"), "Machine")

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
# Auto-discover the MSI when -Msi is empty or does not resolve. In CI the
# uploaded artifact lands nested (e.g. msi/msi-out/*.msi), so a non-recursive
# lookup misses it and the probe would never run.
if (-not $Msi -or -not (Test-Path $Msi)) {
    $cand = @(Get-ChildItem -Path $repoRoot -Recurse -Filter *.msi -ErrorAction SilentlyContinue) +
            @(Get-ChildItem -Path $ConfRoot -Recurse -Filter *.msi -ErrorAction SilentlyContinue)
    if ($cand.Count -gt 0) {
        $Msi = $cand[0].FullName
        Write-Host ("[MSI] auto-discovered: {0}" -f $Msi)
    }
}
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

# Start the echo backend. Its stderr (the ECHO diagnostic log lines) is
# captured to a file -- the arrival/read-complete/respond records are the
# bisect data for the stall (did the request reach the backend at all?).
$backendUrl = "http://127.0.0.1:$BackendPort"
$goArgs = @("run", $backendSrc, "-addr", "127.0.0.1:$BackendPort")
$backendLog  = Join-Path $ConfRoot "backend.log"
$backendOut  = Join-Path $ConfRoot "backend-stdout.log"
$beProc = Start-Process -FilePath $BackendExe -ArgumentList $goArgs `
                        -WindowStyle Hidden -PassThru `
                        -RedirectStandardError $backendLog `
                        -RedirectStandardOutput $backendOut
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

# Sanity gate: a bad FREB config (e.g. a locked-section write) raises a
# Configuration error that 000s every request and would invalidate the whole
# run. If the site is down after the FREB enable, revert the tracing config and
# restart so the probes still measure the real connector/ARR behavior.
if ($frebOn) {
    # NOTE: use /healthz, NOT /hello.txt. The site's rewrite rule matches url=".*"
    # and forwards EVERYTHING to the echo backend, so /hello.txt is answered by
    # the backend with 404 (v9: that 404 made this gate misfire, revert a
    # perfectly good FREB config, and the 10 captured 404 traces were the gate's
    # own retries). /healthz goes through the same rewrite path and returns 200.
    $sane = $false
    foreach ($i in 1..10) {
        try {
            $r = Invoke-WebRequest "http://127.0.0.1:$Port/healthz" -UseBasicParsing `
                     -SkipHttpErrorCheck -TimeoutSec 5
            if ($r.StatusCode -eq 200) { $sane = $true; break }
        } catch { Start-Sleep -Seconds 2 }
    }
    if ($sane) {
        Write-Host "[FREB] post-enable sanity: site serving (/healthz 200)."
    } else {
        Write-Warning "[FREB] site NOT serving after FREB enable -- reverting tracing config (self-heal)."
        try {
            Import-Module WebAdministration -ErrorAction Stop
            Disable-WebRequestTracing -Name $SiteName -ErrorAction SilentlyContinue
        } catch {
            Write-Warning ("[FREB] Disable-WebRequestTracing failed: {0}" -f $_.Exception.Message)
        }
        & iisreset /stop 2>&1 | Out-Null; Start-Sleep -Seconds 2
        & iisreset /start 2>&1 | Out-Null
        foreach ($i in 1..30) {
            if ((Get-Service W3SVC).Status -eq "Running") { break }
            Start-Sleep -Seconds 1
        }
        & $appcmd start site $SiteName 2>&1 | Out-Null
        Write-Warning "[FREB] reverted; probes will run WITHOUT FREB traces."
    }
}

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
    # Snapshot in-flight requests WHILE the load is running. v11 proved that a
    # stalled request is torn down the moment its client disconnects (curl
    # --max-time), so post-phase snapshots always see 0 and FREB can never
    # capture a stall (an aborted request never "completes"). Get-WebRequest
    # during the load shows what each in-flight request is doing RIGHT NOW.
    $snapLog = Join-Path $ConfRoot "inflight-snapshots.log"
    Remove-Item $snapLog -ErrorAction SilentlyContinue
    $maxInflight = 0
    try { Import-Module WebAdministration -ErrorAction SilentlyContinue } catch { }
    while (@($jobs | Where-Object { $_.State -eq 'Running' }).Count -gt 0) {
        try {
            $inflight = @(Get-WebRequest -ApplicationPool $PoolName -ErrorAction SilentlyContinue)
            $ts = (Get-Date).ToString('HH:mm:ss.fff')
            Add-Content $snapLog ("[{0}] inflight={1}" -f $ts, $inflight.Count)
            if ($inflight.Count -gt $maxInflight) { $maxInflight = $inflight.Count }
            foreach ($r in ($inflight | Sort-Object { [long]$_.timeElapsed } -Descending)) {
                Add-Content $snapLog ("    {0} {1} elapsed={2}ms state={3}" -f `
                    $r.verb, $r.url, $r.timeElapsed, $r.state)
                if ([long]$r.timeElapsed -gt 10000) {
                    $dump = $r | Format-List * | Out-String
                    Add-Content $snapLog ("    >>> LONG-RUNNING REQUEST (>{0}ms) FULL DUMP:`n{1}" -f 10000, $dump)
                }
            }
        } catch { }
        Start-Sleep -Milliseconds 1500
    }
    $results = $jobs | Receive-Job -Wait -AutoRemoveJob
    $stall = 0; $trunc = 0; $pass = 0
    foreach ($r in $results) { $stall += $r.stall; $trunc += $r.trunc; $pass += $r.pass }
    $total = $stall + $trunc + $pass
    $status = if ($stall -eq 0 -and $trunc -eq 0) { "PASS" } else { "STALL/TRUNC" }
    Write-Verdict $Name $status "pass=$pass stall=$stall truncated=$trunc of $total (clients=$Clients reps=$Reps)"
    # Surface what the snapshots saw: any request still executing after >=10s
    # is a stalled one -- its state/module IS the blocking stage.
    $slow = @(Get-Content $snapLog -ErrorAction SilentlyContinue |
              Where-Object { $_ -match 'elapsed=\d{5,}ms' })
    Write-Host ("[SNAP] max concurrent in-flight seen: {0}; slow (>10s) entries: {1}; log: {2}" -f `
        $maxInflight, $slow.Count, $snapLog)
    $slow | Select-Object -First 40 | ForEach-Object { Write-Host "[SNAP] $_" }
    return @{ Name = $Name; Ok = ($stall -eq 0 -and $trunc -eq 0); Status = $status;
              Pass = $pass; Stall = $stall; Trunc = $trunc; Total = $total }
}

$control = Invoke-BodyProbe "control-1KiB" $ControlBytes "arrctl=1&pad="
$target  = Invoke-BodyProbe "target-100KiB" $TargetBytes "arrbodyprobe=1&pad="

Write-Host "--- concurrency phase (load generator) ---"
$c1  = Invoke-ConcurrencyProbe "load-c1"  1          $LoadReps $TargetBytes "arrload=1&pad="
$c16 = Invoke-ConcurrencyProbe "load-c16" $LoadClients $LoadReps $TargetBytes "arrload=16&pad="

# ---------------------------------------------------------------------------
# 6b) backend bisect -- did the stalled requests reach the echo backend at all?
#     Correlates the backend's ECHO log lines (arrival / read-complete /
#     responded / read-error) with the probe's stall count:
#       arrivals ~ total sent            => stall is on the RESPONSE path back
#       arrivals < total sent            => stall is BEFORE the backend
#                                           (connector body-read or ARR forward)
#       ECHO-ERR read-failed mid-body    => the ARR re-read of the
#                                           InsertEntityBody stream stalled
# Give late ECHO-ERRs (aborted clients) a few seconds to land first.
# ---------------------------------------------------------------------------
Start-Sleep -Seconds 5
$arrivals  = @(Select-String -Path $backendLog -Pattern 'ECHO arrived'  -ErrorAction SilentlyContinue)
$responded = @(Select-String -Path $backendLog -Pattern 'ECHO responded' -ErrorAction SilentlyContinue)
$readerrs  = @(Select-String -Path $backendLog -Pattern 'ECHO-ERR'      -ErrorAction SilentlyContinue)
$totalSent = $c1.Total + $c16.Total + 2   # + control + target
Write-Host ("[BACKEND] arrivals={0} responded={1} read-errors={2} (probe sent {3} body requests)" -f `
    $arrivals.Count, $responded.Count, $readerrs.Count, $totalSent)
if ($readerrs.Count -gt 0) {
    Write-Host "[BACKEND] read-error lines (ARR re-read of the re-inserted body stalled mid-transfer):"
    $readerrs | Select-Object -First 10 | ForEach-Object { Write-Host ("  " + $_.Line) }
}
$missing = $totalSent - $arrivals.Count
if ($missing -gt 0) {
    Write-Host ("[BACKEND] {0} request(s) NEVER reached the backend => stall is pre-forward " -f $missing)
    Write-Host "[BACKEND] (connector DriveBodyRead/InsertEntityBody or ARR before forwarding)."
} else {
    Write-Host "[BACKEND] all requests reached the backend => stall is on the response path back to the client."
}

# ---------------------------------------------------------------------------
# 6c) body-trace verdict -- decide between the three stall hypotheses using the
#     connector's entity-body trace (enabled via MODSEC_IIS_BODY_TRACE):
#       FINISH size == declared  => full body WAS inserted; the entity pipe
#                                   lost the "more data" signal toward ARR
#                                   (IIS-side, hypothesis C1)
#       FINISH size < declared   => the connector finished the read EARLY on a
#                                   misjudged short-read/EOF (the reason=
#                                   field names the exact stop condition;
#                                   hypothesis: misjudged EOF)
#       BEGIN without FINISH     => a completion the module never saw --
#                                   the request wedged in BEGIN_REQUEST
#                                   (hypothesis C2)
#       INSERT hr != 0           => InsertEntityBody itself failed (C3)
# ---------------------------------------------------------------------------
$traceLog = Join-Path $ConfRoot "data\body-trace.log"
if (-not (Test-Path $traceLog)) {
    Write-Host "[BODYTRACE] no trace file at $traceLog (env var did not reach w3wp?)."
} else {
    $begins   = @(Select-String -Path $traceLog -Pattern 'BEGIN rsc=([0-9A-Fa-f]+)')
    $finishes = @(Select-String -Path $traceLog -Pattern 'FINISH rsc=([0-9A-Fa-f]+) reason=(\S+) size=(\d+)')
    $bRsc = $begins   | ForEach-Object { $_.Matches[0].Groups[1].Value } | Sort-Object -Unique
    $fRsc = $finishes | ForEach-Object { $_.Matches[0].Groups[1].Value } | Sort-Object -Unique
    $wedged = @($bRsc | Where-Object { $fRsc -notcontains $_ })
    Write-Host ("[BODYTRACE] began={0} finished={1} wedged(no-FINISH)={2}" -f `
        $bRsc.Count, $fRsc.Count, $wedged.Count)

    $reasons = $finishes | ForEach-Object { $_.Matches[0].Groups[2].Value } |
               Group-Object | Sort-Object Count -Descending
    Write-Host ("[BODYTRACE] finish reasons: " +
        (($reasons | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) -join " "))

    # Declared sizes seen in the trace (102400 = probe target, 1024 = control).
    $short = @($finishes | Where-Object {
        $s = [long]$_.Matches[0].Groups[3].Value
        $s -ne 0 -and $s -ne 102400 -and $s -ne 1024
    })
    Write-Host ("[BODYTRACE] SHORT finishes (size not 0/1024/102400 -- misjudged-EOF evidence): {0}" -f `
        $short.Count)
    $short | Select-Object -First 10 | ForEach-Object { Write-Host ("  " + $_.Line) }

    $badInsert = @(Select-String -Path $traceLog -Pattern 'INSERT .*hr=0x(?!00000000)')
    Write-Host ("[BODYTRACE] INSERT failures: {0}" -f $badInsert.Count)
    $badInsert | Select-Object -First 5 | ForEach-Object { Write-Host ("  " + $_.Line) }

    if ($wedged.Count -gt 0) {
        Write-Host "[BODYTRACE] wedged rsc ids (first 5): $($wedged | Select-Object -First 5)"
    }
}

# ---------------------------------------------------------------------------
# 6a) final in-flight check. The PRIMARY in-flight diagnostic now lives INSIDE
#     Invoke-ConcurrencyProbe (snapshots taken WHILE the load is running): v11
#     proved that a stalled request is torn down the instant its client
#     disconnects (curl --max-time), so after the phase there is nothing left
#     to see. This final check remains as a cheap sanity probe.
# ---------------------------------------------------------------------------
try {
    Import-Module WebAdministration -ErrorAction Stop
    # Do NOT suppress errors here: v12 showed this API returns nothing at all on
    # the runner's minimal IIS (no management tools), and the swallowed error
    # made every request look invisible. Let a failure land in the catch so the
    # real cause is printed.
    $inflight = @(Get-WebRequest -ApplicationPool $PoolName)
    if ($inflight.Count -eq 0) {
        $inflight = @(Get-WebRequest -ErrorAction SilentlyContinue)
    }
    Write-Host ("[INFLIGHT] after load phase: {0} request(s) still executing (pool {1})" -f `
        $inflight.Count, $PoolName)
    foreach ($r in ($inflight | Select-Object -First 10)) {
        Write-Host ("[INFLIGHT] {0} {1} elapsed={2}ms state={3}" -f `
            $r.verb, $r.url, $r.timeElapsed, $r.state)
    }
    if ($inflight.Count -gt 0) {
        Write-Host "[INFLIGHT] full record of the first in-flight request:"
        $inflight[0] | Format-List * | Out-String | ForEach-Object { Write-Host $_ }
    }
} catch {
    Write-Warning ("[INFLIGHT] snapshot failed: {0}" -f $_.Exception.Message)
}

# ---------------------------------------------------------------------------
# 6b) FREB trace summary (opt-in) -- pinpoint the blocking stage for stalls
# ---------------------------------------------------------------------------
if ($frebOn) {
    # A stalled request that curl aborts at $TimeoutSec keeps running server-side
    # until ARR's proxy timeout (~120s) before completing, and FREB only FLUSHES
    # its XML when the request completes. So traces for the stalls do not exist
    # yet. Wait for the server-side requests to finish so FREB writes them, then
    # summarize. (Healthy 200s flush immediately, so we stop early once we have
    # traces and >=60s have elapsed to let the late stalls land.)
    $deadline = [DateTime]::Now.AddSeconds(150)
    while ([DateTime]::Now -lt $deadline) {
        $fc = @(Get-ChildItem $frebDir -Recurse -Filter fr*.xml -ErrorAction SilentlyContinue)
        if ($fc.Count -gt 0 -and ([DateTime]::Now -ge $deadline.AddSeconds(-60))) { break }
        Start-Sleep -Seconds 10
    }
    Get-FrebSummary -Dir $frebDir
}

# ---------------------------------------------------------------------------
# 7) cleanup + verdict
# ---------------------------------------------------------------------------
# Stop IIS FIRST: that flushes the buffered W3C access logs (they can lag up to
# 60s otherwise) so they can be collected into the diagnostics artifact. The
# W3C time-taken field gives the server-side view of every request without FREB.
& iisreset /stop 2>&1 | Out-Null
Copy-Item "C:\inetpub\logs\LogFiles" (Join-Path $ConfRoot "iis-logs") `
    -Recurse -Force -ErrorAction SilentlyContinue
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
    Write-Host "Diagnostics: $ConfRoot (backend.log, inflight-snapshots.log, iis-logs\, body-*.bin, resp-*.bin, code-*.txt)"
    exit 1
}
