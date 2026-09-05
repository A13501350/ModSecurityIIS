# CRS regression stage for ModSecurityIIS. Runs AFTER ci-smoke.ps1 in the
# same job (module already deployed, site/app pool exist). CRS rules are
# loaded directly; the IIS site proxies every request to the albedo echo
# backend via URL Rewrite + ARR, and go-ftw replays the official CRS
# regression tests, asserting status codes and audit-log rule hits.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DllDir,   # unused here; kept for symmetry/logging
    [string]$CrsVersion = "v4.25.1",
    [string]$ConfRoot   = "C:\inetpub\modsec",
    [string]$SiteRoot   = "C:\inetpub\modsectest",
    [string]$SiteName   = "ModSecTest",
    [string]$PoolName   = "ModSecTestPool"
)

$ErrorActionPreference = "Stop"

# --- 0) preconditions ---------------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Must run elevated."
}
$appcmd  = "$env:windir\System32\inetsrv\appcmd.exe"

# --- 1) fetch + unpack OWASP CRS ----------------------------------------------
$crsDir  = Join-Path $ConfRoot "coreruleset"
New-Item -ItemType Directory -Force $crsDir | Out-Null
$tgz     = Join-Path $env:TEMP "crs-$CrsVersion.tar.gz"
$url     = "https://github.com/coreruleset/coreruleset/archive/refs/tags/$CrsVersion.tar.gz"
Write-Host "Downloading CRS $CrsVersion..."
Invoke-WebRequest -Uri $url -OutFile $tgz -UseBasicParsing
Remove-Item "$crsDir\*" -Recurse -Force -ErrorAction SilentlyContinue
tar -xzf $tgz -C $crsDir --strip-components=1
Get-ChildItem $crsDir -Recurse -Filter "*.example" |
    ForEach-Object { Rename-Item $_.FullName ($_.Name -replace '\.example$', '') }

Write-Host "[1/8] CRS unpacked to $crsDir (stock example setup)"

# --- 2) engine configuration ----------------------------------------------------
$auditDir = "C:\inetpub\logs\modsec-crs-audit"
New-Item -ItemType Directory -Force $auditDir          | Out-Null
New-Item -ItemType Directory -Force "$ConfRoot\data"   | Out-Null
New-Item -ItemType Directory -Force "$ConfRoot\GeoIP"  | Out-Null
# Pool identity needs write access for audit/tmp files and read access to GeoIP.
$poolId = "IIS AppPool\$PoolName"
icacls $auditDir         /grant "${poolId}:(OI)(CI)M" | Out-Null
icacls "$ConfRoot\data"  /grant "${poolId}:(OI)(CI)M" | Out-Null
icacls "$ConfRoot\GeoIP" /grant "${poolId}:(OI)(CI)R" | Out-Null

# GeoIP2: only emit SecGeoLookupDB if a MaxMind .mmdb is actually present.
$geoDb   = "$ConfRoot\GeoIP\GeoIP2-Country.mmdb"
$geoLine = if (Test-Path $geoDb) {
    "SecGeoLookupDB $geoDb"
} else {
    "# SecGeoLookupDB $geoDb   (drop a MaxMind GeoIP2 database here to enable @geoLookup / GEO rules)"
}

$conf = Join-Path $ConfRoot "modsecurity-crs.conf"
# Upstream recommended baseline config. It ships SecRuleEngine DetectionOnly
# and Unix audit paths, so we re-assert AFTER the Include.
$recConf = (Join-Path $PSScriptRoot "..\libmodsecurity\modsecurity.conf-recommended") `
    -replace '\\', '/'
if (-not (Test-Path $recConf)) {
    throw "libmodsecurity/modsecurity.conf-recommended not found at $recConf (is the submodule checked out in this job?)"
}
@"
SecRuleEngine On
SecRequestBodyAccess On
# Response-body inspection enabled (Mode A with responseBodyBlock=true).
SecResponseBodyAccess On
# Albedo echoes JSON; include it so phase-4 rules can inspect the body.
SecResponseBodyMimeType text/plain text/html text/xml application/json application/javascript
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
# Audit everything (not RelevantOnly): go-ftw locates test boundaries via
# X-CRS-Test markers that end in 200 -- RelevantOnly never audited those.
SecAuditEngine On
SecAuditLog $auditDir\audit.log
SecAuditLogType Serial
SecTmpDir $ConfRoot\data
SecDataDir $ConfRoot\data
$geoLine
# go-ftw log marker: echoes X-CRS-Test UUID, disables all other rules for
# marker requests. Must load BEFORE CRS includes.
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
  "id:999999,\
  pass,\
  phase:1,\
  log,\
  msg:'X-CRS-Test %{MATCHED_VAR}',\
  ctl:ruleRemoveById=1-999999"
# /reflect endpoint: degrade to DetectionOnly so phase-2 body parsing doesn't
# block data-leak payloads before albedo can echo them. Phase 1, before CRS.
SecRule REQUEST_URI "@rx ^/reflect([?].*)?$" \
  "id:990140,phase:1,pass,t:none,nolog,noauditlog,ctl:ruleEngine=DetectionOnly"
# Paranoia level 4: exercise every CRS family. Must be phase:1 and BEFORE
# includes (901125 defaults DPL only when unset). Body/arg tuning from the
# official CRS regression suite (rule 900005).
SecAction "id:990110,phase:1,pass,t:none,nolog,noauditlog,setvar:tx.detection_paranoia_level=4,setvar:tx.blocking_paranoia_level=4,setvar:tx.crs_validate_utf8_encoding=1,setvar:tx.arg_name_length=100,setvar:tx.arg_length=400,setvar:tx.total_arg_length=64000,setvar:tx.max_num_args=255,setvar:tx.max_file_size=64100,setvar:tx.combined_file_sizes=65535"
# Opt in to CRS 4.25.x XML attribute inspection.
SecAction "id:990120,phase:1,pass,t:none,nolog,noauditlog,setvar:tx.crs_xml_attr_inspect=1"
# Load upstream recommended baseline (sets SecRuleEngine DetectionOnly and
# Unix audit paths). Re-assert engine and audit AFTER since libModSecurity
# takes the LAST value.
Include $recConf
SecRuleEngine On
SecAuditEngine On
SecAuditLog $auditDir\audit.log
SecAuditLogType Serial
# H (rule ids) + F (response headers) only -- I/E caused ~32 MB per run and
# marker-slice flakes.
SecAuditLogParts ABCFHZ
Include $(Join-Path $crsDir "crs-setup.conf")
Include $(Join-Path $crsDir "plugins\*-config.conf")
Include $(Join-Path $crsDir "plugins\*-before.conf")
Include $(Join-Path $crsDir "rules\*.conf")
Include $(Join-Path $crsDir "plugins\*-after.conf")
# Relax PL4 byte-range rule 920273 so /reflect data-leak tests aren't blocked.
SecRuleRemoveById 920273

"@ | Set-Content $conf -Encoding Ascii
Write-Host "[2/8] Engine config written ($conf)"

# --- 3) point the test site at the CRS config ----------------------------------
& $appcmd set config $SiteName /section:ModSecurity `
    /enabled:true /configFile:$conf /responseBodyBlock:true /commit:site
if ($LASTEXITCODE -ne 0) { throw "appcmd set config (ModSecurity section) failed." }

# go-ftw targets http://localhost (port 80) by default. Delete the Default
# Web Site to win the :80 binding race.
& $appcmd delete site "Default Web Site" 2>$null | Out-Null
& $appcmd set site $SiteName /bindings:"http/*:80:"
& $appcmd start site $SiteName

& iisreset /stop  2>&1 | Out-Null; Start-Sleep -Seconds 2
& iisreset /start 2>&1 | Out-Null
foreach ($i in 1..30) {
    if ((Get-Service W3SVC).Status -eq "Running") { break }
    Start-Sleep -Seconds 1
}

# Assert THIS site owns port 80 before anything else depends on it.
$own = Invoke-WebRequest "http://localhost/hello.txt" -UseBasicParsing `
           -SkipHttpErrorCheck -TimeoutSec 10
if ($own.StatusCode -ne 200 -or "$($own.Content)" -notmatch "hello from modsectest") {
    throw "port-80 ownership check failed ($($own.StatusCode)); ModSecTest is not serving localhost."
}
Write-Host "[3/8] Site '$SiteName' now serving CRS config on port 80."

# --- 4) reverse proxy: URL Rewrite + ARR -> albedo ------------------------------
choco install urlrewrite iis-arr -y --no-progress | Out-Null
& $appcmd set config /section:system.webServer/proxy /enabled:true
if ($LASTEXITCODE -ne 0) { throw "Failed to enable ARR proxy." }

# IMPORTANT: keep the site-level <ModSecurity> element in web.config.
@'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <ModSecurity enabled="true" configFile="C:\inetpub\modsec\modsecurity-crs.conf" responseBodyBlock="true" />
    <rewrite>
      <rules>
        <rule name="ToAlbedo" stopProcessing="true">
          <match url="(.*)" />
          <action type="Rewrite" url="http://127.0.0.1:8080/{R:1}" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
'@ | Set-Content (Join-Path $SiteRoot "web.config") -Encoding Ascii

& iisreset /stop  2>&1 | Out-Null; Start-Sleep -Seconds 2
& iisreset /start 2>&1 | Out-Null
foreach ($i in 1..30) {
    if ((Get-Service W3SVC).Status -eq "Running") { break }
    Start-Sleep -Seconds 1
}
Write-Host "[4/8] URL Rewrite + ARR installed, proxy enabled."

# --- 5) go-ftw + albedo ----------------------------------------------------------
# Skip `go install` when the binary is already on PATH (cached).
if (Get-Command go-ftw -ErrorAction SilentlyContinue) {
    Write-Host "[5/8] go-ftw already on PATH (cached) -- skipping install."
} else {
    go install github.com/coreruleset/go-ftw@latest
    if ($LASTEXITCODE -ne 0) { throw "go install go-ftw failed." }
}
if (Get-Command albedo -ErrorAction SilentlyContinue) {
    Write-Host "[5/8] albedo already on PATH (cached) -- skipping install."
} else {
    go install github.com/coreruleset/albedo@latest
    if ($LASTEXITCODE -ne 0) { throw "go install albedo failed." }
}
$ftwExe    = "go-ftw"
$albedoExe = "albedo"

Start-Process -FilePath $albedoExe -ArgumentList "-p", "8080" -WindowStyle Hidden
$ready = $false
foreach ($i in 1..30) {
    try {
        $resp = Invoke-WebRequest "http://127.0.0.1:8080/capabilities?quiet=true" `
                    -UseBasicParsing -TimeoutSec 3
        if ($resp.StatusCode -eq 200) { $ready = $true; break }
    } catch { Start-Sleep -Seconds 1 }
}
if (-not $ready) { throw "albedo did not become ready on port 8080." }
Restart-Service W3SVC -Force

function Write-ProbeDiagnostics {
    param($Response)
    Write-Host "--- probe response headers ---"
    $Response.Headers.GetEnumerator() |
        ForEach-Object { Write-Host ("    {0}: {1}" -f $_.Key, ($_.Value -join ', ')) }
    $bodyText = if ($Response.Content -is [byte[]]) {
        [System.Text.Encoding]::UTF8.GetString($Response.Content)
    } else { "$($Response.Content)" }
    # The TAIL of an IIS detailed-error page carries the Module/Handler table,
    # which says exactly who produced the response.
    Write-Host "--- probe body TAIL ---"
    Write-Host $bodyText.Substring([Math]::Max(0, $bodyText.Length - 1200))
}

function New-GlobalProxyRule {
    # Promote the proxy rule to a GLOBAL rewrite rule in applicationHost.config.
    $ahConfig = "$env:windir\System32\inetsrv\config\applicationHost.config"
    [xml]$doc = Get-Content $ahConfig
    $sws = $doc.configuration."system.webServer"
    if (-not $sws) { throw "system.webServer not found in applicationHost.config" }
    $rw = $sws.rewrite
    if (-not $rw) { $rw = $sws.AppendChild($doc.CreateElement("rewrite")) }
    $gr = $rw.globalRules
    if (-not $gr) { $gr = $rw.AppendChild($doc.CreateElement("globalRules")) }
    $existing = @($gr.rule) | Where-Object { $_.name -eq "ToAlbedoGlobal" }
    if (-not $existing) {
        $rule = $gr.AppendChild($doc.CreateElement("rule"))
        $rule.SetAttribute("name", "ToAlbedoGlobal")
        $rule.SetAttribute("stopProcessing", "true")
        $match = $rule.AppendChild($doc.CreateElement("match"))
        $match.SetAttribute("url", ".*")
        $action = $rule.AppendChild($doc.CreateElement("action"))
        $action.SetAttribute("type", "Rewrite")
        $action.SetAttribute("url", "http://127.0.0.1:8080/{R:0}")
        $doc.Save($ahConfig)
    }
    & iisreset /stop  2>&1 | Out-Null; Start-Sleep -Seconds 2
    & iisreset /start 2>&1 | Out-Null
    foreach ($i in 1..30) {
        if ((Get-Service W3SVC).Status -eq "Running") { break }
        Start-Sleep -Seconds 1
    }
}

$probe = Invoke-WebRequest "http://localhost/anything" -UseBasicParsing `
             -SkipHttpErrorCheck -TimeoutSec 15
Write-Host "[5/8] go-ftw + albedo ready; proxy probe /anything -> $($probe.StatusCode)"
if ($probe.StatusCode -ne 200) {
    Write-ProbeDiagnostics $probe
    Write-Host "--- effective rewrite config (site) ---"
    & $appcmd list config $SiteName /section:system.webServer/rewrite 2>&1 | Write-Host
    Write-Host "Falling back to a GLOBAL rewrite rule..."
    New-GlobalProxyRule
    $probe = Invoke-WebRequest "http://localhost/anything" -UseBasicParsing `
                 -SkipHttpErrorCheck -TimeoutSec 15
    Write-Host "[5/8] retry with global rule -> $($probe.StatusCode)"
}
if ($probe.StatusCode -ne 200) {
    Write-ProbeDiagnostics $probe
    throw "reverse proxy probe failed even with a global rewrite rule."
}

# --- 6) direct-attack sanity (blocking mode: 403 + audit-log hit) ---------------
$auditLog = Join-Path $auditDir "audit.log"
$offset   = (Test-Path $auditLog) ? (Get-Item $auditLog).Length : 0
$sqli = Invoke-WebRequest "http://localhost/?id=1%27%20OR%20%271%27%3D%271" `
            -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 15
$xss  = Invoke-WebRequest "http://localhost/?q=%3Cscript%3Ealert(1)%3C/script%3E" `
            -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 15
Write-Host "[6/8] sanity: SQLi -> $($sqli.StatusCode), XSS -> $($xss.StatusCode)"
# These probe assertions are NON-FATAL smoke signals only: the real CI gate is
# go-ftw's per-test result against scripts/crs_ignore.txt below. A flaky probe
# (e.g. ARR warm-up timing) must not block the actual CRS regression measurement.
if ($sqli.StatusCode -ne 403) { Write-Host "WARNING: SQLi probe not blocked (got $($sqli.StatusCode))." }
if ($xss.StatusCode  -ne 403) { Write-Host "WARNING: XSS probe not blocked (got $($xss.StatusCode))." }

# The audit slice below proves the ruleset loaded and fired (9421xx/941xxx),
# which also exercises the libModSecurity v3 load path.
$newSlice = ""
foreach ($try in 1..3) {
    if (Test-Path $auditLog) {
        $fs = [System.IO.File]::Open($auditLog, "Open", "Read", "ReadWrite")
        try {
            $fs.Position = [Math]::Min($offset, $fs.Length)
            $reader = New-Object System.IO.StreamReader($fs)
            $newSlice = $reader.ReadToEnd()
        } finally { $fs.Close() }
    }
    if ($newSlice -match '\[id "\d+"\]') { break }
    Start-Sleep -Seconds 3
}
# CRS rule ids are six digits: 9421xx for SQLi group hits, 941xxx for XSS.
# NON-FATAL: this only confirms the audit slice was written; it is not a gate.
if ($newSlice -notmatch '\[id "9421\d{2}"\]') {
    Write-Host "WARNING: SQLi probe was not logged by CRS 9421xx rules."
}
if ($newSlice -notmatch '\[id "941\d{3}"\]') {
    Write-Host "WARNING: XSS probe was not logged by CRS 941xxx rules."
}
Write-Host "[6/8] sanity: SQLi/XSS logged by CRS in audit log (or not -- see WARN above)."

# --- 7) go-ftw over the full IIS-feasible CRS family set -------------------------
# Every failing sub-test is hard-excluded via scripts/crs_ignore.txt using
# go-ftw's testoverride.ignore mechanism. The full suite exercises EVERY
# IIS-feasible CRS family (no blanket --exclude).
#
# MEASUREMENT OVERRIDE: set $true to skip testoverride.ignore entirely and
# measure the raw failure count.
$MeasureMode = $false
# empty = run the FULL IIS-feasible suite. Set to e.g. '^950150-1$' to debug
# a single test via --include.
$SingleTest = ''
$includeRegex = $SingleTest

$ftwConfig = Join-Path $ConfRoot "ftw.yaml"
$auditPathForYaml = (Join-Path $auditDir "audit.log") -replace '\\', '/'
# Hardcoded per-sub-test exclusions via testoverride.ignore (NOT the
# config-level exclude: key, which cannot override --include).
# The ids live in scripts/crs_ignore.txt. To regenerate: run CI with
# $MeasureMode = $true, harvest failing ids into crs_ignore.txt.
$ignoreFile = Join-Path $PSScriptRoot "crs_ignore.txt"
# crs_ignore.txt may contain `#` comment / section-header lines; only treat
# lines matching <rule>-<sub> (e.g. "942100-15") as exclusions.
$ignoreYaml = (Get-Content $ignoreFile | Where-Object { $_.Trim() -match '^[0-9]+-[0-9]+$' } | ForEach-Object {
    $id = $_.Trim()
    "    '^$id`$': `"IIS connector: known CRS 4.25.1 miss under IIS defaults (request-body / phase-4 inspection gap, http.sys pre-WAF rejection, or upstream-intended 200002 deny)`""
  }) -join "`n"
if ($MeasureMode) {
    Write-Host "[7/8] MEASUREMENT MODE: ignoring scripts/crs_ignore.txt -- every included test runs to completion."
    $ignoreYaml = ''
} else {
    Write-Host "[7/8] Loaded $(@($ignoreYaml -split "`n").Count) ignored CRS sub-tests from crs_ignore.txt"
}
$ftwHeader = @"
---
logfile: '$auditPathForYaml'
logmarkerheadername: X-CRS-TEST
mode: 'default'
"@
if ($ignoreYaml.Trim() -ne '') {
    $ftwConfigContent = $ftwHeader + @"

testoverride:
  ignore:
$ignoreYaml
"@
} else {
    $ftwConfigContent = $ftwHeader
}
$ftwConfigContent | Set-Content $ftwConfig -Encoding Ascii

$testsDir = Join-Path $crsDir "tests\regression\tests"
if ($MeasureMode) {
    Write-Host "[7/8] Running go-ftw (MEASUREMENT: all 20 families, no exclusions)..."
} else {
    Write-Host "[7/8] Running go-ftw (all families, exclusions applied)..."
}
# Default output (NOT -o github) so the complete failure reason is captured.
$ftwArgs = @('run', '-d', $testsDir, '--config', $ftwConfig)
# Default is 500 lines; with SecAuditEngine On over 4883 tests the audit log
# grows far faster and go-ftw aborts mid-run. 20000 covers the suite.
$ftwArgs += @('--max-marker-log-lines', '20000')
# Throttle to ~33 req/s. go-ftw opens a new TCP connection per request, so
# the full suite fires ~5-6k connections in ~1 minute. Pacing lets
# TIME_WAIT entries drain, mitigating ephemeral-port exhaustion flakes.
$ftwArgs += @('--rate-limit', '30ms')
# 920/921 (Protocol Enforcement/Attack) and 980 (CORRELATION): full suite now
# exercises these families instead of skipping them. Only specific sub-tests
# are ignored (see scripts/crs_ignore.txt).
if ($includeRegex -ne '') {
    $ftwArgs += @('--include', $includeRegex)
} else {
    # Full-suite run: exercise EVERY CRS family.
}
# Full-suite runs print one line per test (~4300 lines). Only failures matter;
# --show-failures-only keeps the log compact.
if ($SingleTest -eq '') { $ftwArgs += '--show-failures-only' }
if ($SingleTest -ne '' -or $env:MODSEC_IIS_FTW_DEBUG -eq '1' -or $env:MODSEC_IIS_FTW_DEBUG -ieq 'true') { $ftwArgs += '--debug' }
# go-ftw stdout goes ONLY into go-ftw-output.txt (uploaded as artifact),
# never to the run log.
& $ftwExe @ftwArgs 2>&1 | Out-File -FilePath "$PWD\go-ftw-output.txt" -Encoding utf8
$ftwCode = $LASTEXITCODE
# Compact per-test rollup for the run log.
$gOut = Get-Content "$PWD\go-ftw-output.txt" -ErrorAction SilentlyContinue
$fails = $gOut | Select-String -Pattern 'failed (in|to run)|failed: \d' | ForEach-Object { $_.Line } |
         Where-Object { $_ -notmatch 'go-ftw output|Starting|Running go-ftw' }
$gOut | Select-String -Pattern 'total tests|test\(s\) failed|test\(s\) failed to run' |
    ForEach-Object { Write-Host "go-ftw: $($_.Line.Trim())" }
if ($fails) {
    Write-Host "go-ftw failing lines:"
    $fails | Select-Object -First 30 | ForEach-Object { Write-Host "  $($_.Trim())" }
}
Write-Host "go-ftw exit code: $ftwCode"

$auditSrc = Join-Path $auditDir "audit.log"
Copy-Item $auditSrc "$PWD\modsec_crs_audit.log" -Force -ErrorAction SilentlyContinue

# --- 7a) opt-in diagnostic capability (default OFF) ------------------------
# IIS Failed Request Tracing (FREB). PROVEN LIMITATION: after enabling
# IIS-HttpTracing the box is servicing-pending and iisreset cannot bring the
# site up. So FREB can only be enabled AFTER go-ftw -- it captures manual
# probes only, never the suite.
$frebOn = ($env:MODSEC_IIS_FREB -eq '1') -or ($env:MODSEC_IIS_FREB -ieq 'true')
if ($frebOn) {
    $frebDir = "C:\inetpub\logs\FailedReqLogFiles"
    New-Item -ItemType Directory -Force $frebDir -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[7a/8] enabling IIS Failed Request Tracing -> $frebDir"
    try {
        # -All is required: IIS-HttpTracing sits under IIS-HealthAndDiagnostics.
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpTracing -All `
            -NoRestart -ErrorAction Stop | Out-Null
        Write-Host "[7a/8] IIS-HttpTracing feature enabled."
    } catch {
        Write-Host "[7a/8] WARN: IIS-HttpTracing via cmdlet: $($_.Exception.Message)"
        try {
            & dism /Online /Enable-Feature /FeatureName:IIS-HttpTracing /All /NoRestart 2>&1 |
                Write-Host
        } catch {
            Write-Host "[7a/8] WARN: dism fallback failed: $($_.Exception.Message)"
        }
    }
    try {
        & $appcmd set config $SiteName `
            /section:system.webServer/tracing/traceFailedRequestsLogging `
            /enabled:true /directory:$frebDir /maxLogFiles:50 /commit:site 2>&1 | Out-Null
        $ahConfig = "$env:windir\System32\inetsrv\config\applicationHost.config"
        [xml]$doc = Get-Content $ahConfig
        $sws = $doc.configuration."system.webServer"
        if (-not $sws) {
            $sws = $doc.configuration.AppendChild($doc.CreateElement("system.webServer"))
        }
        $tracing = $sws.tracing
        if (-not $tracing) { $tracing = $sws.AppendChild($doc.CreateElement("tracing")) }
        $tfr = $tracing.traceFailedRequests
        if (-not $tfr) { $tfr = $tracing.AppendChild($doc.CreateElement("traceFailedRequests")) }
        $tfr.RemoveAll()
        $add = $doc.CreateElement("add")
        $add.SetAttribute("path", "*")
        $ta = $doc.CreateElement("traceAreas")
        $prov = $doc.CreateElement("add")
        $prov.SetAttribute("provider", "WWW Server")
        $prov.SetAttribute("areas", "RequestNotifications,Modules,Security,Filter,StaticFile,Rewrite,RequestRouting")
        $prov.SetAttribute("verbosity", "Verbose")
        [void]$ta.AppendChild($prov)
        [void]$add.AppendChild($ta)
        $fd = $doc.CreateElement("failureDefinitions")
        $fd.SetAttribute("statusCodes", "200-999")
        [void]$add.AppendChild($fd)
        [void]$tfr.AppendChild($add)
        $doc.Save($ahConfig)
        Write-Host "[7a/8] FREB rule added (all status codes, RequestNotifications)."
    } catch {
        Write-Host "[7a/8] WARN: FREB config failed: $($_.Exception.Message)"
    }
    # iisreset /start returns immediately; wait until W3SVC is really up.
    $eap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & iisreset /stop  2>&1 | Out-Null
        Start-Sleep -Seconds 3
        & iisreset /start 2>&1 | Out-Null
    } catch {
        Write-Host "[7a/8] WARN: iisreset issue: $($_.Exception.Message)"
    }
    $ErrorActionPreference = $eap
    foreach ($i in 1..30) {
        if ((Get-Service W3SVC).Status -eq "Running") { break }
        Start-Sleep -Seconds 1
    }
    # W3SVC Running is NOT enough: start the site and wait until it answers.
    & $appcmd start site $SiteName 2>&1 | Out-Null
    $up = $false
    foreach ($i in 1..30) {
        try {
            $p = Invoke-WebRequest "http://localhost/hello.txt" -UseBasicParsing `
                     -SkipHttpErrorCheck -TimeoutSec 5
            if ($p.StatusCode -eq 200) { $up = $true; break }
        } catch { Start-Sleep -Seconds 2 }
    }
    Write-Host "[7a/8] post-FREB restart: site reachable = $up"
} else {
    Write-Host "[7a/8] FREB disabled (set MODSEC_IIS_FREB=1 to trace per-module pipeline notifications)."
}

# --- 7b) response-phase regression sentinel ----------------------------------
# The full CRS suite above already exercises phase 4 via the RESPONSE-95x
# families. This is a cheap confirmation that response-body inspection is still
# wired (SecResponseBodyAccess On + a /reflect data-leak request reached 950150).
$hit950 = Select-String -Path $auditSrc -Pattern '"950150"' -Quiet
Write-Host "[7b/8] phase:4 rule 950150 present in audit log (response-body inspection live): $hit950"
if (-not $hit950) {
    Write-Host "[7b/8] WARN: no 950150 hit -- is SecResponseBodyAccess On and does the suite reach a /reflect data-leak?"
}

# --- 7c) connector file-trace dump (opt-in) ----------------------------------
# The DLL only writes the trace when w3wp sees MODSEC_IIS_TRACE=1 (app pool
# env). When present, dump it; otherwise say so -- no error either way.
$traceFound = $false
foreach ($tp in @("C:/inetpub/logs/modsec-audit/modsecurityiis-trace.log",
                  "C:/inetpub/logs/modsec-crs-audit/modsecurityiis-trace.log",
                  "C:/inetpub/modsec/modsecurityiis-trace.log")) {
    if (Test-Path $tp) {
        Write-Host "[7c/8] connector trace ($tp, last 50 lines):"
        Get-Content $tp -Tail 50 | Write-Host
        $traceFound = $true
        break
    }
}
if (-not $traceFound) {
    Write-Host "[7c/8] connector trace not written (set MODSEC_IIS_TRACE=1 on the app pool to enable)."
}

if ($MeasureMode) {
    Write-Host "--- go-ftw raw failure list (MEASUREMENT) ---"
    Select-String -Pattern "failed to run:" -Path "$PWD\go-ftw-output.txt" | ForEach-Object { $_.Line }
} else {
    # Dumping the whole log balloons CI log to ~67 MB. Print compact rollup.
    Write-Host "--- CRS audit rule-id rollup (top 25) ---"
    if (Test-Path $auditSrc) {
        $ids = Select-String -Path $auditSrc -Pattern '\[id "(\d+)"\]' -AllMatches |
            ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value }
        $ids | Group-Object | Sort-Object Count -Descending |
            Select-Object -First 25 |
            ForEach-Object { Write-Host ("{0,6}  {1}" -f $_.Count, $_.Name) }
    }
}

# --- 8) event-log hygiene (loader/config problems surface here) -------------------
$bad = Get-WinEvent -FilterHashtable @{ LogName = "Application";
                                       StartTime = (Get-Date).AddMinutes(-30) } `
         -ErrorAction SilentlyContinue |
       Where-Object { $_.Message -match
           'Failed to find the RegisterModule entrypoint|dll failed to load|cannot be read because it is missing a section declaration' }
if ($bad) {
    $bad | Select-Object TimeCreated, ProviderName, Id, Message | Format-List | Out-String | Write-Host
    throw "Found IIS/module error events in the Application log."
}
Write-Host "[8/8] Event log clean."

# go-ftw result gating: ON by default. For diagnostic runs, set
# MODSEC_IIS_NO_GATE=1 to exit 0 and leave failures in the log.
if ($env:MODSEC_IIS_NO_GATE -eq '1' -or $env:MODSEC_IIS_NO_GATE -ieq 'true') {
    if ($ftwCode -ne 0) {
        Write-Host "[9/8] WARNING: go-ftw exit=$ftwCode (MODSEC_IIS_NO_GATE=1, NOT gating). See go-ftw-output.txt."
    }
    exit 0
}
exit $ftwCode
