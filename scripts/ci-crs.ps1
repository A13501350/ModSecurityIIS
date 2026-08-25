# CRS regression stage for ModSecurityIIS. Runs AFTER ci-smoke.ps1 in the
# same job, so the module is already deployed and the site/app pool exist.
#
# Mirrors the v2 connector's approach:
#   OWASP CRS -> modsecurity.conf includes -> IIS site proxies every request
#   to albedo (CRS echo backend) via URL Rewrite + ARR -> go-ftw replays the
#   official CRS regression tests and asserts status codes + audit-log hits.
#
# Differences vs the v2 flow:
#   * we AUTHOR a v3-style modsecurity.conf ourselves (no DetectionOnly swap),
#   * schema/section bootstrap is already done by the smoke stage,
#   * the test site moves to port 80 (Default Web Site stopped) because
#     go-ftw targets http://localhost by default,
#   * a curated --include regex keeps the runtime tight and avoids rule
#     groups that depend on engine facilities IIS+v3 cannot provide
#     (response-body outbound rules, persistent collections, GEO).

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DllDir,   # unused here; kept for symmetry/logging
    [string]$CrsVersion = "v4.18.0",
    [string]$ConfRoot   = "C:\inetpub\modsec",
    [string]$SiteRoot   = "C:\inetpub\modsectest",
    [string]$SiteName   = "ModSecTest",
    [string]$PoolName   = "ModSecTestPool",
    [string]$GoBin      = ""
)

$ErrorActionPreference = "Stop"

# --- 0) preconditions ---------------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Must run elevated."
}
$appcmd  = "$env:windir\System32\inetsrv\appcmd.exe"

# go toolchain ships with the runner image.
if (-not $GoBin) {
    $GoBin = if ($env:GOPATH) { Join-Path $env:GOPATH "bin" } else { Join-Path $env:USERPROFILE "go\bin" }
}

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

# Engine configuration required by the regression suite
# (tests/regression/README.md): PL4, test-tuned limits, remove the anomaly-
# score enforcement rule, and flip every transaction into DetectionOnly --
# tests assert audit-log rule hits, not HTTP blocking.
Add-Content (Join-Path $crsDir "crs-setup.conf") @'
SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.blocking_paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.max_file_size=64100,\
  setvar:tx.combined_file_sizes=65535"
'@
Write-Host "[1/8] CRS unpacked to $crsDir (test setup injected)"

# --- 2) engine configuration ----------------------------------------------------
$auditDir = "C:\inetpub\logs\modsec-crs-audit"
New-Item -ItemType Directory -Force $auditDir          | Out-Null
New-Item -ItemType Directory -Force "$ConfRoot\data"   | Out-Null
# Pool identity needs write access for audit/tmp files (pool exists since the
# smoke stage created it).
$poolId = "IIS AppPool\$PoolName"
icacls $auditDir         /grant "${poolId}:(OI)(CI)M" | Out-Null
icacls "$ConfRoot\data"  /grant "${poolId}:(OI)(CI)M" | Out-Null

$conf = Join-Path $ConfRoot "modsecurity-crs.conf"
@"
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
# Audit EVERYTHING (not RelevantOnly): go-ftw locates test boundaries via
# X-CRS-Test marker requests that end in 200 -- under RelevantOnly those are
# never audited and the runner cannot find its markers. Rule alerts (with
# ids) land in the audit H part of every entry, which is what go-ftw greps.
SecAuditEngine On
SecAuditLog $auditDir\audit.log
SecAuditLogType Serial
SecTmpDir $ConfRoot\data
SecDataDir $ConfRoot\data
# Log marker required by go-ftw outside the CRS docker images (see go-ftw
# README, "How log parsing works"): echoes the X-CRS-Test UUID into the log
# and disables ALL other rules for marker requests. Loaded BEFORE the CRS
# includes so it fires first in phase 1 and the removal takes effect before
# any CRS rule runs -- otherwise PL4 matches would pollute no_expect_ids.
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
  "id:999999,\
  pass,\
  phase:1,\
  log,\
  msg:'X-CRS-Test %{MATCHED_VAR}',\
  ctl:ruleRemoveById=1-999999"
Include $(Join-Path $crsDir "crs-setup.conf")
Include $(Join-Path $crsDir "plugins\*-config.conf")
Include $(Join-Path $crsDir "plugins\*-before.conf")
Include $(Join-Path $crsDir "rules\*.conf")
Include $(Join-Path $crsDir "plugins\*-after.conf")
"@ | Set-Content $conf -Encoding Ascii
Write-Host "[2/8] Engine config written ($conf)"

# --- 3) point the test site at the CRS config ----------------------------------
& $appcmd set config $SiteName /section:ModSecurity `
    /enabled:true /configFile:$conf /commit:site
if ($LASTEXITCODE -ne 0) { throw "appcmd set config (ModSecurity section) failed." }

# go-ftw targets http://localhost (port 80) by default: free the port and
# rebind the test site.
& $appcmd stop site "Default Web Site" 2>$null | Out-Null
& $appcmd set site $SiteName /bindings:"http/*:80:"
& $appcmd start site $SiteName

& iisreset /stop  2>&1 | Out-Null; Start-Sleep -Seconds 2
& iisreset /start 2>&1 | Out-Null
foreach ($i in 1..30) {
    if ((Get-Service W3SVC).Status -eq "Running") { break }
    Start-Sleep -Seconds 1
}
Write-Host "[3/8] Site '$SiteName' now serving CRS config on port 80."

# --- 4) reverse proxy: URL Rewrite + ARR -> albedo ------------------------------
choco install urlrewrite iis-arr -y --no-progress | Out-Null
& $appcmd set config /section:system.webServer/proxy /enabled:true
if ($LASTEXITCODE -ne 0) { throw "Failed to enable ARR proxy." }

@'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
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
go install github.com/coreruleset/go-ftw@latest
if ($LASTEXITCODE -ne 0) { throw "go install go-ftw failed." }
go install github.com/coreruleset/albedo@latest
if ($LASTEXITCODE -ne 0) { throw "go install albedo failed." }
$ftwExe    = Join-Path $GoBin "go-ftw.exe"
$albedoExe = Join-Path $GoBin "albedo.exe"
foreach ($exe in $ftwExe, $albedoExe) {
    if (-not (Test-Path $exe)) { throw "expected binary missing: $exe" }
}

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

# End-to-end probe through WAF -> proxy -> albedo. NOTE: albedo answers 200
# (empty body) for ANY unmatched URL, so any non-200 here means the request
# never reached albedo -- dump everything needed to localize where it died.
$probe = Invoke-WebRequest "http://localhost/anything" -UseBasicParsing `
             -SkipHttpErrorCheck -TimeoutSec 15
Write-Host "[5/8] go-ftw + albedo ready; proxy probe /anything -> $($probe.StatusCode)"
if ($probe.StatusCode -ne 200) {
    Write-Host "--- probe response headers ---"
    $probe.Headers.GetEnumerator() |
        ForEach-Object { Write-Host ("    {0}: {1}" -f $_.Key, ($_.Value -join ', ')) }
    Write-Host "--- probe body (first 1 KiB) ---"
    $bodyText = if ($probe.Content -is [byte[]]) {
        [System.Text.Encoding]::UTF8.GetString($probe.Content)
    } else { "$($probe.Content)" }
    Write-Host $bodyText.Substring(0, [Math]::Min(1024, $bodyText.Length))
    Write-Host "--- rewrite/proxy modules registered ---"
    & $appcmd list modules | Select-String -Pattern "Rewrite|Proxy|ARR" |
        ForEach-Object { Write-Host "    $_" }
    Write-Host "--- site web.config ---"
    Get-Content (Join-Path $SiteRoot "web.config") | Write-Host
    Write-Host "--- direct albedo GET /anything status ---"
    try {
        (Invoke-WebRequest "http://127.0.0.1:8080/anything" -UseBasicParsing `
            -TimeoutSec 5).StatusCode
    } catch { Write-Host "    direct albedo failed: $($_.Exception.Message)" }
    throw "reverse proxy probe failed."
}

# --- 6) direct-attack sanity (DetectionOnly contract: 200 + audit-log hit) ------
# The suite runs with ctl:ruleEngine=DetectionOnly, so probes must be LOGGED
# but NOT blocked. Assert both halves, per tests/regression/README.md.
$auditLog = Join-Path $auditDir "audit.log"
$offset   = (Test-Path $auditLog) ? (Get-Item $auditLog).Length : 0
$sqli = Invoke-WebRequest "http://localhost/?id=1%27%20OR%20%271%27%3D%271" `
            -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 15
$xss  = Invoke-WebRequest "http://localhost/?q=%3Cscript%3Ealert(1)%3C/script%3E" `
            -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 15
Write-Host "[6/8] sanity: SQLi -> $($sqli.StatusCode), XSS -> $($xss.StatusCode)"
if ($sqli.StatusCode -ne 200) { throw "SQLi probe should pass through in DetectionOnly (got $($sqli.StatusCode))." }
if ($xss.StatusCode  -ne 200) { throw "XSS probe should pass through in DetectionOnly (got $($xss.StatusCode))." }

$newSlice = ""
if (Test-Path $auditLog) {
    $fs = [System.IO.File]::Open($auditLog, "Open", "Read", "ReadWrite")
    try {
        $fs.Position = [Math]::Min($offset, $fs.Length)
        $reader = New-Object System.IO.StreamReader($fs)
        $newSlice = $reader.ReadToEnd()
    } finally { $fs.Close() }
}
if ($newSlice -notmatch '\[id "9421\d\d"\]') {
    throw "SQLi probe was not logged by CRS 9421xx rules (DetectionOnly audit check failed)."
}
if ($newSlice -notmatch '\[id "941\d\d"\]') {
    throw "XSS probe was not logged by CRS 941xxx rules (DetectionOnly audit check failed)."
}
Write-Host "[6/8] sanity: SQLi/XSS logged by CRS in audit log."

# --- 7) go-ftw over a representative CRS subset ----------------------------------
# One file per rule group entry point keeps runtime bounded while covering
# every major category: method enforcement (911), protocol (920/921),
# LFI (930), RFI (931), RCE (932), PHP/XSS (933), SSRF (934), scanning (935),
# generic XSS (941), SQLi (942), session fixation (943).
$includeRegex = '^(911100|920100|920120|920160|920200|920210|920250|920280|920300|920320|920340|920350|920360|920420|920440|920480|921110|921130|921150|921160|930100|930110|930120|931100|932100|932105|932150|933100|933110|933131|933160|934100|935100|941100|941110|941160|941190|942100|942110|942140|942260|942360|943100|943110)\.yaml$'

$ftwConfig = Join-Path $ConfRoot "ftw.yaml"
$auditPathForYaml = (Join-Path $auditDir "audit.log") -replace '\\', '/'
@"
---
logfile: '$auditPathForYaml'
logmarkerheadername: X-CRS-TEST
mode: 'default'
"@ | Set-Content $ftwConfig -Encoding Ascii

$testsDir = Join-Path $crsDir "tests\regression\tests"
Write-Host "[7/8] Running go-ftw (representative subset)..."
& $ftwExe run -d $testsDir --include $includeRegex `
    --config $ftwConfig --show-failures-only 2>&1 |
    Tee-Object -FilePath "$PWD\go-ftw-output.txt"
$ftwCode = $LASTEXITCODE
Write-Host "go-ftw exit code: $ftwCode"

$auditSrc = Join-Path $auditDir "audit.log"
Copy-Item $auditSrc "$PWD\modsec_crs_audit.log" -Force -ErrorAction SilentlyContinue
Write-Host "--- TAIL OF AUDIT LOG AFTER go-ftw ---"
Get-Content $auditSrc -Tail 30 -ErrorAction SilentlyContinue

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
exit $ftwCode
