# IIS smoke test for ModSecurityIIS.
# Flow: ensure IIS -> install the module (from an MSI, or use an existing
# install) -> write config -> create app pool/site -> assert A-F + P behaviors.

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
$failures = New-Object System.Collections.Generic.List[string]

function Assert-True([object]$Cond, [string]$Name, [string]$Detail = "") {
    if ($Cond) { Write-Host "PASS $name" -ForegroundColor Green }
    else {
        Write-Host "FAIL $Name :: $Detail" -ForegroundColor Red
        $script:failures.Add("$Name :: $Detail")
    }
}

# --- 0) preconditions ---------------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Must run elevated."
}

# --- 1) ensure IIS ------------------------------------------------------------
$features = Get-WindowsFeature Web-Static-Content, Web-Default-Doc, `
                               Web-Http-Errors, Web-Filtering -ErrorAction SilentlyContinue
if ($features | Where-Object { -not $_.Installed }) {
    Write-Host "Installing missing IIS features..."
    Install-WindowsFeature Web-Static-Content, Web-Default-Doc, `
                           Web-Http-Errors, Web-Filtering | Out-Null
}
if ((Get-Service W3SVC).Status -ne "Running") { Start-Service W3SVC }
$appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
Write-Host "[1/5] IIS ready."

if ($Msi) {
    if (-not (Test-Path $Msi)) { throw "MSI not found: $Msi" }
    $log = Join-Path (Get-Location).Path "msi-install.log"
    Write-Host "== Installing $Msi =="
    $p = Start-Process msiexec.exe -Wait -PassThru `
         -ArgumentList @("/i", (Resolve-Path $Msi).Path, "/qn", "/norestart", "/l*v", $log)
    Assert-True ($p.ExitCode -eq 0) "MSI installed" "msiexec exit=$($p.ExitCode) (log: $log)"
}

$inetsrv = "$env:windir\System32\inetsrv"

# --- 2) module registration ---------------------------------------------------
# The MSI (or a previous install) owns the DLLs, schema and event source; the
# only thing left to check here is that IIS really has the native module.
& $appcmd list modules /name:ModSecurityIIS
Assert-True (& $appcmd list modules /name:ModSecurityIIS | Select-String "ModSecurityIIS" -Quiet) `
            "native module registered" `
            "appcmd list modules came back empty -- install the MSI first"

# Schema files under inetsrv\config\schema require a full IIS config stack
# reload (iisreset).
function Restart-IisConfigStack {
    & iisreset /stop 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    & iisreset /start 2>&1 | Out-Null
    # iisreset /start returns immediately; wait until W3SVC is really up.
    foreach ($i in 1..30) {
        if ((Get-Service W3SVC).Status -eq "Running") { break }
        Start-Sleep -Seconds 1
    }
}
Restart-IisConfigStack

# Diagnostics: prove schema file location and section visibility.
Write-Host "== schema file =="
Get-Item "$env:windir\System32\inetsrv\config\schema\ModSecurity.xml" |
    Format-Table FullName, Length, LastWriteTime

& $appcmd list config /section:system.webServer/ModSecurity 2>&1 | Write-Host
$declared = ($LASTEXITCODE -eq 0)
if (-not $declared) {
    Write-Warning "Schema still invisible after iisreset; declaring the section in applicationHost.config directly."
    $ahConfig = "$env:windir\System32\inetsrv\config\applicationHost.config"
    Copy-Item $ahConfig "$ahConfig.bak-modsec" -Force
    [xml]$doc = Get-Content $ahConfig
    $sg = @($doc.configuration.configSections.sectionGroup) |
          Where-Object { $_.name -eq "system.webServer" }
    if (-not $sg) { throw "sectionGroup 'system.webServer' not found in applicationHost.config" }
    if (-not (@($sg.section) | Where-Object { $_.name -eq "ModSecurity" })) {
        $sec = $doc.CreateElement("section")
        $sec.SetAttribute("name", "ModSecurity")
        $sec.SetAttribute("overrideModeDefault", "Allow")
        $sec.SetAttribute("allowLocation", "false")
        [void]$sg.AppendChild($sec)
        $doc.Save($ahConfig)
    }
    Restart-IisConfigStack
    & $appcmd list config /section:system.webServer/ModSecurity 2>&1 | Write-Host
    $declared = ($LASTEXITCODE -eq 0)
}
Assert-True $declared "schema/section visible to config system" `
            "system.webServer/ModSecurity still undeclared after restarts"
Write-Host "[2/5] Module registered, config stack restarted for schema."

# --- 3) engine config + rules --------------------------------------------------
New-Item -ItemType Directory -Force $ConfRoot | Out-Null
New-Item -ItemType Directory -Force (Join-Path $ConfRoot "data") | Out-Null
New-Item -ItemType Directory -Force "C:\inetpub\logs\modsec-audit" | Out-Null
# GeoIP2 database directory. Directive only emitted when .mmdb exists.
New-Item -ItemType Directory -Force "C:\inetpub\modsec\GeoIP" | Out-Null
$geoDb   = "C:\inetpub\modsec\GeoIP\GeoIP2-Country.mmdb"
$geoLine = if (Test-Path $geoDb) {
    "SecGeoLookupDB $geoDb"
} else {
    "# SecGeoLookupDB $geoDb   (drop a MaxMind GeoIP2 database here to enable @geoLookup / GEO rules)"
}

$modsecConf = @"
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
# Full auditing during smoke runs to verify engine received the body.
SecAuditEngine RelevantOnly
SecAuditLog C:\inetpub\logs\modsec-audit\audit.log
SecAuditLogType Serial
SecTmpDir C:\inetpub\modsec\data
SecDataDir C:\inetpub\modsec\data
$geoLine
Include C:\inetpub\modsec\rules.conf
"@
Set-Content (Join-Path $ConfRoot "modsecurity.conf") $modsecConf -Encoding Ascii

$rules = @"
SecRule REQUEST_HEADERS:User-Agent "@streq modsec-test-block" "id:1001,phase:1,deny,status:403,msg:'smoke: blocked user-agent'"
SecRule ARGS:evil "@rx <script>" "id:1002,phase:2,deny,status:403,msg:'smoke: blocked request body'"
# Non-disruptive probe: libModSecurity only routes NON-disruptive matches to
# the server-log callback (rule 1003 -> Event Viewer path).
SecRule REQUEST_HEADERS:X-ModSec-Probe "@streq logme" "id:1003,phase:1,pass,log,msg:'smoke: non-disruptive probe'"
# Body-completeness probe helper (non-disruptive): matches the probe body so
# the transaction is audited under SecAuditEngine RelevantOnly.
SecRule REQUEST_BODY "@rx bodyprobe" "id:1010,phase:2,pass,t:none,log,msg:'probe: request body completeness'"
"@
Set-Content (Join-Path $ConfRoot "rules.conf") $rules -Encoding Ascii
Write-Host "[3/5] Engine configuration written."

# --- 4) site -------------------------------------------------------------------
New-Item -ItemType Directory -Force $SiteRoot | Out-Null
Set-Content (Join-Path $SiteRoot "hello.txt") "hello from modsectest" -Encoding Ascii

& $appcmd delete site    $SiteName 2>$null | Out-Null
& $appcmd delete apppool $PoolName 2>$null | Out-Null
& $appcmd add apppool /name:$PoolName
& $appcmd set apppool $PoolName /processModel.loadUserProfile:false

# The pool's virtual account (IIS AppPool\<name>) only resolves to a SID
# after the pool exists, so grants must come after "add apppool".
$poolId = "IIS AppPool\$PoolName"
icacls "C:\inetpub\logs\modsec-audit" /grant "${poolId}:(OI)(CI)M" | Out-Null
icacls "$ConfRoot\data"               /grant "${poolId}:(OI)(CI)M" | Out-Null
icacls "C:\inetpub\modsec\GeoIP"      /grant "${poolId}:(OI)(CI)R" | Out-Null

& $appcmd add site /name:$SiteName /physicalPath:$SiteRoot /bindings:"http/*:$($Port):"
& $appcmd set app "$SiteName/" /applicationPool:$PoolName

# Enable ModSecurity for this site; retry a few times in case the schema
# reload races us even after the service restart.
$sectionOk = $false
foreach ($try in 1..5) {
    $out = & $appcmd set config $SiteName /section:ModSecurity `
        /enabled:true /configFile:"C:\inetpub\modsec\modsecurity.conf" /commit:site 2>&1
    if ($LASTEXITCODE -eq 0) { $sectionOk = $true; break }
    Write-Warning "set config attempt $try failed: $out"
    Start-Sleep -Seconds 3
}
Assert-True $sectionOk "ModSecurity section configured" "appcmd kept rejecting the section"
& $appcmd start site $SiteName
& $appcmd list sites
Write-Host "[4/5] Site '$SiteName' listening on 127.0.0.1:$Port"

# --- 5) functional assertions ---------------------------------------------------
New-Item -ItemType Directory -Force "$ConfRoot\diag" | Out-Null
$curl = "$env:windir\System32\curl.exe"
$script:diagN = 0
function Invoke-Case([string]$Name, [string[]]$CurlArgs) {
    $script:diagN++
    $out = "$ConfRoot\diag\case-$($script:diagN)-$($Name -replace '[^A-Za-z0-9]+','-').txt"
    # Save status line + headers + first 2 KiB of body for post-mortem.
    $code = & $curl @CurlArgs -s -D "$out.headers" -o "$out.body" `
                -w "%{http_code}" 2>$null
    "--- STATUS: $code ---" | Add-Content $out
    Get-Content "$out.headers" -ErrorAction SilentlyContinue | Select-Object -First 25 | Add-Content $out
    "--- BODY (first 2048 bytes) ---" | Add-Content $out
    Get-Content "$out.body" -Raw -ErrorAction SilentlyContinue |
        ForEach-Object { $_.Substring(0, [Math]::Min(2048, $_.Length)) } | Add-Content $out
    # Console: status + response headers only.
    Write-Host "== $Name => HTTP $code =="
    Get-Content "$out.headers" -ErrorAction SilentlyContinue |
        Select-Object -First 12 | ForEach-Object { Write-Host "   $_" }
    return @{ Name = $Name; Status = [int]($code ?? "0") }
}

$cA = Invoke-Case "A pass-through GET" @(
    "-H","User-Agent: normal-client","http://127.0.0.1:$Port/hello.txt")
$cB = Invoke-Case "B phase-1 header block" @(
    "-H","User-Agent: modsec-test-block","http://127.0.0.1:$Port/hello.txt")
$cC = Invoke-Case "C phase-2 body block" @(
    "-X","POST","-H","Content-Type: application/x-www-form-urlencoded",
    "--data","evil=<script>alert(1)</script>","http://127.0.0.1:$Port/")
$cD = Invoke-Case "D benign POST passes to handler" @(
    "-X","POST","-H","Content-Type: text/plain","--data","hello",
    "http://127.0.0.1:$Port/hello.txt")
# Exercises the non-disruptive server-log path (rule 1003 -> Event Viewer).
$cP = Invoke-Case "P non-disruptive log probe" @(
    "-H","X-ModSec-Probe: logme","http://127.0.0.1:$Port/hello.txt")

Assert-True ($cA.Status -eq 200) $cA.Name "expected 200, got $($cA.Status)"
Assert-True ($cB.Status -eq 403) $cB.Name "expected 403, got $($cB.Status)"
Assert-True ($cC.Status -eq 403) $cC.Name "expected 403, got $($cC.Status)"
Assert-True ($cD.Status -eq 405) $cD.Name ("expected 405 (static handler verb rejection," +
    " proves no false positive), got $($cD.Status)")
Assert-True ($cP.Status -eq 200) $cP.Name "expected 200, got $($cP.Status)"

Start-Sleep -Seconds 2   # give the audit writer a moment
$audit = "C:\inetpub\logs\modsec-audit\audit.log"
$auditOk = (Test-Path $audit) -and ((Get-Item $audit).Length -gt 0)
Assert-True $auditOk "E audit log written" "$audit missing or empty"
if ($auditOk) {
    $hits = Select-String -Path $audit -Pattern '"100[12]"' -Quiet
    Assert-True $hits "E audit log contains rules 1001/1002" "no id entries found"
}

# --- 6b) request-body completeness probe -------------------------------------
# Does the FULL entity body reach the audit log (part C)? Body is larger than
# the loop's 64 KiB buffer and uploaded slowly via --limit-rate.
$probePad    = 100000
$probeBody   = "bodyprobe=1&pad=" + ("Z" * $probePad)
$bodyFile    = Join-Path $ConfRoot "bodyprobe-request.txt"
$probeOut    = Join-Path $ConfRoot "body-completeness.txt"
Set-Content -Path $bodyFile -Value $probeBody -NoNewline -Encoding ascii

$auditOff = if (Test-Path $audit) { (Get-Item $audit).Length } else { 0 }
$probeResp = Join-Path $ConfRoot "bodyprobe-response.bin"
$probeCode = & $curl -s -o $probeResp -w "%{http_code}" --limit-rate 10k `
                 -X POST -H "Content-Type: application/x-www-form-urlencoded" `
                 --data-binary "@$bodyFile" "http://127.0.0.1:$Port/" 2>$null
Start-Sleep -Seconds 3   # let the audit writer flush

$slice = $null
if (Test-Path $audit) {
    $fs = [System.IO.File]::Open($audit, "Open", "Read", "ReadWrite")
    try {
        $fs.Position = [Math]::Min($auditOff, $fs.Length)
        $slice = (New-Object System.IO.StreamReader($fs)).ReadToEnd()
    } finally { $fs.Close() }
}
# Audit part C = request body. Section headers are "--<unique-id>-<letter>--",
# so part C is "--<id>-C--" .. next section's "--".
$cBody = $null
if ($slice -match '(?sm)^-+[A-Za-z0-9]+-+C--\r?\n(.*?)\r?\n-+[A-Za-z0-9]+-+[A-Z]--') {
    $cBody = $Matches[1]
}
$cLen   = if ($cBody) { $cBody.Length } else { 0 }
$cZeros = if ($cBody) { ([regex]::Matches($cBody, "Z")).Count } else { 0 }
$expected = $probeBody.Length
$verdict  = if ($cZeros -ge $probePad) { "COMPLETE" } `
            else { "TRUNCATED (missing $($probePad - $cZeros) of $probePad pad bytes)" }
$line = ("body-completeness: probe HTTP $probeCode | body sent=$expected B " +
         "| audit part C=$cLen B | pad 'Z' seen=$cZeros / $probePad -> $verdict")
Write-Host "[6b] $line"
$line | Set-Content $probeOut -Encoding Ascii
("expected body bytes: $expected") | Add-Content $probeOut -Encoding Ascii
if ($cBody) {
    ("part C head: " + $cBody.Substring(0, [Math]::Min(120, $cBody.Length))) |
        Add-Content $probeOut -Encoding Ascii
    ("part C tail: " + $cBody.Substring([Math]::Max(0, $cBody.Length - 80))) |
        Add-Content $probeOut -Encoding Ascii
}

try {
    $evts = Get-WinEvent -FilterHashtable @{
                LogName = "Application"; ProviderName = "ModSecurity";
                StartTime = (Get-Date).AddMinutes(-10) } -ErrorAction Stop
    Assert-True ($evts.Count -gt 0) "F event-log entries via server-log callback" `
                "provider 'ModSecurity' returned no events"
} catch {
    Assert-True $false "F event-log entries via server-log callback" $_.Exception.Message
}


Write-Host ""
if ($failures.Count -gt 0) {
    Write-Host "== SMOKE TEST FAILED ($($failures.Count)) ==" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host " - $_" }
    exit 1
}
Write-Host "== SMOKE TEST PASSED ==" -ForegroundColor Green
