# IIS smoke test for ModSecurityIIS, designed for ephemeral CI machines
# (GitHub Actions windows-latest = Windows Server with admin rights).
#
# Flow: ensure IIS -> stage engine dependency DLLs (dumpbin-driven) ->
# deploy the module -> write a minimal modsecurity.conf + rules -> create
# an app pool/site on 127.0.0.1:18080 -> assert behavior:
#
#   A  GET  normal UA               -> 200  (pass-through works)
#   B  GET  UA "modsec-test-block"  -> 403  (phase 1 header rule)
#   C  POST evil=<script>...        -> 403  (phase 2 request-body rule)
#   D  POST benign body             -> 405  (no false positive; handler rejects verb)
#   E  audit log contains rule ids 1001/1002
#   F  Application event log has "ModSecurity" entries (server-log callback)
#   P  GET  X-ModSec-Probe: logme    -> 200  (non-disruptive server-log path)
#
# Any failed assertion exits non-zero.

[CmdletBinding()]
param(
    # Directory holding modsecurityiis.dll + libModSecurity.dll (the build
    # artifact).
    [Parameter(Mandatory = $true)][string]$DllDir,

    [string]$SiteRoot  = "C:\inetpub\modsectest",
    [string]$ConfRoot  = "C:\inetpub\modsec",
    [int]   $Port      = 18080,
    [string]$SiteName  = "ModSecTest",
    [string]$PoolName  = "ModSecTestPool"
)

$ErrorActionPreference = "Stop"
$failures = New-Object System.Collections.Generic.List[string]

function Assert-True([bool]$Cond, [string]$Name, [string]$Detail = "") {
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
$dll    = Join-Path $DllDir "modsecurityiis.dll"
$engine = Join-Path $DllDir "libModSecurity.dll"
foreach ($f in @($dll, $engine)) {
    if (-not (Test-Path $f)) { throw "Missing artifact file: $f" }
}
Write-Host "== Artifacts found =="
Get-ChildItem $DllDir | Format-Table Name, Length

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
Write-Host "[1/6] IIS ready."

# --- 2) stage engine dependency DLLs ------------------------------------------
# libModSecurity is built via Conan; ConanCenter Windows packages are static
# by default, but if any dynamic dependency crept in, w3wp would fail to load
# it. Locate every non-system import we can find and place it next to the
# engine DLL.
$inetsrv = "$env:windir\System32\inetsrv"
$depsOutput = & dumpbin /dependents $engine 2>&1 | Out-String
Write-Host "== dumpbin /dependents libModSecurity.dll =="; Write-Host $depsOutput

# Stage the dynamic VC++ runtime the engine links against (/MD). Without
# this, resolution relies on the VS toolchain being on PATH -- true on the
# runner, not necessarily on a clean deployment host. VS versions name the
# redist folder differently (Microsoft.VC143.CRT / VC144...), so search it;
# fall back to the OS copies in System32.
$crtNames = "msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll"
$crtSrcDirs = @()
if ($env:VCToolsRedistDir) {
    $crtSrcDirs += Get-ChildItem (Join-Path $env:VCToolsRedistDir "x64") -Directory `
                    -Filter "Microsoft.VC*.CRT" -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty FullName
}
foreach ($c in $crtNames) {
    $src = $crtSrcDirs | ForEach-Object { Join-Path $_ $c } |
           Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $src) { $src = Join-Path $env:windir "System32\$c" }
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $inetsrv $c) -Force
    } else {
        Write-Warning "VC runtime $c not found anywhere"
    }
}

$systemDeps = @("kernel32", "user32", "advapi32", "ws2_32", "ws2_64", `
                "iphlpapi", "bcrypt", "crypt32", "msvcrt", "ucrtbase", `
                "vcruntime140", "vcruntime140_1", "msvcp140", "ntdll", `
                "ole32", "shell32")
$missing = @()
foreach ($m in [regex]::Matches($depsOutput, "(?im)^\s*(\S+\.dll)\s*$")) {
    $dep  = $m.Groups[1].Value
    $base = ($dep -replace "\.dll$", "")
    # api-ms-win-crt-* are UCRT API Sets: virtual, always resolvable by the
    # OS loader, and with no physical file under System32.
    if ($base -like "api-ms-win-crt*") { continue }
    if ($systemDeps -contains $base) { continue }
    if (-not (Test-Path (Join-Path $env:windir "System32\$dep"))) { $missing += $dep.ToLower() }
}
foreach ($dep in $missing) {
    Write-Host "Staging dynamic dependency: $dep"
    $roots = @("$env:USERPROFILE\.conan2", "$env:GITHUB_WORKSPACE\build") |
             Where-Object { $_ -and (Test-Path $_) }
    $found = if ($roots) {
        Get-ChildItem $roots -Recurse -Filter $dep `
            -ErrorAction SilentlyContinue | Select-Object -First 1
    } else { $null }
    if ($found) {
        Copy-Item $found.FullName $inetsrv -Force
        Write-Host "  copied from $($found.FullName)"
    } else {
        Write-Warning "Dependency $dep not found anywhere -- module load may fail."
    }
}
Copy-Item $dll    $inetsrv -Force
Copy-Item $engine $inetsrv -Force
Write-Host "[2/6] DLLs staged in $inetsrv"

# --- 3) schema + event source + module registration ---------------------------
& "$PSScriptRoot\deploy-modsecurityiis.ps1" -DllDir $DllDir -InstallDir $inetsrv
Assert-True ($LASTEXITCODE -eq 0) "deploy script succeeded" "exit=$LASTEXITCODE"
& $appcmd list modules /name:ModSecurityIIS
Assert-True (& $appcmd list modules /name:ModSecurityIIS | Select-String "ModSecurityIIS" -Quiet) `
            "native module registered" "appcmd list modules came back empty"

# Schema files under inetsrv\config\schema are only picked up when the whole
# IIS configuration stack reloads -- WAS/W3SVC alone is not enough, the
# watcher lives in IISADMIN (this mirrors iisreset).
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

# Diagnostics: prove the schema file is where we put it and whether the
# config system now knows the section.
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
Write-Host "[3/6] Module registered, config stack restarted for schema."

# --- 4) engine config + rules --------------------------------------------------
New-Item -ItemType Directory -Force $ConfRoot | Out-Null
New-Item -ItemType Directory -Force (Join-Path $ConfRoot "data") | Out-Null
New-Item -ItemType Directory -Force "C:\inetpub\logs\modsec-audit" | Out-Null

$modsecConf = @"
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
# Full auditing during smoke runs: lets us verify in the uploaded artifacts
# whether the engine actually received the request body for phase-2 rules.
SecAuditEngine RelevantOnly
SecAuditLog C:\inetpub\logs\modsec-audit\audit.log
SecAuditLogType Serial
SecTmpDir C:\inetpub\modsec\data
SecDataDir C:\inetpub\modsec\data
Include C:\inetpub\modsec\rules.conf
"@
Set-Content (Join-Path $ConfRoot "modsecurity.conf") $modsecConf -Encoding Ascii

$rules = @"
SecRule REQUEST_HEADERS:User-Agent "@streq modsec-test-block" "id:1001,phase:1,deny,status:403,msg:'smoke: blocked user-agent'"
SecRule ARGS:evil "@rx <script>" "id:1002,phase:2,deny,status:403,msg:'smoke: blocked request body'"
# Non-disruptive probe: libModSecurity only routes NON-disruptive matches to
# the server-log callback (rule_with_actions.cc gates every serverLog call on
# !m_isDisruptive); deny rules surface through the audit log instead. Rule
# 1003 exists precisely to exercise the callback -> Event Viewer path.
SecRule REQUEST_HEADERS:X-ModSec-Probe "@streq logme" "id:1003,phase:1,pass,log,msg:'smoke: non-disruptive probe'"
"@
Set-Content (Join-Path $ConfRoot "rules.conf") $rules -Encoding Ascii
Write-Host "[4/6] Engine configuration written."

# --- 5) site -------------------------------------------------------------------
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
Write-Host "[5/6] Site '$SiteName' listening on 127.0.0.1:$Port"

# --- 6) functional assertions ---------------------------------------------------
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
    # Console: status + response headers only (full details are uploaded as
    # job artifacts; echoing whole HTML error pages floods the CI log).
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
# Exercises the non-disruptive server-log path (rule 1003 -> callback ->
# Event Viewer); response is a plain 200.
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
