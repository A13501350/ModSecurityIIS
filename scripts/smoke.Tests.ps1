# Pester v5 integration smoke test for ModSecurityIIS.
#
# Replaces the old handwritten Assert-True + $failures accumulator in
# scripts/ci-smoke.ps1. Run it via the launcher (keeps the -Msi contract):
#     ./scripts/ci-smoke.ps1 -Msi <path-to.msi>
# or directly:
#     $env:MODSEC_IIS_SMOKE_MSI = 'foo.msi'
#     Invoke-Pester -Path scripts/smoke.Tests.ps1 -Output Detailed
#
# The test installs (optionally) the MSI, wires a site that loads the engine
# with a few hand-written rules, and asserts phase-1/phase-2 blocking,
# pass-through, audit-log writes, request-body completeness and the
# server-log -> Event Viewer callback. It deliberately does NOT run the CRS
# suite (that is the slower, flakier L2 layer in scripts/ci-crs.ps1).
#
# NO SHELLING OUT TO appcmd.exe: IIS is driven through Microsoft.Web.Administration
# (the API appcmd itself sits on). Plain HTTP cases go through Invoke-WebRequest
# (pwsh 7, -SkipHttpErrorCheck). The ONE exception is the 6b body-completeness
# probe, which keeps curl.exe --limit-rate 10k: Invoke-WebRequest has no rate
# limiting, and the slow upload is what exercises the engine's async body-read
# path. iisreset / icacls / msiexec also remain.
#
# PESTER SCOPING (pester.dev/docs/usage/setup-and-teardown): only BeforeAll
# runs in the Run phase -- a .Tests.ps1 file's top-level code executes during
# DISCOVERY only, and Describe-body statements are not visible to BeforeAll/It.
# Everything the tests need (shared paths, helper functions) is therefore
# defined inside BeforeAll: "All variables defined in BeforeAll are available
# to all child blocks and tests."

param(
    # The launcher (ci-smoke.ps1) passes the MSI path via $env:MODSEC_IIS_SMOKE_MSI
    # because Invoke-Pester -Path cannot forward script arguments. Empty = test an
    # already-installed module.
    [string]$Msi = ($env:MODSEC_IIS_SMOKE_MSI ?? ""),
    [string]$SiteRoot  = "C:\inetpub\modsectest",
    [string]$ConfRoot  = "C:\inetpub\modsec",
    [int]   $Port      = 18080,
    [string]$SiteName  = "ModSecTest",
    [string]$PoolName  = "ModSecTestPool"
)

Describe "ModSecurityIIS smoke (L1 integration)" {

    BeforeAll {
        $ErrorActionPreference = "Stop"

        $curl  = "$env:windir\System32\curl.exe"
        $audit = "C:\inetpub\logs\modsec-audit\audit.log"

        # Helper functions are defined here, inside BeforeAll, so they exist in
        # the Run phase and are visible to every It block (Pester v5 docs:
        # import/dot-source helpers in BeforeAll).

        # --- Microsoft.Web.Administration ------------------------------------
        # The API under appcmd.exe. pwsh 7 does not probe the GAC, so load the
        # copy IIS ships in inetsrv; fall back to the IISAdministration module.
        if (-not ("Microsoft.Web.Administration.ServerManager" -as [type])) {
            $mwaDll = "$env:windir\System32\inetsrv\Microsoft.Web.Administration.dll"
            if (Test-Path $mwaDll) {
                Add-Type -Path $mwaDll
            } else {
                Import-Module IISAdministration -SkipEditionCheck -ErrorAction Stop
                if (-not ("Microsoft.Web.Administration.ServerManager" -as [type])) {
                    throw "Microsoft.Web.Administration could not be loaded."
                }
            }
        }

        function New-ServerManager {
            [Microsoft.Web.Administration.ServerManager]::new()
        }

        # Set attributes on the site-level ModSecurity section. This is the
        # equivalent of `appcmd set config <site> /section:ModSecurity ... /commit:site`:
        # the write lands in the site's own web.config.
        function Set-SiteModSecConfig([string]$Site, [hashtable]$Attrs) {
            $sm = New-ServerManager
            try {
                $webCfg = $sm.GetWebConfiguration($Site)
                $sec = $webCfg.GetSection("system.webServer/ModSecurity")
                if (-not $sec) {
                    throw "section system.webServer/ModSecurity not found in web config for site '$Site'"
                }
                foreach ($k in $Attrs.Keys) {
                    # ConfigurationElement's string indexer does not bind
                    # reliably from PowerShell (returns null -> cryptic
                    # "property 'Value' cannot be found"), so go through the
                    # explicit GetAttribute API.
                    $attr = $sec.GetAttribute($k)
                    if (-not $attr) {
                        throw "attribute '$k' missing from the ModSecurity section schema"
                    }
                    $attr.Value = $Attrs[$k]
                }
                $sm.CommitChanges()
            } finally { $sm.Dispose() }
        }

        # Reload the IIS configuration stack so a freshly installed schema file
        # under inetsrv\config\schema becomes visible to the config system.
        function Restart-IisConfigStack {
            & iisreset /stop 2>&1 | Out-Null
            Start-Sleep -Seconds 2
            & iisreset /start 2>&1 | Out-Null
            foreach ($i in 1..30) {
                if ((Get-Service W3SVC).Status -eq "Running") { break }
                Start-Sleep -Seconds 1
            }
        }

        # Send one request via Invoke-WebRequest (curl.exe replacement), persist
        # a short post-mortem, and return its status code.
        function Invoke-Case([string]$Name, [hashtable]$Req) {
            $out = "$ConfRoot\diag\case-$($Name -replace '[^A-Za-z0-9]+','-').txt"
            $params = @{
                Uri                = $Req["Uri"]
                Method             = $Req["Method"]
                SkipHttpErrorCheck = $true   # pwsh 7: keep 4xx/5xx as a response
                TimeoutSec         = 60
            }
            $headers = $Req["Headers"]
            if ($headers -and $headers["User-Agent"]) {
                # Set via the dedicated parameter (safe on every PS edition).
                $params.UserAgent = $headers["User-Agent"]
                $rest = @{}
                foreach ($k in $headers.Keys) {
                    if ($k -ne "User-Agent") { $rest[$k] = $headers[$k] }
                }
                $headers = $rest
            }
            if ($headers -and $headers.Count) { $params.Headers = $headers }
            if ($Req["Body"]) {
                $params.Body = $Req["Body"]
                if ($Req["ContentType"]) { $params.ContentType = $Req["ContentType"] }
            }
            $resp = Invoke-WebRequest @params
            $code = [int]$resp.StatusCode

            "--- STATUS: $code ---" | Add-Content $out
            $resp.Headers.GetEnumerator() | Select-Object -First 25 |
                ForEach-Object { "{0}: {1}" -f $_.Key, ($_.Value -join ", ") } | Add-Content $out
            "--- BODY (first 2048 bytes) ---" | Add-Content $out
            $body = "$($resp.Content)"
            $body.Substring(0, [Math]::Min(2048, $body.Length)) | Add-Content $out
            Write-Host "== $Name => HTTP $code =="
            $resp.Headers.GetEnumerator() | Select-Object -First 12 |
                ForEach-Object { Write-Host ("   {0}: {1}" -f $_.Key, ($_.Value -join ", ")) }
            return @{ Name = $Name; Status = $code }
        }

        $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "Must run elevated."
        }

        # --- 1) ensure IIS --------------------------------------------------
        $features = Get-WindowsFeature Web-Static-Content, Web-Default-Doc, `
                                       Web-Http-Errors, Web-Filtering -ErrorAction SilentlyContinue
        if ($features | Where-Object { -not $_.Installed }) {
            Write-Host "Installing missing IIS features..."
            Install-WindowsFeature Web-Static-Content, Web-Default-Doc, `
                                   Web-Http-Errors, Web-Filtering | Out-Null
        }
        if ((Get-Service W3SVC).Status -ne "Running") { Start-Service W3SVC }

        # --- 1b) install the MSI (optional) --------------------------------
        if ($Msi) {
            if (-not (Test-Path $Msi)) { throw "MSI not found: $Msi" }
            $log = Join-Path (Get-Location).Path "msi-install.log"
            Write-Host "== Installing $Msi =="
            $p = Start-Process msiexec.exe -Wait -PassThru `
                 -ArgumentList @("/i", (Resolve-Path $Msi).Path, "/qn", "/norestart", "/l*v", $log)
            if ($p.ExitCode -ne 0) { throw "msiexec failed (exit=$($p.ExitCode)); log: $log" }
        }

        # Schema files under inetsrv\config\schema need a full config-stack
        # reload before the ModSecurity section becomes visible.
        Restart-IisConfigStack

        # --- 2) engine config + rules --------------------------------------
        New-Item -ItemType Directory -Force $ConfRoot | Out-Null
        New-Item -ItemType Directory -Force (Join-Path $ConfRoot "data") | Out-Null
        New-Item -ItemType Directory -Force "C:\inetpub\logs\modsec-audit" | Out-Null
        New-Item -ItemType Directory -Force "C:\inetpub\modsec\GeoIP" | Out-Null
        New-Item -ItemType Directory -Force "$ConfRoot\diag" | Out-Null
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

        # --- 3) site (via Microsoft.Web.Administration) ---------------------
        New-Item -ItemType Directory -Force $SiteRoot | Out-Null
        Set-Content (Join-Path $SiteRoot "hello.txt") "hello from modsectest" -Encoding Ascii

        $sm = New-ServerManager
        try {
            $oldSite = $sm.Sites[$SiteName]
            if ($oldSite) { $sm.Sites.Remove($oldSite) }
            $oldPool = $sm.ApplicationPools[$PoolName]
            if ($oldPool) { $sm.ApplicationPools.Remove($oldPool) }

            $pool = $sm.ApplicationPools.Add($PoolName)
            $pool.ProcessModel.LoadUserProfile = $false

            # Use the (siteName, port, physicalPath, protocol) overload: the
            # string-bindingInformation overload is ambiguous for PowerShell's
            # binder (it tries to convert the path to int port).
            $site = $sm.Sites.Add($SiteName, $Port, $SiteRoot, "http")
            $site.Applications["/"].ApplicationPoolName = $PoolName
            $sm.CommitChanges()
        } finally { $sm.Dispose() }

        # The pool's virtual account (IIS AppPool\<name>) only resolves to a SID
        # after the pool exists, so grants must come after the commit above.
        $poolId = "IIS AppPool\$PoolName"
        icacls "C:\inetpub\logs\modsec-audit" /grant "${poolId}:(OI)(CI)M" | Out-Null
        icacls "$ConfRoot\data"               /grant "${poolId}:(OI)(CI)M" | Out-Null
        icacls "C:\inetpub\modsec\GeoIP"      /grant "${poolId}:(OI)(CI)R" | Out-Null

        # Enable ModSecurity for the site; retry in case the schema reload from
        # step 1 races us (same reasoning as the appcmd retries it replaces).
        $sectionOk = $false
        foreach ($try in 1..5) {
            try {
                Set-SiteModSecConfig $SiteName @{
                    enabled    = $true
                    configFile = "C:\inetpub\modsec\modsecurity.conf"
                }
                $sectionOk = $true
                break
            } catch {
                Write-Warning "set config attempt $try failed: $($_.Exception.Message)"
                Restart-IisConfigStack
            }
        }
        if (-not $sectionOk) {
            throw "ModSecurity section could not be configured for site '$SiteName'."
        }

        $sm = New-ServerManager
        try {
            $sm.Sites[$SiteName].Start()
            $sm.Sites | Select-Object Name, State | Format-Table -AutoSize | Out-String | Write-Host
        } finally { $sm.Dispose() }
    }

    It "native module registered by install" {
        # appcmd list modules equivalent: the module must appear in the
        # applicationHost.config collections that make it a native IIS module.
        $sm = New-ServerManager
        try {
            $ah = $sm.GetApplicationHostConfiguration()
            $inModules = @($ah.GetSection("system.webServer/modules").GetCollection() |
                Where-Object { "$($_["name"])" -eq "ModSecurityIIS" }).Count -gt 0
            $inGlobals = @($ah.GetSection("system.webServer/globalModules").GetCollection() |
                Where-Object { "$($_["name"])" -eq "ModSecurityIIS" }).Count -gt 0
            ($inModules -or $inGlobals) | Should -BeTrue
        } finally { $sm.Dispose() }
    }

    It "schema/section visible to config system" {
        # appcmd list config /section:... equivalent: the config system can
        # resolve the section, which proves the schema is loaded.
        $sm = New-ServerManager
        try {
            $ah = $sm.GetApplicationHostConfiguration()
            { $null = $ah.GetSection("system.webServer/ModSecurity") } | Should -Not -Throw
        } finally { $sm.Dispose() }
    }

    It "A pass-through GET returns 200" {
        $cA = Invoke-Case "A pass-through GET" @{
            Uri     = "http://127.0.0.1:$Port/hello.txt"
            Method  = "GET"
            Headers = @{ "User-Agent" = "normal-client" }
        }
        $cA.Status | Should -Be 200
    }

    It "B phase-1 header rule blocks with 403" {
        $cB = Invoke-Case "B phase-1 header block" @{
            Uri     = "http://127.0.0.1:$Port/hello.txt"
            Method  = "GET"
            Headers = @{ "User-Agent" = "modsec-test-block" }
        }
        $cB.Status | Should -Be 403
    }

    It "C phase-2 request-body rule blocks with 403" {
        $cC = Invoke-Case "C phase-2 body block" @{
            Uri         = "http://127.0.0.1:$Port/"
            Method      = "POST"
            Body        = "evil=<script>alert(1)</script>"
            ContentType = "application/x-www-form-urlencoded"
        }
        $cC.Status | Should -Be 403
    }

    It "D benign POST is not a false positive (405 from static handler)" {
        $cD = Invoke-Case "D benign POST passes to handler" @{
            Uri         = "http://127.0.0.1:$Port/hello.txt"
            Method      = "POST"
            Body        = "hello"
            ContentType = "text/plain"
        }
        # 405 proves the request reached the static-file handler untouched.
        $cD.Status | Should -Be 405
    }

    It "P non-disruptive log probe returns 200" {
        $cP = Invoke-Case "P non-disruptive log probe" @{
            Uri     = "http://127.0.0.1:$Port/hello.txt"
            Method  = "GET"
            Headers = @{ "X-ModSec-Probe" = "logme" }
        }
        $cP.Status | Should -Be 200
    }

    It "E audit log written and contains rules 1001/1002" {
        $auditOk = (Test-Path $audit) -and ((Get-Item $audit).Length -gt 0)
        $auditOk | Should -BeTrue
        if ($auditOk) {
            $hits = Select-String -Path $audit -Pattern '"100[12]"' -Quiet
            $hits | Should -BeTrue
        }
    }

    It "6b request body reaches the audit log intact (no truncation)" {
        $probePad  = 100000
        $probeBody = "bodyprobe=1&pad=" + ("Z" * $probePad)
        $bodyFile  = Join-Path $ConfRoot "bodyprobe-request.txt"
        Set-Content -Path $bodyFile -Value $probeBody -NoNewline -Encoding ascii

        $auditOff = if (Test-Path $audit) { (Get-Item $audit).Length } else { 0 }
        # curl --limit-rate keeps the slow upload that exercises the engine's
        # async body-read path (Invoke-WebRequest has no rate limiting).
        $probeCode = & $curl -s -o "$ConfRoot\bodyprobe-response.bin" -w "%{http_code}" --limit-rate 10k `
                 -X POST -H "Content-Type: application/x-www-form-urlencoded" `
                 --data-binary "@$bodyFile" "http://127.0.0.1:$Port/" 2>$null
        Write-Host "[6b] throttled POST => HTTP $probeCode"
        Start-Sleep -Seconds 3   # let the audit writer flush

        $slice = $null
        if (Test-Path $audit) {
            $fs = [System.IO.File]::Open($audit, "Open", "Read", "ReadWrite")
            try {
                $fs.Position = [Math]::Min($auditOff, $fs.Length)
                $slice = (New-Object System.IO.StreamReader($fs)).ReadToEnd()
            } finally { $fs.Close() }
        }
        $cBody = $null
        if ($slice -match '(?sm)^-+[A-Za-z0-9]+-+C--\r?\n(.*?)\r?\n-+[A-Za-z0-9]+-+[A-Z]--') {
            $cBody = $Matches[1]
        }
        $cZeros   = if ($cBody) { ([regex]::Matches($cBody, "Z")).Count } else { 0 }
        $verdict  = if ($cZeros -ge $probePad) { "COMPLETE" } `
                    else { "TRUNCATED (missing $($probePad - $cZeros) of $probePad pad bytes)" }
        Write-Host "[6b] body-completeness verdict: $verdict"
        $verdict | Should -Be "COMPLETE"
    }

    It "F server-log callback wrote ModSecurity event-log entries" {
        try {
            $evts = Get-WinEvent -FilterHashtable @{
                        LogName = "Application"; ProviderName = "ModSecurity";
                        StartTime = (Get-Date).AddMinutes(-10) } -ErrorAction Stop
            ($evts.Count -gt 0) | Should -BeTrue
        } catch {
            throw "no ModSecurity event-log entries via server-log callback: $($_.Exception.Message)"
        }
    }
}
