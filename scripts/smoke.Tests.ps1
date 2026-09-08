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

# Helpers and shared state are defined INSIDE the Describe block (see below) so
# they exist during Pester's run phase -- a .Tests.ps1 file's top-level code
# only runs during discovery, so file-scope functions vanish when It/BeforeAll run.

Describe "ModSecurityIIS smoke (L1 integration)" {

    $ErrorActionPreference = "Stop"

    $script:appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
    $script:curl   = "$env:windir\System32\curl.exe"
    $script:audit  = "C:\inetpub\logs\modsec-audit\audit.log"
    $script:diagN  = 0

    # Send one request, persist a short post-mortem, and return its status code.
    function Invoke-Case([string]$Name, [string[]]$CurlArgs) {
        $script:diagN++
        $out = "$ConfRoot\diag\case-$($script:diagN)-$($Name -replace '[^A-Za-z0-9]+','-').txt"
        $code = & $script:curl @CurlArgs -s -D "$out.headers" -o "$out.body" `
                    -w "%{http_code}" 2>$null
        "--- STATUS: $code ---" | Add-Content $out
        Get-Content "$out.headers" -ErrorAction SilentlyContinue | Select-Object -First 25 | Add-Content $out
        "--- BODY (first 2048 bytes) ---" | Add-Content $out
        Get-Content "$out.body" -Raw -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Substring(0, [Math]::Min(2048, $_.Length)) } | Add-Content $out
        Write-Host "== $Name => HTTP $code =="
        Get-Content "$out.headers" -ErrorAction SilentlyContinue |
            Select-Object -First 12 | ForEach-Object { Write-Host "   $_" }
        return @{ Name = $Name; Status = [int]($code ?? "0") }
    }

    function Restart-IisConfigStack {
        & iisreset /stop 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        & iisreset /start 2>&1 | Out-Null
        foreach ($i in 1..30) {
            if ((Get-Service W3SVC).Status -eq "Running") { break }
            Start-Sleep -Seconds 1
        }
    }

    BeforeAll {
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

        # --- 4) site -------------------------------------------------------
        New-Item -ItemType Directory -Force $SiteRoot | Out-Null
        Set-Content (Join-Path $SiteRoot "hello.txt") "hello from modsectest" -Encoding Ascii

        & $script:appcmd delete site    $SiteName 2>$null | Out-Null
        & $script:appcmd delete apppool $PoolName 2>$null | Out-Null
        & $script:appcmd add apppool /name:$PoolName
        & $script:appcmd set apppool $PoolName /processModel.loadUserProfile:false

        $poolId = "IIS AppPool\$PoolName"
        icacls "C:\inetpub\logs\modsec-audit" /grant "${poolId}:(OI)(CI)M" | Out-Null
        icacls "$ConfRoot\data"               /grant "${poolId}:(OI)(CI)M" | Out-Null
        icacls "C:\inetpub\modsec\GeoIP"      /grant "${poolId}:(OI)(CI)R" | Out-Null

        & $script:appcmd add site /name:$SiteName /physicalPath:$SiteRoot /bindings:"http/*:$($Port):"
        & $script:appcmd set app "$SiteName/" /applicationPool:$PoolName

        $sectionOk = $false
        foreach ($try in 1..5) {
            $out = & $script:appcmd set config $SiteName /section:ModSecurity `
                /enabled:true /configFile:"C:\inetpub\modsec\modsecurity.conf" /commit:site 2>&1
            if ($LASTEXITCODE -eq 0) { $sectionOk = $true; break }
            Write-Warning "set config attempt $try failed: $out"
            Start-Sleep -Seconds 3
        }
        if (-not $sectionOk) {
            throw "ModSecurity section could not be configured for site '$SiteName'."
        }
        & $script:appcmd start site $SiteName
        & $script:appcmd list sites
    }

    It "native module registered by install" {
        $out = & $script:appcmd list modules /name:ModSecurityIIS 2>&1 | Out-String
        $out | Should -Match "ModSecurityIIS"
    }

    It "schema/section visible to config system" {
        & $script:appcmd list config /section:system.webServer/ModSecurity 2>&1 | Out-Null
        $LASTEXITCODE | Should -Be 0
    }

    It "A pass-through GET returns 200" {
        $cA = Invoke-Case "A pass-through GET" @(
            "-H","User-Agent: normal-client","http://127.0.0.1:$Port/hello.txt")
        $cA.Status | Should -Be 200
    }

    It "B phase-1 header rule blocks with 403" {
        $cB = Invoke-Case "B phase-1 header block" @(
            "-H","User-Agent: modsec-test-block","http://127.0.0.1:$Port/hello.txt")
        $cB.Status | Should -Be 403
    }

    It "C phase-2 request-body rule blocks with 403" {
        $cC = Invoke-Case "C phase-2 body block" @(
            "-X","POST","-H","Content-Type: application/x-www-form-urlencoded",
            "--data","evil=<script>alert(1)</script>","http://127.0.0.1:$Port/")
        $cC.Status | Should -Be 403
    }

    It "D benign POST is not a false positive (405 from static handler)" {
        $cD = Invoke-Case "D benign POST passes to handler" @(
            "-X","POST","-H","Content-Type: text/plain","--data","hello",
            "http://127.0.0.1:$Port/hello.txt")
        # 405 proves the request reached the static-file handler untouched.
        $cD.Status | Should -Be 405
    }

    It "P non-disruptive log probe returns 200" {
        $cP = Invoke-Case "P non-disruptive log probe" @(
            "-H","X-ModSec-Probe: logme","http://127.0.0.1:$Port/hello.txt")
        $cP.Status | Should -Be 200
    }

    It "E audit log written and contains rules 1001/1002" {
        $auditOk = (Test-Path $script:audit) -and ((Get-Item $script:audit).Length -gt 0)
        $auditOk | Should -BeTrue
        if ($auditOk) {
            $hits = Select-String -Path $script:audit -Pattern '"100[12]"' -Quiet
            $hits | Should -BeTrue
        }
    }

    It "6b request body reaches the audit log intact (no truncation)" {
        $probePad  = 100000
        $probeBody = "bodyprobe=1&pad=" + ("Z" * $probePad)
        $bodyFile  = Join-Path $ConfRoot "bodyprobe-request.txt"
        Set-Content -Path $bodyFile -Value $probeBody -NoNewline -Encoding ascii

        $auditOff = if (Test-Path $script:audit) { (Get-Item $script:audit).Length } else { 0 }
        & $script:curl -s -o "$ConfRoot\bodyprobe-response.bin" -w "%{http_code}" --limit-rate 10k `
                 -X POST -H "Content-Type: application/x-www-form-urlencoded" `
                 --data-binary "@$bodyFile" "http://127.0.0.1:$Port/" 2>$null
        Start-Sleep -Seconds 3   # let the audit writer flush

        $slice = $null
        if (Test-Path $script:audit) {
            $fs = [System.IO.File]::Open($script:audit, "Open", "Read", "ReadWrite")
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
