# IIS plumbing for the v2-vs-v3 connector benchmark.
#
# Everything here is arm-agnostic: it sets up one site that reverse proxies to a
# local backend, and installs/uninstalls whichever ModSecurity IIS module the
# caller asks for. v2 and v3 both ship a DLL called modsecurityiis.dll and both
# read the same `system.webServer/ModSecurity` section, so they can never be
# installed at the same time -- Install-Arm therefore always uninstalls first.

$script:AppCmd  = "$env:windir\System32\inetsrv\appcmd.exe"
$script:AhConfig = "$env:windir\System32\inetsrv\config\applicationHost.config"
$script:Inetsrv  = "$env:windir\System32\inetsrv"
$script:SiteName = "BenchSite"
$script:PoolName = "BenchPool"
$script:SiteRoot = "C:\bench\www"
$script:BenchDir = "C:\bench"

function Assert-True {
    param([bool]$Ok, [string]$What)
    if (-not $Ok) { throw "ASSERT FAILED: $What" }
    Write-Host "  PASS: $What"
}

# ---------------------------------------------------------------------------
# Site + reverse proxy
# ---------------------------------------------------------------------------

# The origin must accept POST, which the IIS static handler does not (it
# answers 405), so the site proxies to a real backend over ARR -- the same
# topology scripts/ci-crs.ps1 uses with albedo.
function Initialize-BenchSite {
    param([string]$BackendUrl = "http://127.0.0.1:8080")

    Write-Host "== Setting up $script:SiteName -> $BackendUrl"

    choco install urlrewrite iis-arr -y --no-progress | Out-Null
    & $script:AppCmd set config /section:system.webServer/proxy /enabled:true | Out-Null

    New-Item -ItemType Directory -Force -Path $script:SiteRoot | Out-Null
    New-Item -ItemType Directory -Force -Path "$script:BenchDir\tmp" | Out-Null
    New-Item -ItemType Directory -Force -Path "$script:BenchDir\data" | Out-Null

    # Port 80 is owned by the stock "Default Web Site".
    & $script:AppCmd delete site "Default Web Site" 2>$null | Out-Null

    if (-not (& $script:AppCmd list site $script:SiteName 2>$null)) {
        & $script:AppCmd add site /name:$script:SiteName `
            /physicalPath:$script:SiteRoot "/bindings:http/*:80:" | Out-Null
    }
    if (-not (& $script:AppCmd list apppool $script:PoolName 2>$null)) {
        & $script:AppCmd add apppool /name:$script:PoolName | Out-Null
    }
    & $script:AppCmd set site $script:SiteName "/[path='/'].applicationPool:$script:PoolName" | Out-Null
    # One worker process so the perf counters have exactly one instance.
    & $script:AppCmd set apppool $script:PoolName /processModel.maxProcesses:1 | Out-Null
    & $script:AppCmd set apppool $script:PoolName /processModel.idleTimeout:00:00:00 | Out-Null

    $webConfig = Join-Path $script:SiteRoot "web.config"
    @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="BenchProxy" stopProcessing="true">
          <match url="(.*)" />
          <action type="Rewrite" url="$BackendUrl/{R:1}" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
"@ | Set-Content $webConfig -Encoding Ascii

    Restart-IIS

    # Declare the config section once, here, with IIS stopped. Per-arm switches
    # must not touch applicationHost.config (see Initialize-ModSecuritySection).
    Initialize-ModSecuritySection
}

function Restart-IIS {
    & iisreset /restart | Out-Null
    Start-Sleep -Seconds 3
}

# ---------------------------------------------------------------------------
# applicationHost.config section declaration -- ONCE, and only with IIS stopped
#
# The schema file alone is not enough: appcmd refuses to set a section that is
# not declared. Both connectors read system.webServer/ModSecurity, so the
# declaration is arm-independent and is made exactly once.
#
# It used to be added and removed on every arm switch, which raced IIS:
# applicationHost.config is owned by the configuration system, and rewriting it
# directly while WAS holds it fails with "The process cannot access the file
# ... because it is being used by another process". That is what killed the run
# right after the v2 arm (baseline and v2 happened to get away with it). Every
# per-arm change now goes through appcmd / AHADMIN, which serialises access
# properly, so the hand-written file edit happens at most once per job.
# ---------------------------------------------------------------------------

function Initialize-ModSecuritySection {
    & iisreset /stop | Out-Null
    for ($i = 0; $i -lt 30; $i++) {
        if ((Get-Service W3SVC -ErrorAction SilentlyContinue).Status -eq "Stopped") { break }
        Start-Sleep -Seconds 1
    }

    $declared = $false
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            [xml]$xml = Get-Content $script:AhConfig
            $group = $xml.configuration.configSections.sectionGroup |
                     Where-Object { $_.name -eq "system.webServer" } |
                     Select-Object -First 1
            if (-not $group) { throw "system.webServer sectionGroup not found" }

            if ($group.section | Where-Object { $_.name -eq "ModSecurity" }) {
                Write-Host "  system.webServer/ModSecurity already declared"
            } else {
                $sec = $xml.CreateElement("section")
                $sec.SetAttribute("name", "ModSecurity")
                $sec.SetAttribute("overrideModeDefault", "Allow")
                $sec.SetAttribute("allowDefinition", "Everywhere")
                [void]$group.AppendChild($sec)
                $xml.Save($script:AhConfig)
                Write-Host "  declared system.webServer/ModSecurity"
            }
            $declared = $true
            break
        } catch {
            Write-Host "  declaration attempt $attempt failed: $_"
            Start-Sleep -Seconds 2
        }
    }

    & iisreset /start | Out-Null
    for ($i = 0; $i -lt 60; $i++) {
        if ((Get-Service W3SVC -ErrorAction SilentlyContinue).Status -eq "Running") { break }
        Start-Sleep -Seconds 1
    }

    if (-not $declared) { throw "could not declare the system.webServer/ModSecurity section" }
}

# ---------------------------------------------------------------------------
# Arm install / uninstall
# ---------------------------------------------------------------------------

function Uninstall-Arm {
    # Disable through appcmd (AHADMIN), then unregister the module and drop the
    # binaries. The section DECLARATION is permanent for the job, so nothing
    # here writes applicationHost.config -- see Initialize-ModSecuritySection.
    # All appcmd work happens before the services are stopped, because appcmd
    # talks to WAS.
    & $script:AppCmd set config -section:system.webServer/ModSecurity `
        /enabled:false /commit:apphost 2>$null | Out-Null
    & $script:AppCmd uninstall module "ModSecurityIIS" 2>$null | Out-Null

    Stop-Service W3SVC -Force -ErrorAction SilentlyContinue
    Stop-Service WAS   -Force -ErrorAction SilentlyContinue

    Remove-Item "$script:Inetsrv\modsecurityiis.dll" -Force -ErrorAction SilentlyContinue
    Remove-Item "$script:Inetsrv\libModSecurity.dll" -Force -ErrorAction SilentlyContinue
    Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\ModSecurity" `
        -Recurse -Force -ErrorAction SilentlyContinue
}

# Installs one connector. $DllDir must contain modsecurityiis.dll; for v3 it
# must also contain libModSecurity.dll. $ConfigFile is the ModSecurity config
# the connector is pointed at.
function Install-Arm {
    param(
        [Parameter(Mandatory)][ValidateSet("baseline", "v2", "v3")][string]$Arm,
        [string]$DllDir,
        [string]$ConfigFile
    )

    Uninstall-Arm

    if ($Arm -eq "baseline") {
        Restart-IIS
        Write-Host "== arm 'baseline': no WAF module installed"
        return
    }

    Assert-True (Test-Path (Join-Path $DllDir "modsecurityiis.dll")) "connector DLL present for $Arm"

    # Copy every runtime DLL we were given -- the connector plus its engine and
    # vcpkg/Conan dependencies. w3wp resolves imports from its own directory,
    # so they all have to sit next to each other in inetsrv.
    Get-ChildItem $DllDir -Filter *.dll | Copy-Item -Destination $script:Inetsrv -Force

    $schemaSrc = if ($Arm -eq "v3") { "ModSecurity.xml" } else { Join-Path $DllDir "ModSecurity.xml" }
    if (-not (Test-Path $schemaSrc)) {
        # v2 keeps its schema at iis/ModSecurity.xml; fall back to ours, which
        # is a superset (v3 adds responseBodyBlock). v2 ignores unknown
        # attributes, but prefers its own when available.
        $schemaSrc = "ModSecurity.xml"
    }
    Copy-Item $schemaSrc "$script:Inetsrv\config\schema\ModSecurity.xml" -Force

    # Without this key the Event Viewer cannot render anything the DLL reports.
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\ModSecurity" -Force | Out-Null
    New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\ModSecurity" `
        -Name EventMessageFile -Value "$script:Inetsrv\modsecurityiis.dll" -Force | Out-Null
    New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\ModSecurity" `
        -Name TypesSupported -Value 7 -PropertyType DWord -Force | Out-Null

    & $script:AppCmd install module /name:ModSecurityIIS `
        /image:"$script:Inetsrv\modsecurityiis.dll" /add:true | Out-Null

    Restart-IIS

    & $script:AppCmd set config -section:system.webServer/ModSecurity `
        /enabled:true /configFile:"$ConfigFile" /commit:apphost | Out-Null

    Restart-IIS

    Assert-True ([bool](& $script:AppCmd list modules /name:ModSecurityIIS 2>$null |
                        Select-String "ModSecurityIIS" -Quiet)) "module registered ($Arm)"

    # A module that fails to load leaves a marker in the event log; catch it
    # here rather than measuring a site that is not actually protected.
    $bad = Get-EventLog -LogName Application -Newest 50 -ErrorAction SilentlyContinue |
           Where-Object { $_.Message -match 'dll failed to load|RegisterModule entrypoint' }
    Assert-True (-not $bad) "module loaded cleanly ($Arm)"
}

# Dumps everything the modules might have said into diag/ for the artifact.
# The connectors log through a host hook -- on IIS that is the Windows Event
# Log under source "ModSecurity" -- and the harness installed the event source
# but never collected what it received. When a module stalls, its own trace is
# the first thing to read rather than inferring from the outside.
function Save-Diagnostics {
    param([string]$Dir = "diag")
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null

    Get-EventLog -LogName Application -Newest 500 -ErrorAction SilentlyContinue |
        Where-Object { $_.Source -match 'ModSecurity|W3SVC|WAS|IIS' } |
        Select-Object TimeGenerated, Source, EntryType, EventID, Message |
        Format-List | Out-File (Join-Path $Dir "eventlog.txt") -Width 400

    # The modules' own trace, one file per arm (see common-*.conf).
    foreach ($p in "C:\bench\modsec-debug-v2.log", "C:\bench\modsec-debug-v3.log",
                   "C:\bench\error.log") {
        if (Test-Path $p) { Copy-Item $p (Join-Path $Dir (Split-Path $p -Leaf)) -Force }
    }

    Get-ChildItem "C:\inetpub\logs\LogFiles\W3SVC*" -Filter *.log -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-2) } |
        Copy-Item -Destination $Dir -Force

    Get-ChildItem $Dir -ErrorAction SilentlyContinue |
        Format-Table Name, Length | Out-String | Write-Host
}

# ---------------------------------------------------------------------------
# Measurement helpers
#
# CPU is ACCOUNTED, not sampled. Install-Arm runs iisreset on every arm switch,
# so w3wp is a fresh process per arm; summing TotalProcessorTime before and
# after a load run therefore yields exactly the CPU that run consumed, with no
# sampling error and no background job.
#
# This replaced a Start-Job + Get-Counter sampler that returned all zeros in CI:
# with -ErrorAction SilentlyContinue the collector's failure was invisible and
# the harness happily reported 0 CPU for every arm.
# ---------------------------------------------------------------------------

# Reads the current worker-process state. CpuSeconds is cumulative for the
# process, so callers take a delta around a run.
function Get-WorkerSnapshot {
    $procs = @(Get-Process -Name w3wp -ErrorAction SilentlyContinue)

    $cpu  = 0.0
    $ws   = 0
    $peak = 0
    foreach ($p in $procs) {
        $cpu += $p.TotalProcessorTime.TotalSeconds
        if ($p.WorkingSet64    -gt $ws)   { $ws   = $p.WorkingSet64 }
        if ($p.PeakWorkingSet64 -gt $peak) { $peak = $p.PeakWorkingSet64 }
    }

    @{
        # Cumulative CPU seconds across all worker processes.
        CpuSeconds = $cpu
        # Working set right now, and the high-water mark since the process
        # started (which is since the arm was installed, because iisreset
        # recycled it). The peak is therefore per-arm, not per-run.
        WsMB       = [math]::Round($ws   / 1MB, 1)
        PeakWsMB   = [math]::Round($peak / 1MB, 1)
        Processes  = $procs.Count
    }
}
