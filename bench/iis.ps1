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
}

function Restart-IIS {
    & iisreset /restart | Out-Null
    Start-Sleep -Seconds 3
}

# ---------------------------------------------------------------------------
# applicationHost.config section plumbing
#
# The schema file alone is not enough: the section has to be *declared* before
# appcmd will let us set it. Both connectors read system.webServer/ModSecurity,
# so this is shared.
# ---------------------------------------------------------------------------

function Add-ModSecuritySection {
    [xml]$xml = Get-Content $script:AhConfig
    $group = $xml.configuration.configSections.sectionGroup |
             Where-Object { $_.name -eq "system.webServer" } |
             Select-Object -First 1
    if (-not $group) { throw "system.webServer sectionGroup not found" }

    if (-not ($group.section | Where-Object { $_.name -eq "ModSecurity" })) {
        $sec = $xml.CreateElement("section")
        $sec.SetAttribute("name", "ModSecurity")
        $sec.SetAttribute("overrideModeDefault", "Allow")
        $sec.SetAttribute("allowDefinition", "Everywhere")
        [void]$group.AppendChild($sec)
        $xml.Save($script:AhConfig)
        Write-Host "  declared system.webServer/ModSecurity"
    }
}

function Remove-ModSecuritySection {
    if (Test-Path $script:AhConfig) {
        $raw = Get-Content $script:AhConfig -Raw
        $raw = $raw -replace '\s*<section name="ModSecurity"[^>]*/>', ''
        Set-Content $script:AhConfig -Value $raw -Encoding UTF8 -NoNewline
    }
}

# ---------------------------------------------------------------------------
# Arm install / uninstall
# ---------------------------------------------------------------------------

function Uninstall-Arm {
    Stop-Service W3SVC -Force -ErrorAction SilentlyContinue
    Stop-Service WAS   -Force -ErrorAction SilentlyContinue
    & $script:AppCmd uninstall module "ModSecurityIIS" 2>$null | Out-Null
    Remove-Item "$script:Inetsrv\modsecurityiis.dll" -Force -ErrorAction SilentlyContinue
    Remove-Item "$script:Inetsrv\libModSecurity.dll" -Force -ErrorAction SilentlyContinue
    Remove-ModSecuritySection
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
        Add-ModSecuritySection
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

    Add-ModSecuritySection
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

# ---------------------------------------------------------------------------
# Measurement helpers
# ---------------------------------------------------------------------------

# Samples w3wp CPU/private-bytes once a second for the duration of a run.
function Start-CounterJob {
    param([int]$Seconds)
    Start-Job -ScriptBlock {
        param($secs)
        Get-Counter -Counter '\Process(w3wp*)\% Processor Time','\Process(w3wp*)\Private Bytes' `
            -SampleInterval 1 -MaxSamples $secs -ErrorAction SilentlyContinue
    } -ArgumentList $Seconds
}

# Returns @{ CpuCores = average cores busy; PeakPrivateMB = peak working set }
function Stop-CounterJob {
    param($Job)
    $samples = @(Receive-Job $Job -Wait -ErrorAction SilentlyContinue)
    Remove-Job $Job -Force -ErrorAction SilentlyContinue

    if ($samples.Count -eq 0) { return @{ CpuCores = 0; PeakPrivateMB = 0 } }

    $perSample = $samples | ForEach-Object {
        ($_.CounterSamples | Where-Object { $_.Path -like '*% Processor Time*' } |
            Measure-Object -Property CookedValue -Sum).Sum
    }
    $bytes = $samples | ForEach-Object {
        ($_.CounterSamples | Where-Object { $_.Path -like '*Private Bytes*' } |
            Measure-Object -Property CookedValue -Maximum).Maximum
    }
    @{
        # "% Processor Time" is 100 per busy core, so /100 is cores.
        CpuCores      = (($perSample | Measure-Object -Average).Average) / 100.0
        PeakPrivateMB = [math]::Round((($bytes | Measure-Object -Maximum).Maximum) / 1MB, 1)
    }
}
