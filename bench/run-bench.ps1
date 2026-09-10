<#
.SYNOPSIS
    Measures the request cost of the IIS connector with no WAF (baseline),
    the v2 connector and the v3 connector, on one machine, interleaved.

.DESCRIPTION
    Design notes -- these are what make the numbers usable:

    * ONE runner, ONE job, ALL arms. A GitHub matrix would put each arm on a
      different (virtualised, shared-tenant) machine and the comparison would
      be meaningless. Arms are therefore switched in place and interleaved
      inside each repetition so machine drift is spread evenly.
    * baseline is measured in every repetition and everything is normalised
      against it, which cancels most of the remaining drift.
    * v2 and v3 both ship modsecurityiis.dll and both read
      system.webServer/ModSecurity, so they can never be loaded together --
      every switch is a full uninstall/install plus iisreset.

.PARAMETER V2DllDir   Directory containing the v2 modsecurityiis.dll (+ deps).
.PARAMETER V3DllDir   Directory containing the v3 modsecurityiis.dll + libModSecurity.dll.
.PARAMETER Rulesets   R0 (engine on, no rules) and/or R1 (20 inspection rules + block probe).
.PARAMETER Scenarios  S1..S6, see the table below.
.PARAMETER Concurrency One or more client concurrency levels.
.PARAMETER Repeats    Repetitions per (arm, ruleset, scenario, concurrency).
.PARAMETER Duration   Duration of a single bombardier run, e.g. 20s.
.PARAMETER Mode       throughput (full tilt) or latency (-r fixed arrival rate).
.PARAMETER Rate       Requests/sec for -Mode latency.
#>
[CmdletBinding()]
param(
    [string]$V2DllDir   = "artifacts\v2",
    [string]$V3DllDir   = "artifacts\v3",
    [string[]]$Rulesets = @("R1"),
    [string[]]$Scenarios = @("S1", "S3", "S4"),
    [int[]]$Concurrency = @(1, 16),
    [int]$Repeats       = 3,
    [string]$Duration   = "20s",
    [ValidateSet("throughput", "latency")][string]$Mode = "throughput",
    [int]$Rate          = 500,
    [string]$OutFile    = "bench-raw.csv"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "iis.ps1")

# ---------------------------------------------------------------------------
# Scenarios. BodyKB > 0 turns the request into a POST of that many KiB to
# /bench/echo. NeedsBlock marks scenarios that only make sense with a ruleset
# containing the blocking probe (R1); they are skipped for R0.
# ---------------------------------------------------------------------------
$ScenarioDefs = @(
    @{ Id = "S1"; Path = "/bench/small"; Method = "GET";  BodyKB = 0;   FillHeaders = 0;  NeedsBlock = $false }
    @{ Id = "S2"; Path = "/bench/small"; Method = "GET";  BodyKB = 0;   FillHeaders = 40; NeedsBlock = $false }
    @{ Id = "S3"; Path = "/bench/echo";  Method = "POST"; BodyKB = 1;   FillHeaders = 0;  NeedsBlock = $false }
    @{ Id = "S4"; Path = "/bench/echo";  Method = "POST"; BodyKB = 100; FillHeaders = 0;  NeedsBlock = $false }
    @{ Id = "S5"; Path = "/bench/big";   Method = "GET";  BodyKB = 0;   FillHeaders = 0;  NeedsBlock = $false }
    @{ Id = "S6"; Path = "/bench/block"; Method = "GET";  BodyKB = 0;   FillHeaders = 0;  NeedsBlock = $true  }
)

function Start-Backend {
    Write-Host "== Starting benchmark backend on 127.0.0.1:8080"
    # `go run .` from inside backend/ (it has its own go.mod; the repo root has
    # none, so a module-aware `go run ./bench/backend` would fail from here).
    $proc = Start-Process -FilePath "go" `
        -ArgumentList @("run", ".", "-addr", "127.0.0.1:8080") `
        -WorkingDirectory (Join-Path $PSScriptRoot "backend") `
        -PassThru -WindowStyle Hidden
    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Seconds 1
        try {
            $null = Invoke-WebRequest "http://127.0.0.1:8080/bench/small" -UseBasicParsing -TimeoutSec 5
            $ready = $true; break
        } catch { }
    }
    if (-not $ready) { throw "backend never became ready on 8080" }
    return $proc
}

function New-Config {
    param([string]$Arm, [string]$Ruleset)
    # common-<arm>.conf + R<ruleset>.conf -> one file the connector loads.
    $common = Join-Path $PSScriptRoot "rules\common-$Arm.conf"
    $rules  = Join-Path $PSScriptRoot "rules\$Ruleset.conf"
    $out    = Join-Path $script:BenchDir "modsecurity.conf"
    $body   = @()
    $body  += (Get-Content $common)
    $body  += ""
    $body  += (Get-Content $rules)
    Set-Content $out -Value $body -Encoding Ascii
    return $out
}

function New-BodyFile {
    param([int]$BodyKB)
    if ($BodyKB -le 0) { return $null }
    $path = Join-Path $script:BenchDir "body-$BodyKB.bin"
    if (-not (Test-Path $path)) {
        $buf = New-Object byte[] ($BodyKB * 1024)
        (New-Object System.Random 42).NextBytes($buf)
        [System.IO.File]::WriteAllBytes($path, $buf)
    }
    return $path
}

function Invoke-LoadRun {
    param($Scenario, [int]$Conc, [string]$Duration)

    $url = "http://127.0.0.1" + $Scenario.Path
    # NOTE: not $args -- that is a PowerShell automatic variable.
    $bargs = @("-c", "$Conc", "-d", $Duration, "-o", "json", "--timeout", "30s")

    if ($Mode -eq "latency") { $bargs += @("-r", "$Rate") }

    for ($i = 0; $i -lt $Scenario.FillHeaders; $i++) {
        # ${i} not $i: in a double-quoted string "$i:" is parsed as a scoped
        # variable reference (the same shape as $env:PATH) and is a parse
        # error, which kills the whole script before it runs a single line.
        $bargs += @("-H", "X-Bench-Fill${i}: filler-value-$i")
    }
    if ($Scenario.BodyKB -gt 0) {
        $bargs += @("-m", "POST", "-f", (New-BodyFile $Scenario.BodyKB),
                    "-H", "Content-Type: text/plain")
    }

    $raw = & bombardier $bargs $url 2>&1 | Out-String
    # The JSON block starts at the first brace; anything before it is the
    # progress line bombardier writes to stderr.
    $start = $raw.IndexOf("{")
    if ($start -lt 0) { throw "no JSON from bombardier:`n$raw" }
    $json = $raw.Substring($start) | ConvertFrom-Json

    $lat = $json.result.latencies
    return [pscustomobject]@{
        RPS      = [math]::Round($json.result.rps.mean, 1)
        P50ms    = [math]::Round($lat.'50th' / 1e6, 2)
        P95ms    = [math]::Round($lat.'95th' / 1e6, 2)
        P99ms    = [math]::Round($lat.'99th' / 1e6, 2)
        Req2xx   = [int]$json.result.req2xx
        Req4xx   = [int]$json.result.req4xx
        Req5xx   = [int]$json.result.req5xx
        Failed   = [int]$json.result.reqFailed + [int]$json.result.others
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$backend = Start-Backend
Initialize-BenchSite

$rows = @()
$durationSec = [int]($Duration -replace "[a-zA-Z]", "")

try {
    foreach ($ruleset in $Rulesets) {
        for ($rep = 1; $rep -le $Repeats; $rep++) {
            # Arms interleaved inside every repetition: baseline, v2, v3.
            foreach ($arm in @("baseline", "v2", "v3")) {

                $config = if ($arm -eq "baseline") { "" } else { New-Config $arm $ruleset }
                $dllDir = if ($arm -eq "v2") { $V2DllDir } elseif ($arm -eq "v3") { $V3DllDir } else { "" }

                Write-Host "== rep $rep/$Repeats  arm=$arm  ruleset=$ruleset"
                Install-Arm -Arm $arm -DllDir $dllDir -ConfigFile $config

                foreach ($scenario in $ScenarioDefs) {
                    if (-not ($Scenarios -contains $scenario.Id)) { continue }
                    if ($scenario.NeedsBlock -and $ruleset -eq "R0") { continue }

                    foreach ($conc in $Concurrency) {
                        # Sample slightly longer than the load run so bombardier's
                        # startup is always covered by at least one sample.
                        $counter = Start-CounterJob -Seconds ($durationSec + 8)
                        $sw = [Diagnostics.Stopwatch]::StartNew()
                        $res = Invoke-LoadRun -Scenario $scenario -Conc $conc -Duration $Duration
                        $sw.Stop()
                        $counters = Stop-CounterJob -Job $counter

                        $rows += [pscustomobject]@{
                            Rep          = $rep
                            Arm          = $arm
                            Ruleset      = $ruleset
                            Scenario     = $scenario.Id
                            Concurrency  = $conc
                            WallSec      = [math]::Round($sw.Elapsed.TotalSeconds, 1)
                            RPS          = $res.RPS
                            P50ms        = $res.P50ms
                            P95ms        = $res.P95ms
                            P99ms        = $res.P99ms
                            Req2xx       = $res.Req2xx
                            Req4xx       = $res.Req4xx
                            Req5xx       = $res.Req5xx
                            Failed       = $res.Failed
                            CpuCores     = [math]::Round($counters.CpuCores, 3)
                            CpuMsPerReq  = if ($res.RPS -gt 0) {
                                [math]::Round($counters.CpuCores * 1000 / $res.RPS, 3)
                            } else { 0 }
                            PeakPrivateMB = $counters.PeakPrivateMB
                        }
                        Write-Host ("   {0} c={1,-3} rps={2,-9} p50={3,-7} cpu/req={4}ms" -f `
                            $scenario.Id, $conc, $res.RPS, $res.P50ms, $rows[-1].CpuMsPerReq)
                    }
                }
            }
        }
    }
}
finally {
    Uninstall-Arm
    if ($backend -and -not $backend.HasExited) { Stop-Process -Id $backend.Id -Force -ErrorAction SilentlyContinue }
}

$rows | Export-Csv $OutFile -NoTypeInformation -Encoding UTF8
Write-Host "`nWrote $($rows.Count) rows to $OutFile"
