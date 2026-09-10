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
    * CPU is accounted from the worker process's TotalProcessorTime delta, not
      sampled. Install-Arm recycles the process, so each arm starts clean.
    * The raw bombardier JSON for every run is written to bench-json/ and
      uploaded, because a wrong guess about its schema shows up only as a
      silent zero.

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
    [string]$OutFile    = "bench-raw.csv",
    [string]$JsonDir    = "bench-json"
)

$ErrorActionPreference = "Stop"
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

# bombardier's JSON keys are read through a candidate list and a -1 sentinel,
# so a schema mismatch is loudly wrong instead of quietly zero.
function Get-Number {
    param($Bag, [string[]]$Names)
    if ($null -eq $Bag) { return $null }
    foreach ($n in $Names) {
        $v = $Bag.$n
        if ($null -ne $v) { return [double]$v }
    }
    return $null
}

# Rows are flushed to disk as they are produced. A full measurement set runs
# for the better part of an hour; writing the CSV only at the end means one
# late failure throws away every measurement before it.
function Add-Row {
    param($Row)
    if (Test-Path $OutFile) {
        $Row | Export-Csv $OutFile -NoTypeInformation -Encoding UTF8 -Append
    } else {
        $Row | Export-Csv $OutFile -NoTypeInformation -Encoding UTF8
    }
    $script:rowCount++
}

function Invoke-LoadRun {
    param($Scenario, [int]$Conc, [string]$Duration, [string]$Tag)

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
    if ($start -lt 0) { throw "no JSON from bombardier for ${Tag}:`n$raw" }
    $jsonText = $raw.Substring($start)

    New-Item -ItemType Directory -Force -Path $JsonDir | Out-Null
    # ${Tag} not $Tag: expandable strings support property access, so "$Tag.json"
    # reads the property `json` off $Tag (a string) and yields nothing.
    Set-Content (Join-Path $JsonDir "${Tag}.json") -Value $jsonText -Encoding Ascii

    # Schema verified against a real payload (run 34465384571), not guessed:
    #   result.latency = { mean, stddev, max }   <- MICROSECONDS, no percentiles
    #   result.rps     = { mean, stddev, max, percentiles = { 50, 75, 90, 95, 99 } }
    # So bombardier gives NO latency percentiles: the percentile block lives
    # under rps and describes throughput. Columns called "p50/p95/p99 latency"
    # would have been invented numbers.
    $json = $jsonText | ConvertFrom-Json
    $res  = $json.result
    $lat  = $res.latency

    $reqs = 0
    foreach ($k in 'req1xx','req2xx','req3xx','req4xx','req5xx','reqFailed','others') {
        $v = Get-Number $res @($k)
        if ($null -ne $v) { $reqs += [int]$v }
    }

    $rpsMean   = Get-Number $res.rps @('mean')
    $latMeanUs = Get-Number $lat @('mean')
    $latMaxUs  = Get-Number $lat @('max')
    $pct       = $res.rps.percentiles

    # Unit self-check via Little's law: rps.mean * latency.mean should be about
    # the client concurrency. If it is off by 1000x the microsecond assumption
    # is wrong, and every latency number is wrong with it.
    $little = if ($null -ne $latMeanUs -and $null -ne $rpsMean -and $Conc -gt 0) {
        [math]::Round(($rpsMean * $latMeanUs / 1e6) / $Conc, 2)
    } else { -1 }

    return [pscustomobject]@{
        RPS       = $rpsMean
        LatMeanMs = if ($null -ne $latMeanUs) { [math]::Round($latMeanUs / 1000, 3) } else { -1 }
        LatMaxMs  = if ($null -ne $latMaxUs)  { [math]::Round($latMaxUs  / 1000, 2) }  else { -1 }
        RpsP50    = Get-Number $pct @('50')
        RpsP95    = Get-Number $pct @('95')
        RpsP99    = Get-Number $pct @('99')
        LittleLaw = $little
        ReqCount  = $reqs
        Req4xx    = [int](Get-Number $res @('req4xx'))
        Req5xx    = [int](Get-Number $res @('req5xx'))
        Failed    = [int](Get-Number $res @('reqFailed'))
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$backend = Start-Backend
Initialize-BenchSite

$script:rowCount = 0
$durationSec = [int]($Duration -replace "[a-zA-Z]", "")

# Start from a clean CSV so an append never mixes with a previous run's rows.
if (Test-Path $OutFile) { Remove-Item $OutFile -Force }

try {
    foreach ($ruleset in $Rulesets) {
        for ($rep = 1; $rep -le $Repeats; $rep++) {
            # Arms interleaved inside every repetition: baseline, v2, v3.
            foreach ($arm in @("baseline", "v2", "v3")) {

                $config = if ($arm -eq "baseline") { "" } else { New-Config $arm $ruleset }
                $dllDir = if ($arm -eq "v2") { $V2DllDir } elseif ($arm -eq "v3") { $V3DllDir } else { "" }

                Write-Host "== rep $rep/$Repeats  arm=$arm  ruleset=$ruleset"
                Install-Arm -Arm $arm -DllDir $dllDir -ConfigFile $config

                # Warm up ARR, the origin's connection pool and the connector's
                # rules load. Not recorded, and taken before the first CPU
                # snapshot so its cost is not charged to the first scenario.
                $warm = $ScenarioDefs | Where-Object { $_.Id -eq "S1" } | Select-Object -First 1
                if ($warm) {
                    try {
                        $null = Invoke-LoadRun -Scenario $warm -Conc $Concurrency[0] `
                                    -Duration "5s" -Tag "warmup-$arm"
                    } catch {
                        Write-Host "  warmup failed (ignored): $_"
                    }
                }

                foreach ($scenario in $ScenarioDefs) {
                    if (-not ($Scenarios -contains $scenario.Id)) { continue }
                    if ($scenario.NeedsBlock -and $ruleset -eq "R0") { continue }

                    foreach ($conc in $Concurrency) {
                        $before = Get-WorkerSnapshot
                        $sw = [Diagnostics.Stopwatch]::StartNew()
                        $tag = "r${rep}-${arm}-${ruleset}-$($scenario.Id)-c${conc}"
                        $res = Invoke-LoadRun -Scenario $scenario -Conc $conc `
                                   -Duration $Duration -Tag $tag
                        $sw.Stop()
                        $after = Get-WorkerSnapshot

                        $cpuSec = $after.CpuSeconds - $before.CpuSeconds
                        $cpuMs  = if ($res.ReqCount -gt 0) {
                            [math]::Round($cpuSec * 1000 / $res.ReqCount, 3)
                        } else { -1 }

                        $row = [pscustomobject]@{
                            Rep         = $rep
                            Arm         = $arm
                            Ruleset     = $ruleset
                            Scenario    = $scenario.Id
                            Concurrency = $conc
                            WallSec     = [math]::Round($sw.Elapsed.TotalSeconds, 1)
                            RPS         = if ($null -ne $res.RPS) { [math]::Round($res.RPS, 1) } else { -1 }
                            LatMeanMs   = $res.LatMeanMs
                            LatMaxMs    = $res.LatMaxMs
                            RpsP50      = if ($null -ne $res.RpsP50) { [math]::Round($res.RpsP50, 1) } else { -1 }
                            RpsP95      = if ($null -ne $res.RpsP95) { [math]::Round($res.RpsP95, 1) } else { -1 }
                            RpsP99      = if ($null -ne $res.RpsP99) { [math]::Round($res.RpsP99, 1) } else { -1 }
                            LittleLaw   = $res.LittleLaw
                            ReqCount    = $res.ReqCount
                            Req4xx      = $res.Req4xx
                            Req5xx      = $res.Req5xx
                            Failed      = $res.Failed
                            CpuSec      = [math]::Round($cpuSec, 3)
                            CpuMsPerReq = $cpuMs
                            WsMB        = $after.WsMB
                            PeakWsMB    = $after.PeakWsMB
                            Workers     = $after.Processes
                        }
                        Add-Row $row
                        Write-Host ("   {0} c={1,-3} rps={2,-9} lat={3}ms cpu/req={4}ms ws={5}MB" -f `
                            $scenario.Id, $conc, $row.RPS, $res.LatMeanMs, $cpuMs, $after.WsMB)

                        # rps * latency / concurrency should be ~1. Far off means
                        # the latency unit is not microseconds and the column is
                        # quietly wrong, so say so loudly.
                        if ($res.LittleLaw -ge 0 -and ($res.LittleLaw -lt 0.5 -or $res.LittleLaw -gt 2.0)) {
                            Write-Warning ("Little's law check failed for {0} c={1}: rps*latency/concurrency = {2} (expected ~1)" -f `
                                $scenario.Id, $conc, $res.LittleLaw)
                        }
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

# Rows were flushed as they were produced; nothing to write here.
Write-Host "`nWrote $script:rowCount rows to $OutFile"
