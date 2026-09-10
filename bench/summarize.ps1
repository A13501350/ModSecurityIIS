<#
.SYNOPSIS
    Turns bench-raw.csv into a Markdown comparison table.

    Every repetition carries its own baseline measurement, so each
    (arm, ruleset, scenario, concurrency) observation is first normalised
    against the baseline from the SAME repetition, then aggregated with the
    median. Normalising per repetition is what cancels machine drift between
    the interleaved arms; the median (not the mean) keeps one bad run from
    moving the headline number.
#>
[CmdletBinding()]
param(
    [string]$Csv   = "bench-raw.csv",
    [string]$Out   = "bench-report.md"
)

$rows = @(Import-Csv $Csv)
if ($rows.Count -eq 0) { throw "no rows in $Csv" }

function Get-Median([double[]]$Values) {
    $sorted = $Values | Where-Object { $_ -ne $null } | Sort-Object
    if ($sorted.Count -eq 0) { return $null }
    if ($sorted.Count % 2) { return [double]$sorted[($sorted.Count - 1) / 2] }
    return ([double]$sorted[$sorted.Count / 2 - 1] + [double]$sorted[$sorted.Count / 2]) / 2
}

# Keyed by ruleset|scenario|concurrency|rep -> baseline row.
$baseline = @{}
foreach ($r in $rows) {
    if ($r.Arm -eq "baseline") {
        $baseline["$($r.Ruleset)|$($r.Scenario)|$($r.Concurrency)|$($r.Rep)"] = $r
    }
}

$groups = $rows | Where-Object { $_.Arm -ne "baseline" } |
          Group-Object Ruleset, Scenario, Concurrency, Arm

$out = @()
$out += "# IIS connector benchmark: v2 vs v3"
$out += ""
$out += "Generated from ``$Csv`` ($($rows.Count) measurements)."
$out += ""
$out += "Columns are **medians across repetitions** of per-repetition values that"
$out += "were first normalised against that repetition's baseline (no WAF module)."
$out += ""
$out += "| ruleset | scenario | conc | arm | rps | vs base | p50 ms | vs base | cpu ms/req | peak MB |"
$out += "|---|---|---|---|---:|---:|---:|---:|---:|---:|"

foreach ($g in ($groups | Sort-Object Name)) {
    $parts = $g.Name -split ", "
    $ruleset, $scenario, $conc, $arm = $parts[0], $parts[1], $parts[2], $parts[3]

    $rpsRatio = @(); $latRatio = @(); $rps = @(); $p50 = @(); $cpu = @(); $mem = @()
    foreach ($r in $g.Group) {
        $b = $baseline["$ruleset|$scenario|$conc|$($r.Rep)"]
        $rps  += [double]$r.RPS
        $p50  += [double]$r.P50ms
        $cpu  += [double]$r.CpuMsPerReq
        $mem  += [double]$r.PeakPrivateMB
        if ($b -and [double]$b.RPS -gt 0) {
            $rpsRatio += ([double]$b.RPS - [double]$r.RPS) / [double]$b.RPS * 100
        }
        if ($b -and [double]$b.P50ms -gt 0) {
            $latRatio += ([double]$r.P50ms - [double]$b.P50ms) / [double]$b.P50ms * 100
        }
    }

    $fmt = {
        param($v, [string]$suffix)
        if ($v -eq $null) { return "n/a" }
        return ("{0:N1}{1}" -f $v, $suffix)
    }

    $out += ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} |" -f `
        $ruleset, $scenario, $conc, $arm,
        (& $fmt (Get-Median $rps) ""),
        (& $fmt (Get-Median $rpsRatio) "%"),
        (& $fmt (Get-Median $p50) ""),
        (& $fmt (Get-Median $latRatio) "%"),
        (& $fmt (Get-Median $cpu) ""),
        (& $fmt (Get-Median $mem) ""))
}

$out += ""
$out += "## How to read this"
$out += ""
$out += "* **vs base (rps)** -- throughput lost to the WAF. Lower is better."
$out += "* **vs base (p50)** -- added median latency. Lower is better."
$out += "* **cpu ms/req** -- worker-process CPU milliseconds per request"
$out += "  (``cores busy / rps * 1000``). The cleanest single cost number, because"
$out += "  it is independent of how busy the shared runner happened to be."
$out += "* Absolute numbers are only comparable **within one run**. GitHub-hosted"
$out += "  runners are virtualised and shared-tenant; compare the normalised"
$out += "  columns across runs, not raw rps."

Set-Content $Out -Value ($out -join "`n") -Encoding UTF8
Write-Host "Wrote $Out"
