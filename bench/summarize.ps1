<#
.SYNOPSIS
    Turns bench-raw.csv into a Markdown comparison table.

    Every repetition carries its own baseline measurement, so each
    (arm, ruleset, scenario, concurrency) observation is first normalised
    against the baseline from the SAME repetition, then aggregated with the
    median. Normalising per repetition is what cancels machine drift between
    the interleaved arms; the median (not the mean) keeps one bad run from
    moving the headline number.

    -1 is the CSV's "the harness could not read this" sentinel (it comes from
    Get-Number finding none of the candidate JSON keys) and is shown as n/a
    rather than being averaged in as a real zero.
#>
[CmdletBinding()]
param(
    [string]$Csv     = "bench-raw.csv",
    # Not $Out: PowerShell variable names are case-insensitive, so a $Out
    # parameter collides with a $out buffer in the body and the type constraint
    # corrupts the buffer.
    [string]$OutFile = "bench-report.md"
)

$rows = @(Import-Csv $Csv)
if ($rows.Count -eq 0) { throw "no rows in $Csv" }

function Get-Median {
    param([double[]]$Values)
    $sorted = @($Values | Where-Object { $null -ne $_ -and $_ -ge 0 } | Sort-Object)
    if ($sorted.Count -eq 0) { return $null }
    if ($sorted.Count % 2) { return [double]$sorted[[int](($sorted.Count - 1) / 2)] }
    return ([double]$sorted[$sorted.Count / 2 - 1] + [double]$sorted[$sorted.Count / 2]) / 2
}

function Format-Num {
    param($Value, [string]$Suffix)
    if ($null -eq $Value) { return "n/a" }
    return ("{0:N1}{1}" -f $Value, $Suffix)
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

$lines = @()
$lines += "# IIS connector benchmark: v2 vs v3"
$lines += ""
$lines += "Generated from ``$Csv`` ($($rows.Count) measurements)."
$lines += ""
$lines += "Columns are **medians across repetitions** of per-repetition values that"
$lines += "were first normalised against that repetition's baseline (no WAF module)."
$lines += "Lower is better for every *vs base* column."
$lines += ""
$lines += "| ruleset | scenario | conc | arm | rps | vs base rps | p50 ms | vs base p50 | cpu ms/req | ws MB |"
$lines += "|---|---|---|---|---:|---:|---:|---:|---:|---:|"

foreach ($g in ($groups | Sort-Object Name)) {
    $parts = $g.Name -split ", "
    $ruleset = $parts[0]; $scenario = $parts[1]; $conc = $parts[2]; $arm = $parts[3]

    $rps = @(); $p50 = @(); $cpu = @(); $ws = @()
    $rpsRatio = @(); $latRatio = @()

    foreach ($r in $g.Group) {
        $rps += [double]$r.RPS
        $cpu += [double]$r.CpuMsPerReq
        $ws  += [double]$r.WsMB
        if ([double]$r.P50ms -ge 0) { $p50 += [double]$r.P50ms }

        $b = $baseline["$ruleset|$scenario|$conc|$($r.Rep)"]
        if ($b) {
            if ([double]$b.RPS -gt 0 -and [double]$r.RPS -ge 0) {
                $rpsRatio += ([double]$b.RPS - [double]$r.RPS) / [double]$b.RPS * 100
            }
            if ([double]$b.P50ms -gt 0 -and [double]$r.P50ms -ge 0) {
                $latRatio += ([double]$r.P50ms - [double]$b.P50ms) / [double]$b.P50ms * 100
            }
        }
    }

    $lines += ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} |" -f `
        $ruleset, $scenario, $conc, $arm,
        (Format-Num (Get-Median $rps) ""),
        (Format-Num (Get-Median $rpsRatio) "%"),
        (Format-Num (Get-Median $p50) ""),
        (Format-Num (Get-Median $latRatio) "%"),
        (Format-Num (Get-Median $cpu) ""),
        (Format-Num (Get-Median $ws) ""))
}

$lines += ""
$lines += "## How to read this"
$lines += ""
$lines += "* **vs base rps** -- throughput lost to the WAF. Negative means the WAF arm"
$lines += "  was *faster* than no WAF, which means the run was noise-dominated:"
$lines += "  raise ``-Repeats`` and ``-Duration`` before believing the number."
$lines += "* **vs base p50** -- added median latency."
$lines += "* **cpu ms/req** -- worker-process CPU milliseconds per request, from the"
$lines += "  exact ``TotalProcessorTime`` delta around each run. This is the cleanest"
$lines += "  single cost figure: it does not depend on how busy the shared runner was."
$lines += "* **ws MB** -- worker-process working set after the run."
$lines += "* Absolute numbers are only comparable **within one run**. GitHub-hosted"
$lines += "  runners are virtualised and shared-tenant; compare the normalised columns"
$lines += "  across runs, not raw rps."
$lines += "* A ``n/a`` means the value could not be read -- check ``bench-json/``"
$lines += "  in the artifacts for the raw bombardier output."

# .NET rather than Set-Content: no provider/encoding ambiguity.
[System.IO.File]::WriteAllLines(
    (Join-Path $PWD $OutFile), [string[]]$lines, [System.Text.UTF8Encoding]::new($false))

Write-Host "Wrote $OutFile ($($lines.Count) lines)"
