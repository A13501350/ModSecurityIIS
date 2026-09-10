# Benchmarking the v2 and v3 IIS connectors

Runs entirely on GitHub Actions (`bench.yml`, `workflow_dispatch`). Nothing needs
to be installed on a workstation.

```bat
gh workflow run bench.yml                     :: defaults: R1, S1/S3/S4, c=1+16, 3 reps
gh workflow run bench.yml -f scenarios=S1,S2,S3,S4,S5,S6 -f concurrency=1,8,32,64 -f repeats=5
```

Results land in the `bench-results` artifact (`bench-raw.csv`, `bench-report.md`).

## What is actually being compared

| arm | what it is |
|---|---|
| `baseline` | no WAF module registered — the reference every number is normalised against |
| `v2` | `modsecurityiis.dll` built from `owasp-modsecurity/ModSecurity` (v2.9.x), engine compiled into the DLL |
| `v3` | `modsecurityiis.dll` + `libModSecurity.dll` (v3.0.16 submodule) |

This is a **stack-to-stack** comparison, not a clean A/B of the connector code:
the two engines are different programs. The rulesets below are what make the
number interpretable.

## Rulesets

| | content | isolates |
|---|---|---|
| `R0` | engine ON, **zero rules** | connector cost: build the transaction, feed request line + headers, run the (empty) phase machine, tear down |
| `R1` | 20 inspection rules + 1 blocking probe | connector + engine matching cost |

`R1` is written to be loadable by **both** engines (only `@rx`/`@streq` and
variables both understand), to never match the benchmark's benign traffic, and
to use `pass,nolog` — so the measurement is inspection cost, not blocking or
logging I/O.

## Scenarios

| | request | why |
|---|---|---|
| S1 | tiny GET | phase-1 fixed cost |
| S2 | GET + 40 filler headers | header-table construction (v2 builds a fake `apr_table`, v3 calls `addRequestHeader` per header) |
| S3 | POST 1 KiB | phase-2, small body |
| S4 | POST 100 KiB | body transport (v2 forced streaming + rewrite vs v3 async drain + single `InsertEntityBody`) |
| S5 | GET 64 KiB response | phase 3/4 (v2 inspects the first chunk, v3 buffers everything) |
| S6 | GET `/bench/block` | intervention path; needs `R1` (skipped for `R0`) |

## Methodology — and why it is shaped like this

* **One runner, one job, all arms.** A GitHub matrix would put each arm on a
  different virtualised, shared-tenant machine and the comparison would be
  worthless. Arms are switched in place and **interleaved inside every
  repetition** so drift spreads evenly.
* **v2 and v3 cannot coexist.** Both ship `modsecurityiis.dll` and both read
  `system.webServer/ModSecurity`, so every switch is a full
  uninstall → install → `iisreset`.
* **Per-repetition baseline normalisation.** Every repetition measures
  `baseline` too, and results are normalised against *that* baseline before
  aggregation — this is what cancels machine drift. Absolute RPS is only
  comparable within a single run.
* **Median across repetitions**, not mean, so one bad run does not move the
  headline number.
* **`cpu ms/req`** (`cores busy / rps × 1000`) is the cleanest single cost
  figure, because it is independent of how busy the runner happened to be.
* Audit and debug logging are **off** in both arms (`common-v2.conf` /
  `common-v3.conf` are mirrors). They would dominate the measurement and differ
  between engines.
* Origin is a small Go server (`backend/`) behind ARR, same topology
  `scripts/ci-crs.ps1` uses with albedo. The IIS static handler cannot be used:
  it answers 405 to POST, so S3/S4 would never exercise a body.

## What the CSV columns mean

| column | source |
|---|---|
| `RPS` | `result.rps.mean` |
| `LatMeanMs` / `LatMaxMs` | `result.latency.mean` / `.max` — **microseconds** in the payload, converted to ms |
| `RpsP50` / `RpsP95` / `RpsP99` | `result.rps.percentiles` — a **throughput** distribution, not latency |
| `LittleLaw` | `rps * latency / concurrency`, expected ≈ 1.0. A self-check on the microsecond assumption; far from 1 means the latency columns are wrong |
| `CpuSec` / `CpuMsPerReq` | `w3wp`'s `TotalProcessorTime` delta around the run ÷ requests |
| `WsMB` / `PeakWsMB` | working set after the run, and its high-water mark since the arm was installed |
| `ReqCount` / `Req4xx` / `Req5xx` | status buckets, summed from `result.req*` |

Raw payloads for every run are in `bench-json/` in the artifact — the ground
truth for the schema above.

## Known limitations

* **No latency percentiles.** bombardier's JSON exposes only
  `latency.mean/stddev/max`; its `percentiles` block belongs to `rps`. If tail
  latency (p95/p99) is what you need, add k6 as a second generator — the
  harness is agnostic, only `Invoke-LoadRun` would change.
* **Per-arm switching is not free.** Each arm switch is uninstall → install →
  `iisreset` (the two connectors cannot coexist), so keep the scenario set
  small enough that setup does not dominate wall-clock.
* Stack comparison — see above.
* `windows-latest` is 4 vCPU / 16 GB, virtualised and shared. Noisy.
* The load generator runs on the same box as `w3wp`, so at high concurrency the
  client competes for CPU. Check the `cpu ms/req` column and the reported RPS
  together; if RPS plateaus while CPU is well below the core count, the client
  is the bottleneck, not the WAF.
* v2 is built **without** Lua, YAJL and ssdeep (the upstream workflow has them
  on). Irrelevant for R0/R1, but it means JSON-body and Lua rules are untested.
* CRS is **not** included yet. Adding it as an `R2` ruleset is the obvious next
  step, using the same CRS version and paranoia level on both engines.
