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
| S7 | POST 1 KiB → `/bench/discard` | as S3 but the origin discards the body, so the response is tiny |
| S8 | POST 100 KiB → `/bench/discard` | as S4 but the origin discards the body |
| S9 | GET `/bench/small` + `X-Bench-Probe: yes` | trips rule 9003, a deny keyed on a header instead of the URI; see "Known defects" |

S6 and S9 are a pair. S6's deny is keyed on `REQUEST_URI`, S9's on a request
header; v2 served S6 as 200 while v3 returned 403 for every request, so the two
together say whether the URI failed to match or the interception failed to act.

S7/S8 exist to separate the two directions: a POST that hangs on `/bench/echo`
*and* on `/bench/discard` points at the request-body path, while one that hangs
only on `/bench/echo` points at the response-body path.

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

## Known defects found by this harness

Both were found on 2026-09-10 and are reproducible; neither is a harness bug.

### v2: every request with a body returns no response

With `SecRequestBodyAccess On` (the normal WAF configuration), the v2
connector built from `owasp-modsecurity/ModSecurity@v2/master` reads the
request body, finishes phase 2, installs its input forwarding filter, and then
the request never produces a response. The body is never handed downstream, so
the proxied origin waits for it forever; phase 5 only appears in a batch when
the client's timeout tears the connections down.

Evidence (run 34480703201, `SecDebugLogLevel 4`):

```
REQUEST_HEADERS 5231   RESPONSE_HEADERS 5163     -> 68 short
REQUEST_BODY    5231   RESPONSE_BODY    5163
body log lines: "Reading request body" x68 = 1024B x34 + 102400B x34
```

68 is exactly the number of POSTs the harness sends (S3+S7 and S4+S8 at c=1 and
c=16), so every POST had its body read and none produced a response. A single
POST's trace ends at:

```
Input filter: Completed receiving request body (length 1024).
Starting phase REQUEST_BODY.
Hook insert_filter: Adding input forwarding filter (r ...).
Hook insert_filter: Adding output filter (r ...).
<nothing>
```

Independent of rules (reproduces under R0), of body size (1 KiB already stalls),
of the limit directives (aligning them with the proven
`scripts/ci-crs.ps1:67-81` values changes nothing), and of the fork's
`iis-fix-chunked-te` commit (building v2 from it makes no difference).

`SecRequestBodyAccess Off` makes all four POST scenarios healthy again
(run 34484364411), which scopes it to the request-body path and is also the
only known workaround -- at the cost of not inspecting bodies at all.

Upstream CI misses it because its three functional assertions are all GET
(`test-ci-windows.yml:273-277`) and its go-ftw step never checks the exit code
(line 332).

### v3: 100 KiB request bodies stall

The v3 connector handles 1 KiB POSTs normally but stalls on 100 KiB ones, and
this is **unaffected** by `SecRequestBodyAccess` because its async drain
(`DriveBodyRead`) runs unconditionally from `OnBeginRequest`. A different
defect from the v2 one. c=16 partially works around it, which suggests a
per-connection block rather than a hard failure.

Consequence for the benchmark: only the header path (S1, S2, S6) is comparable
today, which is why it is the default scenario set.

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
