---
name: xprobe-measure-latency
description: Find where time goes in a live or recorded Linux CPU, CPython, or NVIDIA CUDA workload with bounded xprobe evidence. Use to triage an unknown slow process, measure a known function, syscall, CUDA API, kernel, transfer, NVTX range, or event-to-event latency, measure several related latencies at once, compare workers or regressions, inspect an existing xprobe artifact, or install and repair xprobe.
---

# Profile workloads with xprobe

Reach an answer in two commands: triage, then one exact measurement. Choose the
shortest route the evidence allows; never collect every source by checklist.

Commands print JSON whenever stdout is not a terminal. Measurement, graph, and
triage results use schema version `3.0`; other records and Event JSONL use
`2.0`. Treat malformed output or an unknown version as an error.

## Route the task

- **Existing artifact**: analyze it offline. Re-correlate Event JSONL with
  `measure --input`; summarize GPU activity with `scripts/analyze_trace.py`.
  Skip installation, `doctor`, `discover`, and live attachment unless a new
  capture is required.
- **Unknown live workload**: identify the process, then triage one
  representative cycle (one request, batch, or iteration, after warmup):

  ```bash
  xprobe measure --pid "$PID" --triage --duration-ms 2000
  ```

  Read `findings` from rank 1. A finding's `next.spec` is a ready measurement:
  write it to a file and run `xprobe measure --spec next.json`. An
  `environment` finding (throttling, runqueue wait, GPU clock limits) is a
  conclusion, not a cue to profile code.
- **Known boundary**: skip triage. Run read-only `validate` when injection or
  selector resolution is uncertain, then one bounded `measure`.
- **Several related boundaries** (request → launch → kernel): one measurement
  graph captures every edge at once; see [selectors](references/selectors.md).
- **CUDA worker unknown**: `discover --pid ROOT` lists CUDA context holders; pick
  from workload evidence. For several workers read
  [multi-process](references/multi-process.md).
- **Missing CLI, container target, or environment failure**: read
  [setup](references/setup.md). Run `doctor` only when capability is unknown or
  a command reports an environment failure.

Read [interpreting results](references/interpreting.md) before stating a
latency claim, and [selectors](references/selectors.md) before writing a
selector yourself.

## Read results

- Triage: check `sources` before trusting silence. An `unavailable` source and
  every `not_covered` item are questions triage did not answer. Shares are
  estimates; blocked time includes idle waiting.
- Exact results: start from `quality.verdict` and its issues. `caution` limits
  the claim; say why. Rank exemplars (min, p50, p90, p99, max) are inline; the
  full capture is at `evidence.artifact.path`.
- A command error is not a result. Errors keep structured `details`, including
  any preserved artifact path; follow `hints` instead of retrying blindly.

## Dig deeper when the first pass is inconclusive

Escalate one step at a time, each driven by the previous result; details are in
[deep dive](references/deep-dive.md).

1. **Triage found nothing actionable**: fix `unavailable` sources first, then
   widen the window to cover a slow cycle, or run the focused inventory triage
   omits (memcpy/memset activity, larger CPU sample, `-X perf` for Python).
2. **A span is slow but unexplained**: split it with a measurement graph into
   sub-edges, and follow sampled stacks down to a callee boundary.
3. **Only the tail is slow**: read the p99 and max exemplars, then inspect the
   artifact around them; re-correlate it offline with `measure --input` before
   recapturing.
4. **Threads are blocked**: measure the dominant syscall exactly, check Python
   GC lifecycles, and treat lock or I/O attribution as not yet covered.
5. **It is a regression**: run the same spec on the baseline and compare
   distributions and quality, not single means.

Stop escalating when a step adds no new boundary; report what is known, what
remains unexplained, and which hand-off tool fits.

## Keep these invariants

- Identify a live process by PID plus procfs start time; never reuse a PID-only
  choice after a restart.
- Bound every capture by samples or duration, timeout, and capacity.
- Before CUDA injection, tell the user that `measure` will ptrace the process
  and leave the CUPTI shared object mapped. NVTX needs the Agent at startup.
- Keep process and CUDA stream identity in every claim. Summed concurrent GPU
  time is not wall time, sampled shares are estimates, and temporal correlation
  is not exact causality.
- Record an application baseline for regressions or overhead claims.

## Stop or hand off

Stop on target exit or reuse, permission failure, invalid selectors, drops, or
a clock failure that invalidates the claim; report the structured error. Once
time is isolated inside one GPU kernel, hand off to NCU or PC sampling; once it
is isolated in code without an observable boundary, use a runtime-specific
profiler. Do not claim Python semantics when `python_status` says otherwise.
