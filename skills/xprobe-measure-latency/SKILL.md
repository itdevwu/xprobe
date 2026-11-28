---
name: xprobe-measure-latency
description: Collect and analyze bounded latency evidence from a live or recorded Linux CPU, CPython, or NVIDIA CUDA workload with xprobe. Use to measure a function, syscall, CUDA API, kernel, transfer, NVTX range, or event-to-event latency, several related latencies at once, GPU idle time and stream gaps, rare spikes, Python stacks, CPU hotspots, or multi-rank GPU jobs; to analyze an existing xprobe artifact; or to install and repair xprobe.
---

# Profile workloads with xprobe

xprobe collects bounded evidence; you decide what to ask. Performance problems
vary, so there is no fixed procedure: form a hypothesis from what the user and
the workload tell you, pick the evidence that tests it, read the artifact, and
iterate. [Artifacts](references/artifacts.md) lists what every result and
artifact contains and how to read it correctly; read it before analyzing one.

Commands print JSON whenever stdout is not a terminal. Measurement, graph,
trigger, and triage results use schema version `3.0`; other records and Event
JSONL use `2.0`. Treat malformed output or an unknown version as an error.

## Evidence to choose from

| Question | Evidence |
| --- | --- |
| How long does A → B take? | `measure --from A --to B --match POLICY` with `--samples` or `--duration-ms` |
| How do several related spans compare? | one measurement graph via `measure --spec` (up to eight edges, one capture) |
| Where does CPU time go? | `--cpu-sample` stack inventory |
| Which syscalls cost time? | `--syscall-aggregate` |
| What does Python run, and who holds the GIL? | `--python-sample` (CPython 3.9–3.14, read-only) |
| Which kernels or copies dominate? | `--aggregate` over `cuda:kernel_*`, `cuda:memcpy_*`, or `cuda:memset_*` |
| When is a GPU idle or a stream stalled? | an exact capture with `stream-order`, then `scripts/analyze_trace.py` |
| A spike is rare | a triggered capture: `--trigger-idle-ms`, `--trigger-gap-ms`, `--trigger-duration-ms`, `--trigger-latency-ms` |
| Ranks of one job behave differently | one capture per rank, compared by `scripts/analyze_trace.py` |
| A quick broad look | `--triage`: several sources at once with rule-based hints; a reference, not a verdict |

Selectors, policies, specs, and capacity are in
[selectors](references/selectors.md); for several processes or ranks
(`discover --pid ROOT` lists CUDA context holders) read
[multi-process](references/multi-process.md).

## Work with the evidence

- **Existing artifact**: analyze it offline. Re-correlate Event JSONL with
  `measure --input`; summarize GPU timing with `scripts/analyze_trace.py`.
  Skip installation, `doctor`, `discover`, and live attachment unless a new
  capture is required.
- **Live target**: identify the process, warm it up, and capture one
  representative cycle. Run read-only `validate` when a selector, policy, or
  injection is uncertain:

  ```bash
  xprobe measure --pid "$PID" --from cuda:launch_api:exit \
    --to cuda:kernel_start --match exact --samples 200
  ```

- Combine sources when the question spans them: run concurrent bounded
  commands, or a measurement graph when edges must share one capture.
- Read raw fields, not only summaries: inventories, Event JSONL, and Python
  sample records hold more than any rule ranks.
- Triage findings are heuristics over one window. Use its inventories and
  `sources`, check `not_covered`, and confirm a finding with a direct
  measurement before reporting it. Its `next.spec` is one possible next step.
- **Missing CLI, container target, or environment failure**: read
  [setup](references/setup.md). Run `doctor` only when capability is unknown or
  a command reports an environment failure.

## Read results

- Start exact results from `quality.verdict` and its issues; `caution` limits
  the claim, and you say why. Rank exemplars are inline; the full capture is
  at `evidence.artifact.path`, with its `.manifest.json` beside it.
- A command error is not a result. Errors keep structured `details`, including
  any preserved artifact path; follow `hints` instead of retrying blindly.
- Stop collecting when a step adds no new boundary; report what is known, what
  remains unexplained, and which tool fits next.

## Keep these invariants

- Identify a live process by PID plus procfs start time; never reuse a PID-only
  choice after a restart.
- Bound every capture by samples or duration, timeout, and capacity.
- Before CUDA injection, tell the user that `measure` will ptrace the process
  and leave the CUPTI shared object mapped. NVTX needs the Agent at startup.
- Keep process, device, and stream identity in every claim. A stream gap is not
  device idle time, summed concurrent GPU time is not wall time, sampled shares
  are estimates, and temporal correlation is not exact causality.
- Record an application baseline for regressions or overhead claims.

## Stop or hand off

Stop on target exit or reuse, permission failure, invalid selectors, drops, or
a clock failure that invalidates the claim; report the structured error. Once
time is isolated inside one GPU kernel, hand off to NCU or PC sampling; once it
is isolated in code without an observable boundary, use a runtime-specific
profiler. Do not claim Python semantics when `python_status` says otherwise.
