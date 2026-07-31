---
name: xprobe-measure-latency
description: Profile live or recorded Linux CPU, CPython, and NVIDIA CUDA workloads with bounded xprobe evidence. Use when an agent needs to install or repair xprobe, inventory unknown CPU/GPU work, find native or Python hotspots, inspect syscall or CPython GC cost, validate and measure a known function, syscall, CUDA API, kernel, transfer, synchronization point, NVTX range, or event-to-event latency, compare workers, investigate regressions, or inspect an existing xprobe artifact.
---

# Profile workloads with xprobe

Choose the shortest route supported by the question and existing evidence. Do
not run a fixed checklist or collect every source.

## Route the task

- **Existing artifact**: Read [references/trace-analysis.md](references/trace-analysis.md)
  and [references/result-quality.md](references/result-quality.md). Analyze it
  directly or use `measure --input`; skip installation, `doctor`, `discover`,
  and live attachment unless a new capture is required.
- **Known live boundary**: Read [references/cli-contract.md](references/cli-contract.md)
  and [references/result-quality.md](references/result-quality.md). Confirm PID
  plus start time, run read-only `validate`, then one bounded measurement. Do
  not run a broad inventory solely to satisfy a checklist.
- **Unknown CPU or Python workload**: Read
  [references/investigation.md](references/investigation.md). Start with bounded
  `--cpu-sample` evidence. Add `--syscall-aggregate` only for a kernel-facing
  hypothesis; validate CPython GC boundaries only for a GC hypothesis. Narrow
  from emitted selector hints rather than guessing or requiring manual symbol
  inspection first. Do not run CUDA discovery.
- **Unknown GPU or mixed workload**: Read
  [references/investigation.md](references/investigation.md). Use `discover`
  only to select CUDA context holders. Collect the relevant bounded GPU
  aggregate and, for mixed work, a bounded CPU sample inventory. Run independent
  coarse captures concurrently when an aligned workload window matters, with
  separate bounds, outputs, failures, and perturbation accounting.
- **Multiple processes**: Also read
  [references/multi-process.md](references/multi-process.md). Select explicit
  PID/start-time identities. Inventory one representative per defensible worker
  class, then run independent narrow commands concurrently where useful.
- **Setup or repair**: Read [references/setup.md](references/setup.md) only when
  a required live command is absent, incompatible, or unhealthy. Existing
  artifacts do not require a local collector.

Classify live work as CPU-only or GPU/mixed before choosing collectors. Run
`doctor` when capability is unknown or a command reports an environment
failure, not as a prerequisite for valid offline or already-diagnosed work.

## Narrow from evidence

For unknown CPU work, validate and run one representative `--cpu-sample`
window. Inspect sample loss, stack truncation, thread coverage, symbol coverage,
`python_status`, stack groups, and inclusive/exclusive hotspots. An active
Python perf map provides Python frames; `inactive` or `unsupported` does not
invalidate native frames. Use native or Python hotspot context and emitted
entry/return selector hints to form the next hypothesis.

Use `--syscall-aggregate` when CPU evidence or the question points to I/O,
allocation, scheduling, or VM behavior. Inspect unmatched/inflight/drop and map
capacity before using a group's selector hints. For suspected CPython garbage
collection, validate `python:gc_start` to `python:gc_end`; validation checks the
target's ELF USDT metadata and may reject a build without those probes.

For unknown GPU work, aggregate only relevant kernel, memcpy, or memset
families over a representative cycle. Read group counts, duration totals,
bytes, completeness, and selector hints. Scope breadth and capture duration are
independent: narrowing scope is not a substitute for retaining a representative
window.

Every hotspot or aggregate group is a hypothesis, not final attribution. Pass
the selected exact endpoints through read-only `validate`, honor its policy
recommendation explicitly, and collect one detailed bounded measurement per
stated hypothesis. A failed validation revises the hypothesis; it does not
justify unrelated collection.

## Preserve these invariants

- Use JSON mode and require schema version `2.0`. Treat malformed output and
  unknown versions as errors.
- Identify a live process by PID plus procfs start time and verify it around
  validation and attachment. Never substitute a reused PID.
- Bound every capture by duration or samples, timeout, and record/group/thread
  capacity. Preserve each command's stdout, stderr, status, and artifact.
- Before CUDA injection, disclose that `measure` will ptrace the process and
  leave the CUPTI shared object mapped. `startup_required` NVTX work must restart
  with the matching Agent before the first NVTX call.
- Inspect completeness, loss/drops, capacities, unmatched/ambiguous evidence,
  symbol and stack coverage, clock alignment, method, confidence, and evidence
  pairs before interpreting latency.
- Keep process and CUDA stream identity in every claim. Summed concurrent GPU
  duration is not wall time; temporal correlation is not exact causality.

Record a baseline when investigating regression or profiler overhead. Warm up
framework and JIT work before a representative capture. Independent CPU and GPU
inventories can run concurrently, but compare their perturbation and never
merge their distinct result contracts as if they were one timeline.

For exact GPU artifacts, run `scripts/analyze_trace.py` and inspect launch
variants, stream distribution, `busy_union_ns`, overlap factor, and gaps.
Aggregate and sampled inventories contain no event timeline and cannot be
re-correlated offline.

## Stop or hand off deliberately

Stop on target reuse, permission failure, invalid selectors, unavailable
required collectors, incomplete collection, loss/drops, or a clock/correlation
problem that invalidates the claim. Preserve structured failures and artifacts.

Once evidence isolates unexplained time inside one GPU kernel, use NCU or PC
sampling for microarchitecture. Once native sampling isolates code without an
observable boundary, use a runtime-specific profiler or instrumentation. Do not
claim xprobe identifies Python semantics when `python_status` or symbolization
coverage says otherwise.
