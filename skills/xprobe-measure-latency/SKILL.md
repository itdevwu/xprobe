---
name: xprobe-measure-latency
description: Profile live or recorded Linux CPU and NVIDIA CUDA workloads with bounded xprobe evidence. Use when an agent needs to install or repair xprobe, inspect an existing xprobe JSONL artifact, inventory unknown CPU/GPU activity, validate and measure a known function, syscall, CUDA API, kernel, transfer, synchronization point, NVTX range, or event-to-event latency, compare selected worker processes, investigate a performance regression, or decide when to hand an isolated kernel or host span to another profiler.
---

# Profile workloads with xprobe

Choose the shortest route that answers the user's question. Do not run the full
investigation playbook when the target, selectors, or completed artifact already
provide the missing evidence.

## Route the task

- **Existing artifact**: Read [references/trace-analysis.md](references/trace-analysis.md)
  and [references/result-quality.md](references/result-quality.md). Analyze the
  artifact directly or use `measure --input` to test compatible selectors or a
  policy. Skip installation, `doctor`, `discover`, and live attachment unless a
  separate live capture is actually needed.
- **Known live boundary**: Read [references/cli-contract.md](references/cli-contract.md)
  and [references/result-quality.md](references/result-quality.md). Confirm the
  target identity, validate the supplied selectors, and run a bounded measure.
  Do not run a broad inventory solely to satisfy a checklist.
- **Unknown CPU workload**: Read
  [references/investigation.md](references/investigation.md), classify the
  suspected host boundary, and narrow from application, symbol, syscall, or
  tracepoint evidence. Do not run CUDA discovery.
- **Unknown GPU or mixed workload**: Read
  [references/investigation.md](references/investigation.md). Establish
  readiness, discover CUDA context holders, collect only the broad bounded
  inventories needed by the question, derive selectors from evidence, then
  validate and measure narrowly.
- **Multiple processes**: Also read
  [references/multi-process.md](references/multi-process.md). Select relevant
  PID/start-time identities and run independent bounded commands concurrently
  when aligned capture windows matter. Keep every result and artifact separate.
- **Setup or repair**: Read [references/setup.md](references/setup.md) only when
  live commands are needed and the CLI is absent, incompatible, or unhealthy.
  A completed-artifact analysis does not require a local collector.

For live work, classify the selected path as CPU-only or GPU/mixed before
choosing collectors. Run `doctor` when capability is unknown or a command
reports an environment failure; it is not a prerequisite for every valid
offline or already-diagnosed workflow.

## Preserve these invariants

- Use JSON mode and require schema version `2.0`. Treat malformed output and
  unknown schema versions as errors.
- Identify each live target by PID plus procfs start time. Recheck the identity
  around validation and attachment; never substitute a newly observed PID.
- Run read-only `validate` before every live measurement or target mutation.
  Use its explicit policy recommendation, but never change policy silently.
- Bound every capture by samples or duration, timeout, and exact-event or
  aggregate-group capacity. Scope breadth and capture duration are independent.
- When validation reports `injection_required`, disclose that `measure` will
  ptrace the process and leave the CUPTI shared object mapped. When it reports
  `startup_required` for NVTX, restart with the matching Agent before the first
  NVTX call; online injection cannot retrofit initialized NVTX dispatch.
- Inspect status, collection completeness, buffer utilization, unmatched,
  ambiguous, and dropped counts, clock alignment and estimated error,
  correlation method, confidence, and every evidence pair before interpreting
  a result.
- Keep stream and process identity in every claim. Summed concurrent GPU
  duration is not wall time; temporal correlation is not exact causality.

## Choose collection depth from evidence

Use broad-to-narrow collection when selectors are unknown. Keep the broad scope
representative but collect aggregate kernel, memcpy, or memset families only
when they could answer the current question. Use selector hints, counts,
duration totals, transfer bytes, and bounds to state a narrower hypothesis.

When a trustworthy selector is supplied by the user, application, an NVTX
range, a previous artifact, or a matching build's symbol inspection, validate
it directly. A failed validation is evidence to revise the selector; it is not
a reason to run unrelated inventories.

Use one bounded live capture per stated hypothesis when source activation or
capture windows differ. A single exact Event JSONL artifact may support several
offline correlations without reattaching. Independent worker captures or
non-conflicting hypotheses may run concurrently when the caller can preserve
their bounds, outputs, failures, and perturbation separately.

Record an application baseline when the question concerns a regression,
slowdown, or profiler overhead. Warm up readiness-sensitive framework/JIT work
before selecting a representative window. Do not require a new baseline for
schema validation or a purely offline artifact question.

For exact GPU artifacts, run `scripts/analyze_trace.py` and inspect launch
variants, stream distribution, `busy_union_ns`, overlap factor, and adjacent
gaps. Aggregate output has no event ordering and cannot be re-correlated.

## Stop or hand off deliberately

Stop on target reuse, permission failure, invalid selectors, unavailable
required collectors, drops, incomplete capture, or a clock/correlation problem
that invalidates the intended claim. Preserve failed-capture artifacts and
structured details instead of reporting partial success. A quality limitation
that does not affect the requested same-domain claim may be reported explicitly
rather than treated as a universal stop condition.

Stop using xprobe once evidence isolates unexplained time inside one kernel;
use NCU or PC sampling for microarchitectural behavior. Use a CPU sampling
profiler when the unresolved time is inside an uninstrumented host span.
