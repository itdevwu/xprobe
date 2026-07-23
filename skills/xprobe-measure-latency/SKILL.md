---
name: xprobe-measure-latency
description: Investigate unknown Linux CPU/CUDA latency with bounded xprobe captures, derive selectors from trace evidence, analyze multi-stream GPU activity, and measure host functions, CUDA APIs, kernels, memory copies, memory sets, and event-to-event gaps. Use when an agent must profile a running process, narrow a performance regression, inspect an xprobe JSONL artifact, or decide when duration evidence should hand off to Nsight Compute or another microarchitectural profiler.
---

# Investigate latency with xprobe

Use JSON mode to make a wide, coarse workload inventory before measuring one
boundary narrowly and finely. Read [references/setup.md](references/setup.md)
to install or repair the CLI and this Skill. Read
[references/investigation.md](references/investigation.md) before profiling an
unknown workload. Read [references/result-quality.md](references/result-quality.md)
before interpreting correlation, clocks, concurrency, or overhead. The exact
CLI and selector syntax is in [references/cli-contract.md](references/cli-contract.md).

## Workflow

1. Run `xprobe --version`. When the command is absent or not 0.3.2, read
   [references/setup.md](references/setup.md) and install or repair the CLI
   yourself; do not ask the user to perform a separate CLI installation.
   Confirm every JSON response has `schema_version: "2.0"`; do not assume a
   pre-0.3 or future protocol is compatible with this Skill.
2. Establish an application-level latency baseline. Wait for process readiness,
   CUDA context creation, JIT compilation, and warmup before discovery. Keep a
   repeatable request or batch trigger ready for the measurement window.
3. Run `xprobe doctor --json --non-interactive --no-color`. Check individual
   capabilities; `ok: true` only means diagnosis completed.
4. Run `xprobe discover --pid ROOT_PID --limit 200 --json --non-interactive
   --no-color`. It returns NVML-confirmed CUDA context holders under that process
   tree. Choose a worker from workload, PID/start-time, command line, and GPU
   UUID evidence. Measure workers separately when several ranks are relevant.
5. Map the workload before choosing a name. Validate broad kernel, memcpy, or
   memset activity endpoints, then collect one bounded, representative coarse
   inventory per event family with `--events-out`. Scope breadth and collection
   duration are independent: keep the selector broad, but choose a duration that
   covers the workload cycle being diagnosed. Give `--max-events` headroom.
6. Run `scripts/analyze_trace.py` on each coarse artifact. Use kernel names,
   selector hints, duration aggregates, launch variants, stream distribution,
   busy union, overlap factor, and adjacent gaps to form one narrow hypothesis. Read
   [references/trace-analysis.md](references/trace-analysis.md) when interpreting
   the report.
7. Run `xprobe validate --pid WORKER_PID --from SELECTOR --to SELECTOR --match
   POLICY --json --non-interactive --no-color`. Stop when `valid` is false. If
   `agent_activation` is `injection_required`, disclose that `measure` will
   ptrace the target and leave the CUPTI shared object mapped. Use
   `policy_recommendation` explicitly; xprobe never changes policy for the caller.
8. Run one bounded `xprobe measure` for that hypothesis. Set samples or duration,
   timeout, and max-events; write `--events-out` when the capture may need audit
   or offline re-correlation. Use `--spec FILE` for a versioned live configuration.
9. Check `status`, matched/unmatched/ambiguous/dropped counts, collection
   completeness, buffer utilization, clock alignment, estimated error,
   correlation method/confidence/score, warnings, and every evidence pair.
10. Repeat only with a stated reason: select another event family, narrow the
    selector, select another worker or stream, change an explicitly compatible
    policy, or test the next boundary.
    Recheck application latency after profiling and report observed overhead.

For completed captures, replace `--pid` with one or more `--input` arguments.
Begin with the [coarse kernel inventory](examples/coarse-kernel-inventory.json)
or [coarse memcpy inventory](examples/coarse-memcpy-inventory.json), then use the
[kernel duration](examples/kernel-duration.json),
[same-stream gap](examples/same-stream-kernel-gap.json),
[host span](examples/host-function-span.json), and
[memcpy duration](examples/memcpy-duration.json) specs, plus the
[CUDA synchronization API](examples/cuda-api-duration.json) shape, after
replacing target identity and selectors. Each bounded call answers one
hypothesis; orchestration remains the agent framework's responsibility.

## Stop conditions

- Stop on target reuse, permission failure, invalid selectors, unavailable
  collectors, drops, incomplete capture, unknown clock alignment, or unexamined
  ambiguity. Read structured `details`, `hints`, and any failed-capture artifact.
- Do not claim request causality from `first-after` or `nearest`. Do not compare
  or sum events across streams as if they were serial.
- Stop using xprobe once evidence isolates time inside one kernel. Kernel
  duration cannot explain warp stalls, cache misses, occupancy, instruction mix,
  or Tensor Core utilization; hand that question to NCU or PC sampling.
- Avoid continuous or repeated exploratory capture in one production process.
  Use representative bounded inventories, narrow formal measurements, and a
  post-profile baseline.
