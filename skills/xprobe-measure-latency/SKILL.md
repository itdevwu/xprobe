---
name: xprobe-measure-latency
description: Discover, validate, and measure bounded latency between Linux host functions, CUDA Runtime or Driver APIs, GPU kernels, memory copies, and memory sets with the four-command xprobe CLI. Use for launch delay, request-to-GPU latency, GPU activity duration, and evidence-based profiling of a running PID or completed captures.
---

# Measure latency with xprobe

Use JSON mode and keep collection bounded. Read
[references/cli-contract.md](references/cli-contract.md) for selector and exit
semantics. Read [references/result-quality.md](references/result-quality.md)
before using temporal correlation or normalized clocks.

## Workflow

1. Run `xprobe doctor --json --non-interactive --no-color`. Check individual
   capabilities; `ok: true` only means diagnosis completed.
2. Run `xprobe discover --pid PID --query TEXT --limit 200 --json
   --non-interactive --no-color`. Select the narrowest returned host or CUDA
   selectors. Activity templates marked `requires_observation` are valid event
   classes, not proof that the target will emit them.
3. Run `xprobe validate --pid PID --from SELECTOR --to SELECTOR --match POLICY
   --json --non-interactive --no-color`. Stop when `valid` is false. If
   `agent_activation` is `injection_required`, disclose that `measure` will
   ptrace the target and leave the CUPTI shared object mapped.
4. Run one bounded `xprobe measure --pid PID --from SELECTOR --to SELECTOR
   --match POLICY --samples N --timeout-ms MS --json --non-interactive
   --no-color`. Use `--events-out PATH [--format jsonl|chrome]` when an artifact
   is needed. For a versioned configuration, use `xprobe measure --spec FILE`.
5. Check `status`, matched/unmatched/ambiguous/dropped counts, clock alignment,
   `estimated_error_ns`, correlation method/confidence/score, every warning,
   and each `evidence` pair before interpreting latency.

For completed captures, replace `--pid` with one or more `--input` arguments.
Use `examples/request-to-first-kernel.json` as a `MeasurementSpec` shape after
replacing the target identity and selectors with values from `discover`.

## Guardrails

- Do not use unbounded collection. Set samples or duration, timeout, and a
  finite event limit.
- Do not continue after target reuse, permission failure, invalid selectors, or
  unavailable required collectors.
- Expect a warning on automatic CUPTI injection. Do not suppress or misreport
  target mutation; do not manually unload the mapped agent afterward.
- Do not claim exact causality for `first-after` or `nearest`.
- Do not ignore drops, unmatched or ambiguous pairs, unknown clock error, or a
  `timed_out` status.
