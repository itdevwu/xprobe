---
name: xprobe-measure-latency
description: Measure bounded latency between Linux host functions, CUDA Runtime or Driver APIs, GPU kernels, memory copies, and memory sets with the xprobe CLI. Use for request-to-GPU latency, launch delay, GPU activity duration, and evidence-based host-to-GPU investigations without restarting or modifying a running target.
---

# Measure latency with xprobe

Use the checked-in CLI and JSON schemas as the contract. Keep every collection
bounded and preserve the target process unless the user explicitly approves a
different lifecycle.

## Workflow

1. Run `xprobe doctor --json --non-interactive --no-color`. Read individual
   capability checks; `ok: true` does not mean every capability is available.
2. Run `xprobe inspect --pid PID --json --non-interactive --no-color`. Save both
   `target.pid` and `target.process_start_time`; stop if either changes later.
3. Resolve every host selector with `xprobe resolve`. CUDA selectors are checked
   by `validate` and do not require symbol resolution.
4. Run `xprobe validate --pid PID --from SELECTOR --to SELECTOR --match POLICY
   --json --non-interactive --no-color`. Do not collect while `valid` is false.
5. Choose the narrowest selectors and strongest valid correlation policy. Read
   [references/result-quality.md](references/result-quality.md) before using a
   temporal or cross-clock policy.
6. Run a bounded foreground `measure`, or write a versioned MeasurementSpec and
   run `trace --spec`. Always set `samples` or `duration_ms`, plus `timeout_ms`
   and `max_events` where the command supports them.
7. Check `status`, matched and unmatched samples, ambiguous samples, dropped
   events, clock alignment, estimated timestamp error, correlation method,
   confidence, and every warning before interpreting latency.
8. Let the foreground command finish cleanup. Verify no collector remains after
   interruption or failure. Base the conclusion only on returned measurements
   and explicitly state quality limitations.

Use `examples/request-to-first-kernel.json` as a spec shape after replacing the
target identity and selectors with values established from the live process.

## Safety

- Do not restart, inject into, signal, or modify a target process without explicit
  user approval. A missing CUPTI Agent is a reported prerequisite, not permission
  to alter the process.
- Do not attach when `validate` reports an unresolved selector, reused PID,
  insufficient permission, or unavailable required collector.
- Do not use unbounded sample counts, durations, event rates, or memory limits.
- Do not claim exact causality for `first-after` or `nearest` correlation.
- Do not ignore `EVENTS_DROPPED`, `HIGH_UNMATCHED_RATE`, clock warnings, or a
  `timed_out` result.

For stable exit codes and error envelopes, read
`docs/cli-contract.md` in the xprobe repository.
