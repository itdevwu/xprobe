# Multi-process workloads

xprobe has no multi-process command. Selection and concurrency stay in the
agent; each `validate` and `measure` targets one PID plus process start time.

## Select workers

Run `discover --pid ROOT` after warmup and keep the candidate records. Select
from application ownership, command line, rank, and GPU UUID, not merely
because a process holds a CUDA context. One representative stands for others
only when configuration and evidence show the same role and load. Parallel
jobs are rarely uniform: in DP2TP4, tensor-parallel peers wait on each other in
collectives, data-parallel groups can drift apart, and pipeline stages differ by
design, so capture every rank whose role or load may differ.

Name every spec, result, stderr log, and artifact with the worker's
`target.pid` and `target.process_start_time`. Never reuse an artifact path
across workers or attempts.

## Validate, then capture concurrently

Write one spec per worker with its own bounds. Validate each and require that
the response's `target` exactly matches the selected identity; a mismatch or
failure removes that worker rather than substituting a new PID. Disclose any
`injection_required` worker before measuring.

Launch one bounded `measure --spec` per worker as native concurrent tool calls
so the windows cover the same workload cycle. Wait for every command. Do not
cancel sibling commands when one fails; mark the overall experiment incomplete
and report usable per-worker results separately. To compare GPU time across
ranks, capture all activity (`stream-order`, or a triggered `--trigger-idle-ms`
capture per rank) so idle time is real.

## Compare without correlating

Do not concatenate artifacts and correlate across processes: correlation IDs,
streams, and threads are process-scoped, and overlapping timestamps do not
establish a relationship. Compare instead:

- Per-worker distributions, only when selectors, phase, and device assignment
  match; read each result's quality independently.
- Per-GPU time budgets of several artifacts from one host:

  ```bash
  scripts/analyze_trace.py rank0.jsonl rank1.jsonl rank2.jsonl rank3.jsonl
  ```

  Over the window every input covers, each rank's GPU (by UUID) gets busy,
  idle, compute, and communication-only time. A rank with more compute and
  less communication-only time is the one its collective peers wait for.
  Artifacts from different hosts have unrelated clocks; compare their shares,
  never their timestamps.

Concurrent captures perturb shared resources; record a workload baseline and
reduce the worker set if throughput changes materially.
