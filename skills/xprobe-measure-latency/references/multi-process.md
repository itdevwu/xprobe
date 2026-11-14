# Multi-process workloads

xprobe has no multi-process command. Selection and concurrency stay in the
agent; each `validate` and `measure` targets one PID plus process start time.

## Select workers

Run `discover --pid ROOT` after warmup and keep the candidate records. Select
from application ownership, command line, rank, and GPU UUID, not merely
because a process holds a CUDA context. For workers that configuration and
evidence show to be homogeneous, triage one representative worker and reuse its
selectors; otherwise treat each class separately.

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
and report usable per-worker results separately.

On one worker, a CPU sample inventory and GPU aggregate may also run as two
concurrent commands with separate bounds and outputs. Prefer triage when one
window must cover both.

## Interpret without merging

Read each result's quality independently and compare per-worker distributions
only when selectors, phase, and device assignment match. Do not concatenate
artifacts and correlate across processes: correlation IDs, streams, and threads
are process-scoped, and overlapping timestamps do not establish a relationship.
Concurrent captures perturb shared resources; record a workload baseline and
reduce the worker set if throughput changes materially.
