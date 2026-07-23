# Multi-process workloads

Keep process selection and concurrency in the agent framework. xprobe has no
multi-process command: each `validate` and `measure` remains an independent,
bounded invocation for one stable target identity.

## Select workers

Run one `discover` after workload warmup and retain the full candidate records
used for selection. Select workers from application ownership, command/rank
metadata, GPU UUIDs, and the intended experiment. Do not select every candidate
merely because it owns a CUDA context.

Treat workers as homogeneous only when application configuration and observed
workload evidence support that claim. For a homogeneous rank set, use one
representative worker for each broad aggregate inventory. Derive narrow
selectors from that inventory, then apply those selectors to every selected
worker. For heterogeneous workers, inventory one representative per defensible
class or investigate workers separately.

Record each selected candidate's exact `target.pid` and
`target.process_start_time`. Name every spec, result, stderr log, and event
artifact with both values. Never reuse an artifact path across workers or
attempts.

## Revalidate identity

Create one narrow Measurement Spec per selected worker. Copy its full discovery
identity into `target`; give every spec its own samples or duration,
`timeout_ms`, and `max_events`. Capacities are per worker, never a shared budget.

Issue one read-only `validate` call per selected worker, concurrently when the
agent framework supports concurrent tool calls. Before any mutation, require
that each validation response is valid and that its `target` exactly matches
the selected PID and `process_start_time`. Preserve each validation JSON and its
warnings. A mismatch, exit, or failed validation removes that worker from the
measurement batch; do not replace it with a newly observed PID.

When validation reports `injection_required`, disclose and retain that worker's
mutation warning. Do not preload or repeatedly broad-profile all ranks merely
to make injection look uniform. Injection completes before that worker's ARM
window, but its application-level startup perturbation still belongs in the
report.

## Capture concurrently

After every selected identity has passed validation, launch one bounded
`xprobe measure --spec WORKER_SPEC` per selected worker using native concurrent
tool calls from the agent framework. Start the calls in one concurrency batch
so their capture windows cover the same controlled request, batch, or iteration
cycle. Do not serialize the commands unless the investigation explicitly needs
different workload windows.

Keep these outputs separate for every worker:

- spec with the discovered target identity;
- validation JSON and stderr;
- measurement JSON and stderr;
- exact Event JSONL artifact when requested;
- command exit status and start/end wall timestamps.

Wait for every command. Do not cancel sibling commands or discard successful
outputs when one worker fails. Preserve injection warnings, configured capacity,
collection quality, and the structured error for each worker. Mark the overall
experiment incomplete when any selected worker fails, while describing usable
single-worker evidence separately.

## Interpret without merging

Read every result's status, completeness, drops, utilization, ambiguity, clock,
correlation, and evidence independently. Compare per-worker distributions only
after checking that selectors, workload phase, device assignment, and quality
are comparable.

Do not concatenate artifacts and rerun correlation across processes. CUPTI
correlation IDs, CUDA contexts, streams, host thread identity, and process
clocks are process-scoped evidence; overlapping wall timestamps do not establish
cross-process causality. Report variation or concurrent observation, not an
exact relationship between worker events.

Measure an application baseline before the batch and again afterward. Report
per-worker command startup time and workload throughput during collection.
Concurrent captures can perturb shared CPU, GPU, storage, and driver resources,
so a result that changes the workload materially needs a smaller worker set,
narrower selectors, or a shorter but still representative window.
