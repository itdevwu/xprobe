# Result quality

Prefer `exact` when CUDA endpoints carry the same CUPTI correlation ID or when
one named syscall has entry/exit records from the same thread and process
identity. CPython GC exact matching likewise requires ordered start/end markers
on the same thread and process identity. Prefer `stack-nested` for entry/return pairs of the same host
function. Use `stream-order` only for GPU activity endpoints on the same device,
context, and stream. Treat `first-after` and `nearest` as temporal heuristics,
never request causality.

Inspect every evidence pair for selector scope, process identity, correlation
IDs, device/context/stream, timestamps, and clock domains. A result is not
sufficient when records were dropped, no samples matched, target identity
changed, collection was incomplete, or clock alignment failed. Report unmatched
and ambiguous counts with matched samples. `estimated_error_ns: null` means no
quantified interpolation error bound.

Inventory modes are separate contracts:

- For CPU sampling, require `completeness: complete`, zero lost samples,
  `observed_samples == grouped_samples`, acceptable stack truncation, expected
  thread coverage, and reasonable group-table utilization. Read native,
  Python, and unresolved frame counts before using hotspot names. Sample
  proportions have sampling uncertainty and are not exact time shares.
- For syscall aggregation, require `completeness: complete`, zero dropped
  aggregates, acceptable unmatched/inflight counts, and reasonable group-table
  utilization. Durations are exact for retained matched lifecycles, but groups
  contain no event order or percentiles.
- For GPU aggregate inventory, require `completeness: complete`, zero dropped
  activities, equal observed and grouped activity counts, and reasonable table
  utilization. Min/max/mean derive from integer totals, but there is no event
  ordering, stream overlap, or correlation evidence.

Do not compare capacities or completeness fields across these schemas as if
they described the same collector.

## Concurrency

Group GPU evidence by device, context, and stream before interpreting order.
Events on different streams may overlap and timestamp order does not establish a
request relationship. `stream-order` does not cross stream boundaries. Prefer
correlation-ID `exact` when a deterministic relationship exists.

Summed kernel or activity duration double-counts overlap. Use GPU `busy_union_ns`
for wall-clock busy time and `overlap_factor` to quantify concurrency. Compare
per-stream gaps separately. A top kernel's `summed_kernel_time_share` describes
its share of summed kernel work, not its exclusive share of wall time.

For multi-process captures, keep every result and artifact scoped to its PID
plus process start time. Compare worker summaries only after checking individual
quality and workload alignment. Do not merge Event JSONL files for correlation:
timestamp overlap, matching names, or matching correlation IDs across processes
does not establish causality. Preserve partial command failures instead of
silently reporting only successful workers.

## Bounds and completion

`completed` means either requested samples or duration was reached. `timed_out`
is partial and must be reported as such. For one complete kernel duration, start
and end consume at least two CUPTI records; unmatched boundaries and records
admitted by a broad hot-path filter consume additional capacity. Sample
completion is evaluated from snapshots, so a high-rate buffer can reach
`max-events` before the caller observes the requested sample count.

For narrow start/end activity pairs, begin with:

```text
minimum_records = samples * (start_records_per_sample + end_records_per_sample)
max_events >= minimum_records + expected_unmatched_records
```

Use at least 2x headroom for stable narrow selectors. For broad aggregate
inventory, size `max-groups` from expected operation or syscall diversity rather
than event rate. For CPU sampling, size `max-samples` from frequency times
duration, `max-threads` from target fanout, `stack-depth` from expected call
depth, and `max-groups` from stack diversity. Keep enough duration to cover a
representative cycle; saturation or sample loss is an explicit quality failure.

`duration-ms` limits correlation to a window beginning at the first selected
event. In live mode it also sets a collection stop from ARM completion, so finish
readiness and warmup before invoking `measure`. When both samples and duration
are set, either bound completes the call; timeout remains the outer operation and
cleanup limit.

## Perturbation

Record an application-level latency distribution before profiling and repeat it
afterward under the same workload. Report the difference and whether automatic
injection occurred. The injected shared object remains mapped but is logically
disabled after collection. For mixed concurrent inventories, report each
collector's wall time, available CPU/RSS observations, and combined workload
throughput. Do not interpret a one-off profiled request as an unperturbed
baseline or claim universal superiority over another profiler.
