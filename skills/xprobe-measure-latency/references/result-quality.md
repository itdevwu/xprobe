# Result quality

Prefer `exact` when CUDA endpoints carry the same CUPTI correlation ID. Prefer
`stack-nested` for entry/return pairs of the same host function. Use
`stream-order` only for GPU activity endpoints on the same device, context, and
stream. Treat `first-after` and `nearest` as temporal heuristics, never request
causality.

Inspect every evidence pair for selector scope, process identity, correlation
IDs, device/context/stream, timestamps, and clock domains. A result is not
sufficient when records were dropped, no samples matched, target identity
changed, collection was incomplete, or clock alignment failed. Report unmatched
and ambiguous counts with matched samples. `estimated_error_ns: null` means no
quantified interpolation error bound.

## Concurrency

Group GPU evidence by device, context, and stream before interpreting order.
Events on different streams may overlap and timestamp order does not establish a
request relationship. `stream-order` does not cross stream boundaries. Prefer
correlation-ID `exact` when a deterministic relationship exists.

Summed kernel or activity duration double-counts overlap. Use GPU `busy_union_ns`
for wall-clock busy time and `overlap_factor` to quantify concurrency. Compare
per-stream gaps separately. A top kernel's `summed_kernel_time_share` describes
its share of summed kernel work, not its exclusive share of wall time.

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

Use at least 2x headroom for stable narrow selectors and 4-10x for high-rate or
broad surveys. For a duration survey, size from a pilot artifact's observed
records per second. Increasing max-events without narrowing a noisy selector
only increases profiler work.

`duration-ms` limits correlation to a window beginning at the first selected
event. In live mode it also sets a collection stop from ARM completion, so finish
readiness and warmup before invoking `measure`. When both samples and duration
are set, either bound completes the call; timeout remains the outer operation and
cleanup limit.

## Perturbation

Record an application-level latency distribution before profiling and repeat it
afterward under the same workload. Report the difference and whether automatic
injection occurred. The injected shared object remains mapped but is logically
disabled after collection. Do not interpret a one-off profiled request as an
unperturbed baseline.
