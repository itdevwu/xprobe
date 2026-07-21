# Result quality

Prefer `exact` when both CUDA endpoints carry the same CUPTI correlation ID.
Prefer `stack-nested` for entry/return pairs of the same host function and
`stream-order` for activity endpoints on the same device, context, and stream.
Treat `first-after` and `nearest` as temporal heuristics.

A result is not sufficient evidence when records were dropped, no samples
matched, the selected process identity changed, or clock alignment failed.
Report unmatched and ambiguous counts alongside matched samples. For a broad
selector, state that another eligible event could have changed the pairing.

Compare latency values only when the result reports a shared or normalized clock
domain. Report `estimated_error_ns`; `null` means no quantified interpolation
error bound. Inspect the full start and end events in every `evidence` pair when
checking selector scope, correlation IDs, streams, and timestamps.

`completed` means the requested bound was reached. `timed_out` may still contain
useful partial evidence, but it must be identified as partial.
