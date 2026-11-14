# Interpreting results

Each result type has its own schema under `schemas/`; field meanings live
there. This page covers how to read them without overclaiming.

## Triage

- `findings` are ranked by `impact_share`, an estimated share of the window.
  `null` means the evidence cannot bound the impact (clock limits, PCIe link);
  such findings rank last but may still matter.
- `threads.top_threads` splits each whole-window thread into on-CPU, runqueue,
  and blocked time. Blocked time includes idle waiting, so a mostly idle
  thread pool is normal; read the busiest threads, not process totals.
- `gpu_devices` utilization is NVML's device-wide sampled estimate and includes
  other processes on the GPU. `gpu_activity` lists the target's kernels with
  summed durations, which double-count overlap.
- Full CPU, syscall, and GPU inventories are written to the artifacts listed in
  `sources`; read them when the inline top five are not enough.

## Exact measurements and graphs

Start from `quality.verdict`:

| Issue | Severity | Meaning |
| --- | --- | --- |
| `TIMED_OUT`, `INCOMPLETE_SESSION` | caution | Partial statistics |
| `HEURISTIC_CORRELATION`, `AMBIGUOUS_CORRELATION`, `AMBIGUOUS_PAIRS` | caution | Pairing is temporal or not unique |
| `UNMATCHED_EVENTS` | caution when unmatched exceed matched, else info | Selector scope or window edges |
| `CLOCK_ERROR_LARGE` | caution | Clock error ≥ 10% of p50 |
| `CLOCK_ERROR_UNAVAILABLE` | info | CUPTI gave no interpolation bound |
| `FEW_SAMPLES` | info | Tail ranks rest on < 100 pairs |

Drops, no matched pairs, target changes, incomplete collection, and clock
misalignment are command errors, never results. Inspect the rank exemplars for
selector scope, thread or stream identity, and correlation IDs; use
`--evidence full` or the artifact when a claim depends on individual pairs.

`completed` means the samples or duration bound was reached; `timed_out` is
partial. `duration-ms` measures from the first selected event and starts after
the capture is armed, so finish warmup before invoking `measure`.

## Inventories

CPU sampling, syscall aggregation, and GPU aggregation are separate contracts;
do not compare their capacities or completeness as one collector.

- CPU samples: check lost samples, stack truncation, thread coverage, group
  table use, and resolved native, Python, and unresolved frame counts before
  using hotspot names. Proportions are sampled estimates. `python_status`
  `inactive` or `unsupported` means native fallback; native frames remain
  valid, Python semantics are not claimed.
- Syscall aggregation: durations are exact for matched lifecycles, but groups
  have no order or percentiles; check unmatched, inflight, and drops.
- GPU aggregation: count, summed, min, max, and mean duration and bytes per
  group; no ordering, overlap, or correlation.

## GPU concurrency

Group GPU evidence by device, context, and stream. Events on different streams
overlap, and their order is not a request relationship. For wall-clock GPU
busy time, run the bundled analyzer on an exact Event JSONL artifact:

```bash
scripts/analyze_trace.py capture.jsonl > capture-analysis.json
```

Use `gpu.busy_union_ns` for wall-clock busy time and `overlap_factor` to see
concurrency; summed activity is not wall time when the factor exceeds 1.
`launch_variants` separates one kernel name by grid and block shape, and
`streams` reports per-stream counts and adjacent gaps. The analyzer describes
one capture window; it never relates distinct windows or assigns work to
requests.

## Perturbation

Profiling changes the workload. Record an application-level baseline before
and after, report whether the CUPTI Agent was injected (it stays mapped but
disabled), and treat a materially slower profiled run as a reason to narrow
selectors or shorten the window rather than as the answer.
