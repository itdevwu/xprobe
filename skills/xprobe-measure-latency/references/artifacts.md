# Artifacts and how to read them

Each result has a schema under `schemas/` with every field's definition. This
page maps the fields an analysis usually needs and the traps in reading them.
Compute what your question needs from these fields; no summary here replaces
the raw evidence.

## Measurement result and graph result

- `measurement.latency_ns` (min, mean, p50–p99, max) and `samples` (`matched`,
  `unmatched_start`, `unmatched_end`, `ambiguous`, `dropped`). A graph result
  repeats both per entry of `edges`.
- `quality.verdict` and `quality.issues[].code`: `HEURISTIC_CORRELATION` and
  `AMBIGUOUS_*` mean temporal or non-unique pairing; `UNMATCHED_EVENTS`
  suggests selector scope or window edges; `FEW_SAMPLES` means tail ranks rest
  on under 100 pairs; `CAPTURE_COVERAGE_UNKNOWN` and
  `STREAM_COVERAGE_UNVERIFIED` mean the capture may not hold every activity.
- `correlation.method` and `confidence`; `clock.alignment` and
  `estimated_error_ns`.
- `collection.coverage` (`source`, `all_gpu_activity`), `collection.cupti`
  (capacity, drops), and `collection.cuda_devices`, which maps each
  process-local CUDA `device_id` to a GPU UUID.
- `evidence.exemplars` (rank pairs inline), `evidence.pairs` with
  `--evidence full`, and `evidence.artifact.path`, the Event JSONL.

`timed_out` statistics are partial. `--duration-ms` counts from the first
selected event, so warm up before measuring. Drops, no matched pairs, a changed
target, and clock misalignment are errors, never results.

## Event JSONL and its manifest

One event per line: `timestamp_ns`, `clock_domain`, `pid`, `tid`, `source`,
`event_type`, `sequence`, and a payload: `cuda` (`device_id`, `context_id`,
`stream_id`, `correlation_id`, `kernel_name`, `grid`, `block`, `bytes`,
`memcpy_kind`), `nvtx`, or `host`. GPU activity is two records, a start and an
end with the same `correlation_id`.

- Compare timestamps only within one clock domain; `host_monotonic` and
  `cupti_normalized_to_host_monotonic` share `CLOCK_MONOTONIC`, raw `cupti`
  does not. Within a timestamp, `sequence` is the record order.
- A stream gap (one stream's end to its next start) is not device idle time:
  another stream may run meanwhile. Device idle is the gap in the union of
  every stream's activity on one device of one process.
- Records at the capture edges may lack their other boundary; such activity
  ran before or after the capture, not zero time.
- `device_id` is the process's CUDA ordinal (renumbered by
  `CUDA_VISIBLE_DEVICES`); name GPUs across processes by UUID.

`<artifact>.manifest.json` records the target, the `CLOCK_MONOTONIC` window,
armed selectors, `all_gpu_activity`, losses, `cuda_devices`, and the artifact's
SHA-256. Idle time is trustworthy only when `all_gpu_activity` is true, since
a narrow selector hides the activity it filtered out. Keep the manifest beside
the artifact; `measure --input` restores losses and coverage from it.

## Inventories

- **CPU sample** (`--cpu-sample`): `hotspots` (self and inclusive shares,
  `entry_selector_hint`, `return_selector_hint`), `stack_groups` (whole stacks
  with counts), and collection counters: lost samples, truncation, thread
  coverage, resolved frames, and `python_status`. Shares are sampled
  estimates; `inactive` or `unsupported` Python status means native frames
  only.
- **Syscall aggregate**: per syscall count, errors, and exact summed, min, and
  max duration; no order or percentiles. Blocked time includes idle waiting.
- **GPU aggregate** (`--aggregate`): per kernel name, copy kind, or memset and
  `device_id`, count and duration totals, bytes, and copy `src_memory` and
  `dst_memory` (`pageable` means staged copies). Summed durations double-count
  overlap; there is no ordering.
- **Python sample** (`--python-sample`): `inventory.gil_hotspots` and
  `gil_stacks` as shares of GIL ticks, `gil_released_proportion`, all-thread
  stacks, and `native_waits`; `collection` holds achieved rates,
  `inconsistent_reads`, `tid_source`, and read latency. Its JSONL artifact has
  one record per sample: `timestamp_ns` (`CLOCK_MONOTONIC`), `pid`, `tid`,
  `gil`, `frames` (innermost first, `first_line` is where a function starts),
  and `native` for blocked threads.

## Triggered capture result

`trigger` (kind and threshold), `observed` (spans evaluated, over threshold,
the longest), and `windows`: each with its firing span, `start_ns`, `end_ns`,
`truncated`, longest spans, and its own Event JSONL plus manifest.
`collection` counts ring overwrites, drops, `lost_windows`, and
`revoked_windows`. `TRIGGER_NOT_OBSERVED` is a result: `longest_ns` bounds every
span seen. Kinds: `idle` is device idle, `gap` a stream gap, `duration` one
activity, `latency` one edge.

## Triage result

Triage runs several sources over one window and applies fixed rules. Use it as
a broad first look:

- `sources[]` says which inventories ran; an `unavailable` source and every
  `not_covered` item are questions triage did not answer.
- The inline inventories (`threads`, `cpu_hotspots`, `syscalls`,
  `gpu_activity`, `gpu_devices` with `cuda_devices`, `python_hotspots`) and the
  per-source artifacts are the evidence; read them directly.
- `findings` are rule-based hints ranked by an estimated `impact_share`; a
  `null` share cannot be bounded. Confirm one with a direct measurement before
  reporting it.
- `gpu_devices` utilization is NVML's device-wide estimate, including other
  processes. GPU findings cover only GPUs the target ran work on.

## Analyzer output

`scripts/analyze_trace.py ARTIFACT` reads one Event JSONL and its manifest:

- `devices[]`: per process, device, and clock, the span, `busy_ns`, `idle_ns`,
  `compute_ns`, `communication_ns`, `communication_only_ns`, `transfer_ns`,
  `top_idle_gaps`, and `top_compute_gaps`. Communication kernels match
  `--comm-kernel` (default `^nccl`), a naming heuristic; NCCL kernels spin
  while waiting, so `busy` includes waiting for peers.
- `kernels`, `memcpy` (with `bandwidth_gbps`), `streams[].top_gaps`, and
  `gpu.top_idle_gaps`.
- `--measurement RESULT` ranks the slowest pairs; `--slice-gap N`,
  `--slice-outlier N`, or `--around START:END` lists events in a window, and
  `--python-samples FILE` adds the Python stacks sampled inside it. Events in a
  window are concurrent with it, not proven causes.

Several artifacts compare instead: per-device budgets over the window every
input covers, with `shares` and a `spread` of compute share. On a collective,
the rank computing longest is the one its peers wait for. Only artifacts of one
host share a clock.

## Perturbation

Profiling changes the workload. Record an application baseline, report whether
the CUPTI Agent was injected (it stays mapped but disabled), and treat a
materially slower profiled run as a reason to narrow selectors or shorten the
window.
