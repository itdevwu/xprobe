# Trace analysis

Run the bundled analyzer on an Event JSONL artifact:

```bash
skills/xprobe-measure-latency/scripts/analyze_trace.py capture.jsonl \
  > capture-analysis.json
```

The command rejects non-2.0 events, clock-domain mismatches within an activity,
and negative durations. Unpaired activity boundaries remain visible in
`events` and produce a warning; they are excluded from duration metrics.

Read the report in this order:

1. `events`: confirm counts and zero unpaired starts/ends.
2. `gpu.busy_union_ns`: wall-clock union of kernel, memcpy, and memset activity.
3. `gpu.summed_activity_ns` and `overlap_factor`: quantify overlap; do not use
   summed activity as wall time when the factor is above 1.
4. `kernels.by_name`: rank total time, then inspect p50/p95 and
   `summed_kernel_time_share`.
5. `launch_variants`: separate the same kernel name by grid/block shape before
   concluding that its latency distribution is homogeneous.
6. `streams`: compare activity counts and adjacent kernel gaps per
   PID/device/context/stream. Cross-stream order is not causal evidence.
7. `memcpy.by_kind`: inspect transfer duration and bytes separately from kernel
   work.

`selector_hint` is exact for names shorter than the CUPTI filter bound. For long
names it may be a prefix or suffix unique only among names observed in that
capture; validate it and repeat a narrow measurement before treating it as
stable. Analyze every broad inventory separately; the report never establishes
wall-clock relationships between distinct capture windows.

The analyzer reports descriptive activity timing. It does not assign work to a
request, calculate kernel hardware efficiency, or turn temporal proximity into
causality.
