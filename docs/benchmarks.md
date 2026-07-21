# Precision and overhead benchmarks

Run the reproducible GPU benchmark with the pinned CUDA devel image:

```bash
just benchmark-gpu
```

The benchmark uses the actual visible GPU and reports one JSON document. It
compares the duration of a dedicated kernel from CUPTI Activity with an
independent CUDA Event measurement. It also compares the median host wall time
with and without the CUPTI Agent for two workloads: five rounds of 1,000 empty
kernel launches, and five rounds of 200 approximately 1 ms kernels.

The run fails on malformed captures, unknown or dropped records, a precision
error above `max(250 us, 10%)`, or an overhead ratio above `25x`. The broad
overhead limit catches broken instrumentation. The empty-launch result is a
high-event-rate stress metric. The paced workload verifies its observed event
rate is below 10,000 events/s before reporting whether the current `<2%`
engineering target was met. That target is an observation, not a compatibility
promise, and should be evaluated on representative applications as well.

The output records the GPU name, driver, compute capability, workload shape,
reference and CUPTI durations, error, baseline and instrumented medians, overhead
ratio, ABI metadata, and drop counters. Keep complete JSON output with benchmark
results; do not label a run by a GPU model inferred from machine documentation.
