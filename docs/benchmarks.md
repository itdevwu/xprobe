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

For aggregate inventory changes, run:

```bash
just benchmark-aggregate
```

This benchmark keeps a two-kernel CUDA workload at a high event rate and
captures it once as raw exact events and once into a four-slot aggregate table.
It fails unless both captures are complete and drop-free, the aggregate count
exceeds table capacity without saturation, and exactly two groups are retained.
It also requires aggregate capture to use less collector CPU, collector peak
RSS, target-process RSS growth, and artifact space than raw broad capture.

The resource comparison uses `wait4` for collector CPU and peak RSS and samples
target RSS from procfs while the command runs. It deliberately does not gate on
short GPU throughput windows: device clock changes can make those samples move
opposite to profiler overhead. The JSON output includes every asserted resource
and collection value so regressions remain diagnosable.

Run the agent-orchestrated worker benchmark with:

```bash
just benchmark-multiprocess
```

Fresh homogeneous batches of one, two, and four CUDA workers are discovered by
PID plus start time. One representative worker supplies a broad aggregate
inventory; its selector hints are validated for every worker before independent
spec-based measurements start concurrently. The benchmark rejects identity
changes, missing injection warnings, path reuse, non-overlapping commands,
incomplete captures, and drops.

Its JSON keeps validation, command timing, quality, artifact metadata, and
baseline-versus-collection throughput per worker. Perturbation is reported
without a fixed pass ratio because shared GPU scheduling and first injection
cost vary by workload and worker count.
