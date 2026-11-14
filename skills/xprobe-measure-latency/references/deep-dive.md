# Dig deeper

Use this when triage or the first exact measurement does not explain the
latency. Each step names the evidence that triggers it, the next bounded
command, and when to stop. Escalate one step at a time.

## Triage found nothing actionable

1. **Missing sources.** Read every `sources` entry. An `unavailable` syscall or
   CPU source usually means missing BPF or perf permission; fix it through
   [setup](setup.md) and triage again. Silence from a missing source is not
   evidence of absence.
2. **Window missed the slow work.** Triage covers one window. If the problem is
   intermittent or per-request, drive one slow request during the window or
   lengthen `--duration-ms` to cover several cycles.
3. **Triage omits transfers.** GPU activity in triage covers kernels only.
   Inventory copies and memsets explicitly; groups with `src_memory` or
   `dst_memory` of `pageable` point at host buffers to pin:

   ```bash
   xprobe measure --pid "$PID" --from cuda:memcpy_start --to cuda:memcpy_end \
     --match exact --aggregate --duration-ms 2000 --max-groups 256
   ```

4. **CPU time is spread thin.** A `CPU_BOUND` finding without a single hotspot
   needs more samples or semantic frames. Raise frequency and duration, and for
   CPython 3.12+ restart the target with `-X perf` so samples resolve to Python
   functions:

   ```bash
   xprobe measure --pid "$PID" --cpu-sample --duration-ms 5000 \
     --frequency-hz 499 --max-samples 50000 --max-groups 512
   ```

   Read `stack_groups`, not only `hotspots`: inclusive callers show which
   high-level operation owns the spread-out leaf time.

## A span is slow but unexplained

Split the span into sub-edges with one measurement graph instead of repeated
single captures. Choose intermediate endpoints from the sampled stacks (callee
`entry_selector_hint` and `return_selector_hint`), CUDA API boundaries, or NVTX
ranges, then compare edge p50/p99:

```json
"edges": [
  {"name": "request_to_launch", "from": "request", "to": "launch_exit",
   "match_policy": "first_after", "samples": 200},
  {"name": "launch_to_kernel", "from": "launch_exit", "to": "kernel_start",
   "match_policy": "exact", "samples": 200}
]
```

The edge whose latency carries the regression is the next span to split. Edges
are independent pairings; they show where time is spent per edge, not that one
edge caused another.

For a host function, descend one stack level at a time: measure the function
with `stack-nested`, then the heaviest callee from the CPU sample stack groups.
Stop when a callee no longer carries most of the parent's time.

## Only the tail is slow

1. Read the `p99` and `max` exemplars: their thread, stream, timestamps, and
   CUDA correlation IDs identify concrete slow instances.
2. Open the evidence artifact (`evidence.artifact.path`) and list events that
   overlap those instances in time: GC lifecycles, syscalls, other kernels on
   the same stream. Report them as concurrent, not causal.
3. Re-correlate the same artifact with other selectors or policies through
   `measure --input` before recapturing; a new capture is needed only for
   endpoints the artifact does not contain.
4. If the tail is rare, raise `samples` so p99 rests on at least a few hundred
   pairs, and check the `FEW_SAMPLES` quality issue.

## Threads are blocked

Triage reports how long threads were blocked, not where. Narrow it:

- `SYSCALL_TIME` points at a syscall; measure it exactly
  (`syscall:NAME:entry` to `syscall:NAME:exit`). `futex` time indicates lock
  or condition waits; `poll`, `epoll_wait`, `read`, and `recvfrom` indicate
  I/O or idle event loops, so compare against the workload's expected idle.
- In CPython, validate `python:gc_start` to `python:gc_end` and measure GC
  lifecycles when blocked or tail time coincides with allocation-heavy phases.
- In CUDA workloads, measure `cudaStreamSynchronize` or `cudaDeviceSynchronize`
  entry to exit; long synchronization means the CPU waits on the GPU, so return
  to the GPU findings.
- Lock owner and off-CPU stack attribution are not covered by this release;
  say so instead of guessing.

## It is a regression

Run the same spec or graph on the baseline and the regressed build or host,
with the same workload phase, window, and bounds. Compare per-edge
distributions (p50, p90, p99), matched counts, and quality verdicts. A changed
`quality` issue or capacity pressure on one side makes the comparison
unreliable; fix that before attributing the difference.

## Hand off

- Time isolated inside one kernel: NCU or PC sampling for occupancy, memory,
  and instruction stalls.
- Time isolated in code without an attachable boundary (JIT, generated, or
  inlined code): a runtime-specific profiler or added instrumentation such as
  an NVTX range or an exported function boundary.
- Python semantics unavailable (`python_status` not `active`): py-spy or the
  framework profiler, reported as a separate tool's evidence.
