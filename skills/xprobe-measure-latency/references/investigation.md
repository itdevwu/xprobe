# Investigation playbook

## Coordinate the workload

Wait for the service readiness signal, CUDA context creation, framework warmup,
and JIT compilation. Run `discover` only after the target has submitted CUDA
work. Start a bounded measurement immediately before a controlled request/batch,
or while repeatable traffic is active. A quiet target commonly produces
`NO_MATCHED_SAMPLES`; it is not evidence that the selector is invalid.

Keep launcher and worker roles separate. `discover --pid ROOT_PID` reports only
CUDA context holders, so a wrapper PID should not be selected unless it appears
as a candidate. Map GPU UUID and command/rank metadata to workload ownership.
Measure multiple relevant workers one at a time. After a restart, rerun discovery
and use PID plus procfs start time; never reuse an old PID-only choice.

## Map broadly before selecting

When kernel names are unknown, first validate and collect all kernel activity.
Choose `REPRESENTATIVE_WINDOW_MS` to cover one steady-state request, batch, or
iteration cycle, not an arbitrarily short interval. The capture is always
bounded; its duration must still preserve the behavior being diagnosed.

```bash
xprobe validate --pid "$PID" \
  --from cuda:kernel_start --to cuda:kernel_end --match exact \
  --json --non-interactive --no-color

xprobe measure --pid "$PID" \
  --from cuda:kernel_start --to cuda:kernel_end --match exact \
  --duration-ms "$REPRESENTATIVE_WINDOW_MS" --timeout-ms "$TIMEOUT_MS" \
  --max-events "$MAX_EVENTS" --events-out coarse-kernels.jsonl --format jsonl \
  --json --non-interactive --no-color

skills/xprobe-measure-latency/scripts/analyze_trace.py coarse-kernels.jsonl \
  > coarse-kernels-analysis.json
```

Map copies and memsets in separate bounded captures when they could matter:

```bash
xprobe validate --pid "$PID" \
  --from cuda:memcpy_start --to cuda:memcpy_end --match exact \
  --json --non-interactive --no-color

xprobe measure --pid "$PID" \
  --from cuda:memcpy_start --to cuda:memcpy_end --match exact \
  --duration-ms "$REPRESENTATIVE_WINDOW_MS" --timeout-ms "$TIMEOUT_MS" \
  --max-events "$MAX_EVENTS" --events-out coarse-memcpy.jsonl --format jsonl \
  --json --non-interactive --no-color
```

Do not guess a named kernel or host function in this stage. CUDA API selectors
require a concrete Runtime or Driver API name, so inventory activity first and
choose API boundaries from application, framework, or trace evidence later.
Analyze each artifact separately; busy union only describes the capture window
inside that artifact.

Treat capacity as a consequence of observed event rate, not a universal default.
On `EVENT_RATE_TOO_HIGH`, inspect the written artifact and error counters. First
split event families or reduce selector scope while retaining a representative
cycle; reduce duration only when the remaining window is still representative.
Preserve the artifact as evidence for the change.

## Derive CUDA selectors

Use `kernels.by_name` and `selector_hint` from the analysis report. Kernel
selectors accept a regular expression, but the CUPTI hot path can lower only a
short exact, prefix, suffix, or contains literal (under 128 characters). Complex
regex is applied after a broader capture and may fill capacity quickly. Escape
regex metacharacters and validate the final selector.

For Triton and other JIT kernels, use captured names plus grid/block variants to
identify a launch family, then correlate it with framework cache metadata,
generated source, or application logs. xprobe does not read JIT cache contents
and cannot select by grid/block. Long mangled names should be narrowed to a
short, observed-unique literal instead of copied wholesale.

## Derive host selectors

Resolve the mapped object in the target, then inspect its symbols:

```bash
readlink -f "/proc/$PID/exe"
cat "/proc/$PID/maps"
readelf -Ws /path/to/object
nm -D --defined-only /path/to/object
```

Use `uprobe:<binary>:<symbol>:entry|return` when a symbol is available. For
stripped or local code, derive a file offset with `readelf`/`objdump` and use
`uprobe:<binary>:+0xOFFSET:entry|return`. Always pass the exact candidate to
`validate`; do not infer a runtime virtual address from one process and reuse it
as a file offset.

## Measure one narrow hypothesis

Choose one next boundary from evidence:

- kernel start to end with `exact` for kernel duration;
- CUDA API exit to kernel start with `exact` for launch delay;
- kernel end to next activity start with `stream-order` for one-stream gaps;
- host function entry to return with `stack-nested` for CPU span;
- host marker to GPU activity with `first-after` only as a disclosed heuristic.

After capture, analyze the artifact and all result quality fields. Re-correlate a
completed artifact with `measure --input` when only selectors or policy change;
do not attach again merely to recompute pairing.

```bash
xprobe measure --input coarse-kernels.jsonl \
  --from 'cuda:kernel_start:name~^selected_kernel$' \
  --to 'cuda:kernel_end:name~^selected_kernel$' \
  --match exact --samples 100 --max-events 200000 \
  --json --non-interactive --no-color
```

## Escalate at the right boundary

xprobe can isolate slow kernels, launch gaps, copies, synchronization boundaries,
host spans, and host-to-GPU timing. Once the remaining time is inside a single
kernel, use NCU or PC sampling for stalls, cache behavior, occupancy, instruction
mix, or Tensor Core utilization. Use a CPU sampling profiler when the unresolved
time is inside an uninstrumented host span.
