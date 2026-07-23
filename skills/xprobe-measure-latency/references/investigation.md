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
For multiple relevant workers, follow [multi-process.md](multi-process.md):
inventory a representative worker where homogeneity is defensible, then run
independent narrow captures concurrently. After a restart, rerun discovery and
use PID plus procfs start time; never reuse an old PID-only choice.

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
  --aggregate --duration-ms "$REPRESENTATIVE_WINDOW_MS" \
  --timeout-ms "$TIMEOUT_MS" --max-groups "$MAX_GROUPS" \
  --json --non-interactive --no-color > coarse-kernels.json
```

Map copies and memsets in separate bounded captures when they could matter:

```bash
xprobe validate --pid "$PID" \
  --from cuda:memcpy_start --to cuda:memcpy_end --match exact \
  --json --non-interactive --no-color

xprobe measure --pid "$PID" \
  --from cuda:memcpy_start --to cuda:memcpy_end --match exact \
  --aggregate --duration-ms "$REPRESENTATIVE_WINDOW_MS" \
  --timeout-ms "$TIMEOUT_MS" --max-groups "$MAX_GROUPS" \
  --json --non-interactive --no-color > coarse-memcpy.json
```

Do not guess a named kernel or host function in this stage. CUDA API selectors
require a concrete Runtime or Driver API name, so inventory activity first and
choose API boundaries from application, framework, or trace evidence later.
Read each inventory separately. Use its selector hints to start the next exact
measurement; device-specific groups may still need workload-level GPU routing.

Treat group capacity as a consequence of workload diversity, not event rate.
On `EVENT_RATE_TOO_HIGH`, split event families or reduce selector scope while
retaining a representative cycle; reduce duration only when the remaining
window is still representative. Aggregate mode never returns partial output.

## Derive CUDA selectors

Use `kernels.by_name` and `selector_hint` from the analysis report. Kernel
selectors accept a regular expression, but the CUPTI hot path can lower only a
short exact, prefix, suffix, or contains literal (under 128 characters). Complex
regex is applied after a broader capture and may fill capacity quickly. Escape
regex metacharacters and validate the final selector.

For Triton and other JIT kernels, use captured names plus grid/block variants to
identify a launch family, then correlate it with framework cache metadata,
generated source, or application logs. xprobe does not read JIT cache contents
and cannot select by grid/block. Use each aggregate group's emitted selector
hint directly. A `name_complete: false` group contains a bounded observed prefix
and therefore emits a prefix hint; do not add an exact end anchor. When a hint
still covers several groups, derive a shorter observed-unique prefix or
contains literal and validate it before collection.

## Derive CPU selectors

Choose the narrowest observable boundary supported by existing evidence. For a
function, resolve the mapped object in the target and inspect its symbols:

```bash
readlink -f "/proc/$PID/exe"
cat "/proc/$PID/maps"
readelf -Ws /path/to/object
nm -D --defined-only /path/to/object
nm -D --defined-only --demangle /path/to/cpp-object
```

Use `uprobe:<binary>:<symbol>:entry|return` when a symbol is available. For
an exact C++ signature containing `::`, use
`uprobe:<binary>:symbol=<full-demangled-signature>:entry|return`; validation
returns both the mangled attach name and readable signature. For stripped or
local code, derive a file offset with `readelf`/`objdump` and use
`uprobe:<binary>:+0xOFFSET:entry|return`. Always pass the exact candidate to
`validate`; do not infer a runtime virtual address from one process and reuse it
as a file offset.

For eager PyTorch, inspect the mapped CPython executable, `torch._C`, and the
loaded libtorch objects. Prefer an exported dispatcher or native operator
signature observed in that exact installed build, such as an
`at::_ops::<operator>::call(...)` boundary, and validate both entry and return
before measuring with `stack-nested`. Treat `_PyEval_EvalFrameDefault` only as a
broad interpreter boundary; xprobe does not turn it into Python function names.

After `torch.compile` or Triton warmup, do not assume an eager operator boundary
still encloses the fused work. Inventory CUDA kernels first and narrow using
the emitted kernel names. Generated CPU code without a stable file-backed ELF
symbol is not a valid uprobe target. Never reuse a C++ signature, mangled name,
file offset, or generated kernel name across PyTorch builds without resolving
and validating it again.

For kernel-facing latency, first use application logs, `/proc` state, or a
bounded syscall summary to identify a candidate. Then validate
`syscall:NAME:entry` to `syscall:NAME:exit` with `exact`. Use
`tracepoint:CATEGORY:NAME` only when the kernel event itself is the intended
boundary. Do not start an unknown high-rate workload with unfiltered raw
syscall tracepoints: select first, then collect detailed evidence.

## Measure one narrow hypothesis

Choose one next boundary from evidence:

- kernel start to end with `exact` for kernel duration;
- CUDA API exit to kernel start with `exact` for launch delay;
- kernel end to next activity start with `stream-order` for one-stream gaps;
- host function entry to return with `stack-nested` for CPU span;
- named syscall entry to exit with `exact` for kernel-facing latency;
- host marker to GPU activity with `first-after` only as a disclosed heuristic.

After capture, analyze the artifact and all result quality fields. An aggregate
inventory cannot be re-correlated because it intentionally contains no events.
Collect one exact artifact for the selected hypothesis, then use
`measure --input` when only selectors or policy change.

```bash
xprobe measure --pid "$PID" \
  --from 'cuda:kernel_start:name~^selected_kernel$' \
  --to 'cuda:kernel_end:name~^selected_kernel$' \
  --match exact --samples 100 --max-events 200000 \
  --events-out selected-kernel.jsonl --format jsonl \
  --json --non-interactive --no-color

skills/xprobe-measure-latency/scripts/analyze_trace.py selected-kernel.jsonl \
  > selected-kernel-analysis.json
```

## Escalate at the right boundary

xprobe can isolate slow kernels, launch gaps, copies, synchronization boundaries,
host spans, and host-to-GPU timing. Once the remaining time is inside a single
kernel, use NCU or PC sampling for stalls, cache behavior, occupancy, instruction
mix, or Tensor Core utilization. Use a CPU sampling profiler when the unresolved
time is inside an uninstrumented host span.
