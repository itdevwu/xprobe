# Selectors, policies, and specs

Prefer selectors that xprobe emitted: triage `next.spec`, inventory
`*_selector_hint` fields, and analyzer `selector_hint`. Write one by hand only
when no emitted hint covers the boundary, and pass it through `validate`.

## Selector syntax

| Source | Selector |
| --- | --- |
| Native function | `uprobe:<binary>:<symbol>:entry\|return` |
| C++ signature with `::` | `uprobe:<binary>:symbol=<full-demangled-signature>:entry\|return` |
| Stripped or local code | `uprobe:<binary>:+0x<file-offset>:entry\|return` |
| Syscall | `syscall:<name>:entry\|exit` |
| Kernel tracepoint | `tracepoint:<category>:<name>` (identity and timestamp only) |
| CPython GC | `python:gc_start`, `python:gc_end` |
| CUDA API | `cuda:runtime_api\|driver_api:<name>:entry\|exit` |
| GPU activity | `cuda:kernel_start\|kernel_end[:name~REGEX]`, `cuda:memcpy_start\|memcpy_end[:kind=HtoD\|DtoH\|DtoD\|HtoH\|PtoP]`, `cuda:memset_start\|memset_end` |
| NVTX range | `cuda:nvtx_range_start\|nvtx_range_end:name~REGEX` |

CUDA API selectors need a concrete Runtime or Driver API name. Kernel and NVTX
regexes are filtered in the CUPTI hot path only when they reduce to an exact,
prefix, suffix, or contains literal under 128 bytes; anything else is applied
after a broader capture and fills capacity faster. Escape regex metacharacters.
A `name_complete: false` kernel group carries a truncated prefix: keep its
prefix hint and do not add an end anchor.

## Derive a native boundary

Use a CPU sample hotspot's `entry_selector_hint` and `return_selector_hint`
first. Without one, inspect the mapped object of this target:

```bash
readlink -f "/proc/$PID/exe"
grep -F ' r-xp ' "/proc/$PID/maps"
readelf -Ws /path/to/object
nm -D --defined-only --demangle /path/to/object
```

Use a symbol when one exists; otherwise derive a file offset with `readelf` or
`objdump`. Never reuse a runtime virtual address as a file offset, and never
reuse a C++ signature, offset, or generated kernel name across builds without
validating it again.

For eager PyTorch, prefer sampled boundaries in CPython, `torch._C`, or a
loaded libtorch object, such as `at::_ops::<operator>::call(...)` with
`stack-nested`. After `torch.compile` or Triton warmup, fused work no longer
sits inside eager operator boundaries: select by kernel name instead. Generated
CPU code without a file-backed ELF symbol cannot be a uprobe target.

For CPython GC, check capability, not the process name: `validate` resolves the
USDT markers in the mapped interpreter or `libpython` and rejects builds without
them. Do not substitute a guessed symbol.

```bash
xprobe validate --pid "$PID" --from python:gc_start --to python:gc_end --match exact
```

## Choose a policy

| Policy | Use for | Confidence |
| --- | --- | --- |
| `exact` | Same CUPTI correlation ID (API ↔ its kernel or copy), kernel/copy start ↔ end, NVTX range ID, one syscall's entry ↔ exit on a thread, CPython GC start ↔ end | exact |
| `stack-nested` | Entry ↔ return of one host function per thread | high |
| `stream-order` | Activity end ↔ next start on one device stream | high |
| `first-after`, `nearest` | Host marker ↔ GPU activity and other unrelated sources | heuristic |

`validate` reports `policy_recommendation` with a reason and the compatible
set; xprobe never changes the requested policy silently. Heuristic policies
never establish request-level causality.

## Specs

A single-edge `MeasurementSpec` (schema `2.0`) pins the target identity and
bounds; triage emits ready ones, and `examples/` holds templates. Run it with
`measure --spec FILE`.

A measurement graph (schema `3.0`) names endpoints once and measures up to
eight edges from one capture. See `examples/request-path-graph.json`. Rules:

- 1–8 endpoints and 1–8 edges; every edge sets `samples` or the graph sets
  `duration_ms`; `max_events` bounds the whole capture.
- At most two syscall, tracepoint, or USDT endpoints; uprobe endpoints are not
  limited further; CUDA endpoints share eight Agent filters.
- `validate --spec graph.json` reports issues scoped to the graph, an endpoint,
  or an edge. Any failing edge fails `measure`; the artifact is still written.

## Capacity

Start an exact capture with modest record headroom:
`max_events ≈ 2 × samples × (records per start + records per end)` plus
expected unmatched records. Triage specs size capacity from the observed rate.
On `EVENT_RATE_TOO_HIGH`, narrow the selector before raising `max_events`, and
keep the window representative.
