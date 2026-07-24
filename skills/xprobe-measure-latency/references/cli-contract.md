# CLI contract

xprobe exposes four public commands: `doctor`, `discover`, `validate`, and
`measure`. Use `--json --non-interactive --no-color` with every command. JSON
responses carry `schema_version: "2.0"`; diagnostics and the injection warning
go to stderr. Pre-0.3 schema versions are not maintained in parallel.

## Discovery and selectors

`discover --pid ROOT_PID` lists only NVML-confirmed CUDA context holders in the
root's process tree. Choose a worker from its PID, start time, command line, and
GPU UUID evidence before validation. The CLI does not choose one automatically.

Host function selectors use:

```text
uprobe:<binary>:<symbol>:entry
uprobe:<binary>:<symbol>:return
uprobe:<binary>:symbol=<full-demangled-c++-signature>:entry
uprobe:<binary>:symbol=<full-demangled-c++-signature>:return
uprobe:<binary>:+0x<file-offset>:entry
uprobe:<binary>:+0x<file-offset>:return
```

Use the `symbol=` form for a C++ name containing `::`; pass the complete
demangled signature. Validation returns the actual mangled ELF symbol and the
readable signature. This resolves native code mapped by a Python process, not
Python frame or `module.qualname` names.

Linux selectors use `syscall:<name>:entry|exit` and
`tracepoint:<category>:<name>`. Syscall entry/exit for one name supports
`exact` per-thread lifecycle matching. Entry evidence contains scalar ABI
register values and exit evidence contains the scalar return value; xprobe
does not dereference pointers. Named tracepoints contain no payload fields.
Always let `validate` resolve the named syscall or tracepoint on the current
host before measurement.

CUDA selectors cover Runtime and Driver API entry/exit; kernel, memcpy, and
memset activity start/end; and bounded NVTX range start/end. Kernel activity
accepts `name~REGEX`; memcpy accepts `kind=<HtoD|DtoH|DtoD|HtoH|PtoP>`. NVTX
uses `cuda:nvtx_range_start:name~REGEX` and
`cuda:nvtx_range_end:name~REGEX`; the regex must reduce to an exact, prefix,
suffix, or contains match shorter than 128 bytes. `validate` must accept the
complete selector and policy before measurement.

## Correlation

Use `exact` for CUDA events with the same CUPTI correlation ID, NVTX boundaries
with the same range kind and ID, or entry/exit of one named syscall.
Use `stack-nested` for entry/return of the same host function and `stream-order`
for activity events on one CUDA stream. `first-after` and `nearest` are temporal
heuristics and cannot establish causality. Read `policy_recommendation.policy`,
its machine-readable `reason`, and `compatible_policies`; xprobe never silently
changes the requested policy.

## Bounds and failures

Direct `measure` calls require a positive `--samples` or `--duration-ms` bound.
`--timeout-ms` defaults to 30 seconds and `--max-events` to 100,000. Use exactly
one source mode: `--pid`, one or more `--input` files, or `--spec`.

Use `measure --aggregate --duration-ms ... --max-groups ...` for a live, coarse
kernel, memcpy, or memset inventory. Aggregate endpoints must be one matching
activity start/end pair with `--match exact`. The result contains bounded group
counts, total/min/max/mean duration, transfer bytes, selector hints, and table
quality. It contains no event evidence, percentiles, or correlation confidence;
`--samples`, `--input`, and `--events-out` are invalid in this mode.
Kernel regex must be an exact, prefix, suffix, or contains shape that the Agent
can apply before aggregation; other regex is rejected instead of widened.
Kernel groups expose `name_complete`. When it is false, the observed name is a
bounded prefix and the emitted selector hints deliberately remain prefix
selectors that the Agent can apply before reserving exact events.

Kernel and other GPU activity durations require separate start and end records,
so `max-events` is record capacity rather than sample capacity. Sample completion
is checked after bounded snapshots and does not reserve space in the CUPTI
buffer. `duration-ms` limits correlation from the first selected event and also
sets a live stop from ARM completion; either samples or duration may complete a
call when both are present. Timeout bounds the complete foreground operation and
cleanup.

Linux syscall filtering runs in BPF before event reservation. A duration-bound
host capture that reaches `max-events` fails with `EVENT_RATE_TOO_HIGH`; narrow
the selector or increase the explicit bound. Do not replace it with partial
evidence.

`--events-out PATH` atomically writes the bounded capture with mode `0600`, not
only matched evidence. Collection completeness and CUPTI capacity, observed,
retained, dropped, and buffer utilization fields describe capture integrity
separately from correlation confidence. Correlation or clock failure after
collection still writes the artifact and reports its metadata in error
`details`; inspect it before retrying.

Exit status `0` means the command emitted a result. Status `1` is validation,
collection, decode, export, cleanup, or internal failure; `2` is invalid CLI
syntax; `3` means the target disappeared or was reused; and `4` is a permission
failure. Treat every nonzero status as an explicit failure and read its JSON
error code, message, details, and hints.

Validation is read-only. When it reports `injection_required`, the following
live `measure` may ptrace the target and load the matching CUDA 12 or CUDA 13
CUPTI Agent. Measurement disables the Agent logically after collection but
does not unload the shared object. When validation reports `startup_required`
for an NVTX selector, restart the worker with `NVTX_INJECTION64_PATH` pointing
to that Agent before its first NVTX call, reacquire its PID plus start time, and
validate again. Online injection cannot install NVTX dispatch after NVTX has
initialized.
