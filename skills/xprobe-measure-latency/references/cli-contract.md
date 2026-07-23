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
uprobe:<binary>:+0x<file-offset>:entry
uprobe:<binary>:+0x<file-offset>:return
```

CUDA selectors cover Runtime and Driver API entry/exit plus kernel, memcpy, and
memset activity start/end. Kernel activity accepts `name~REGEX`; memcpy accepts
`kind=<HtoD|DtoH|DtoD|HtoH|PtoP>`. `validate` must accept the complete selector
and policy before measurement.

## Correlation

Use `exact` for CUDA events with the same CUPTI correlation ID,
`stack-nested` for entry/return of the same host function, and `stream-order`
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

Kernel and other GPU activity durations require separate start and end records,
so `max-events` is record capacity rather than sample capacity. Sample completion
is checked after bounded snapshots and does not reserve space in the CUPTI
buffer. `duration-ms` limits correlation from the first selected event and also
sets a live stop from ARM completion; either samples or duration may complete a
call when both are present. Timeout bounds the complete foreground operation and
cleanup.

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
does not unload the shared object.
