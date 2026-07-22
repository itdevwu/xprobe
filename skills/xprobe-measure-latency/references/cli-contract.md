# CLI contract

xprobe exposes four public commands: `doctor`, `discover`, `validate`, and
`measure`. Use `--json --non-interactive --no-color` with every command. JSON
responses carry `schema_version: "1.0"`, while `discover` process-candidate
results carry `"2.0"`; diagnostics and the injection warning go to stderr.

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
heuristics and cannot establish causality.

## Bounds and failures

Direct `measure` calls require a positive `--samples` or `--duration-ms` bound.
`--timeout-ms` defaults to 30 seconds and `--max-events` to 100,000. Use exactly
one source mode: `--pid`, one or more `--input` files, or `--spec`.

Exit status `0` means the command emitted a result. Status `1` is validation,
collection, decode, export, cleanup, or internal failure; `2` is invalid CLI
syntax; `3` means the target disappeared or was reused; and `4` is a permission
failure. Treat every nonzero status as an explicit failure and read its JSON
error code, message, details, and hints.

Validation is read-only. When it reports `injection_required`, the following
live `measure` may ptrace the target and load the matching CUDA 12 or CUDA 13
CUPTI Agent. Measurement disables the Agent logically after collection but
does not unload the shared object.
