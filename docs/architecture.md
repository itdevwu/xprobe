# Architecture

This document describes the implemented xprobe 0.2.0 architecture.

## Boundary

```text
human or coding agent
        |
        | doctor -> discover -> validate -> measure
        | versioned JSON
        v
xprobe CLI
        |
        +-- core: procfs identity, ELF discovery/resolution, validation, injection
        +-- collector: PID-scoped eBPF and CUPTI snapshots
        +-- correlator: bounded pairing, quality, statistics, evidence
        +-- exporter: JSONL and Chrome trace artifacts
        v
running process or completed capture files
```

There is no daemon and no persistent session API. A foreground `measure` owns
attachment, collection, correlation, logical CUPTI shutdown, and cleanup.

## Workspace

| Path | Responsibility |
| --- | --- |
| `xprobe/cli` | Four public commands, rendering, exit codes, orchestration |
| `xprobe/core` | doctor, process identity, discovery, ELF resolution, validation, ptrace injection |
| `xprobe/protocol` | Strict serde contracts and generated JSON Schema |
| `xprobe/collector` | eBPF collection, CUPTI control protocol and ABI decoding |
| `xprobe/correlator` | Selector matching, pair evidence, statistics and quality |
| `xprobe/exporter` | Event JSONL and Chrome Trace Event Format |
| `bpf/` | PID-scoped uprobe/uretprobe programs |
| `cupti/` | Reusable in-process CUDA callback/activity agent |

## Identity and discovery

A target identity is its PID plus `/proc/<pid>/stat` start time. xprobe verifies
that pair before and after metadata operations and attachment. PID reuse returns
`TARGET_REUSED`; disappearance returns `TARGET_EXITED`.

`discover` reads the executable and mapped ELF libraries. It emits bounded
entry/return selectors for text symbols, CUDA Runtime/Driver callback selectors
for exported API symbols, and CUPTI activity templates for kernels, memcpy, and
memset. Discovery does not attach. GPU activity templates are marked as
requiring observation because static ELF metadata cannot enumerate future
kernel names.

Host selector resolution converts ELF virtual addresses through load segments
to file offsets, then through `/proc/<pid>/maps` to runtime addresses. This
supports executables, PIE, and shared libraries without assuming that a mapping
base is a symbol address.

## Validation

`validate` is read-only. It resolves host selectors, parses CUDA selectors,
checks correlation-policy compatibility, and reports eBPF, CUPTI, callback,
activity, and clock requirements. CUPTI activation is one of:

- `not_required`
- `already_loaded`
- `injection_required`

`injection_required` keeps validation valid when all semantic requirements are
met, sets `target_mutation: true`, and emits `TARGET_PROCESS_WILL_BE_MODIFIED`.
Malformed selectors, unresolved symbols, invalid policies, and unavailable
required host collection remain explicit issues or errors.

## Collection

Host events use libbpf-rs with one PID-scoped uprobe or uretprobe per unique
host endpoint. The BPF path only filters identity, records monotonic timestamps
and CPU/TID, updates bounded counters, and submits fixed records. Rust ownership
detaches links on every return path.

CUDA events use an in-process CUPTI Agent. CUDA 12 and CUDA 13 builds share the
same source and capture ABI but link `libcupti.so.12` and `libcupti.so.13`
respectively. CUDA 12 decodes Kernel9 records; CUDA 13 selects Kernel10,
Kernel11, or Kernel12 from the runtime CUPTI version. The Agent subscribes to
Runtime and Driver API callbacks and concurrent kernel, memcpy, and memset activity. Callbacks
write fixed records to a bounded 65,536-slot array without blocking I/O. CUPTI
activity timestamps are normalized to `CLOCK_MONOTONIC` through its timestamp
callback or an explicit CUDA 12 clock calibration. Before each capture is
written, activity timestamps must fall within the bounded Agent activation and
snapshot window. The ABI host-monotonic feature flag is cleared when that check
fails, preserving GPU same-domain durations while preventing cross-domain
subtraction.

The Unix socket control protocol has two commands: snapshot and stop. Stop
flushes final activity, returns the final capture, disables activities,
unsubscribes callbacks, closes and unlinks the socket, and leaves the shared
object mapped. A later measurement resets the bounded buffers and subscribes
again.

## Online injection

When CUDA collection is required and no compatibility socket was supplied,
`measure` derives the major from mapped CUPTI/CUDART libraries and selects the
matching installed Agent. It then uses ptrace on Linux x86_64. It resolves target `malloc`, `free`,
`dlopen`, and `dlsym`, executes them on one stopped target thread, and calls
`xprobe_cupti_agent_start` with a private socket path. Each remote call saves and
restores registers and the touched stack word. An unexpected trap, timeout, or
syscall error fails explicitly; the cleanup path restores target state before
detach.

The target must share xprobe's mount namespace so the agent path has the same
meaning. ptrace policy, credentials, and LSMs still apply. xprobe warns on
stderr and records `CUPTI_AGENT_INJECTED` in the result. It never `dlclose`s the
agent because unloading callback code in a live CUDA process is unsafe.

## Correlation and evidence

All sources normalize into the versioned `Event` type. `measure` supports:

| Policy | Pairing | Confidence |
| --- | --- | --- |
| `exact` | CUPTI correlation ID | exact |
| `first-after` | First unused end at or after each start | heuristic |
| `nearest` | Nearest unused end by timestamp | heuristic |
| `stack-nested` | Per-thread LIFO host entry/return | high |
| `stream-order` | Ordered activity within device/context/stream | high |

Every result includes full matched start/end events and `latency_ns` in
`evidence`. Statistics are derived from those pairs. Drops, unmatched events,
ambiguity, policy, confidence, and clock quality remain visible. A normalized
CUPTI event without a reported interpolation bound makes
`estimated_error_ns: null` and emits `CLOCK_ERROR_UNAVAILABLE`.

## Contracts and failure model

Public records use schema version `1.0`; generated schemas are checked in and
tested for drift. Unknown fields and unsupported versions fail deserialization.
Expected capability absence is represented as available/restricted/unavailable
data. Unexpected I/O, malformed procfs/ELF/capture data, target changes,
collector errors, and cleanup failures return errors rather than partial
success.
