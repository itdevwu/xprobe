# Architecture

This document describes the implemented xprobe architecture.

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
| `bpf/` | PID-scoped uprobe, syscall, and named tracepoint programs |
| `cupti/` | Reusable in-process CUDA callback/activity agent |

## Identity and discovery

A target identity is its PID plus `/proc/<pid>/stat` start time. xprobe verifies
that pair before and after metadata operations and attachment. PID reuse returns
`TARGET_REUSED`; disappearance returns `TARGET_EXITED`.

`discover` queries NVML compute processes, verifies each PID's ancestry under
the requested process-tree root, and returns only confirmed CUDA context
holders with stable process identity, parent PID, command line, and GPU UUIDs.
It does not attach and does not choose a worker. That orchestration belongs to
the calling Agent or user. A multi-process investigation uses one bounded
command per selected PID/start-time identity; concurrency and per-worker failure
handling remain in the caller, and event correlation never crosses processes.

Host selector resolution converts ELF virtual addresses through load segments
to file offsets, then through `/proc/<pid>/maps` to runtime addresses. This
supports executables, PIE, and shared libraries without assuming that a mapping
base is a symbol address. Raw ELF names are matched without demangling the
symbol table. A full C++ signature uses the explicit `symbol=` selector form;
the resolver checks exported dynamic symbols first, falls back to the complete
table, and returns both the attachable mangled name and readable signature.

## Validation

`validate` is read-only. It resolves ELF probes and Linux syscall numbers,
parses named tracepoint and CUDA selectors, checks correlation-policy
compatibility, and reports eBPF, CUPTI, callback, activity, and clock
requirements. CUPTI activation is one of:

- `not_required`
- `already_loaded`
- `injection_required`

`injection_required` keeps validation valid when all semantic requirements are
met, sets `target_mutation: true`, and emits `TARGET_PROCESS_WILL_BE_MODIFIED`.
Malformed selectors, unresolved symbols, invalid policies, and unavailable
required host collection remain explicit issues or errors.

## Collection

Host events use libbpf-rs. ELF functions attach one PID-scoped uprobe or
uretprobe per unique endpoint. Linux syscall endpoints share raw
`sys_enter`/`sys_exit` links and compare up to two configured x86_64 syscall
numbers after PID-namespace filtering. Only matching entries read the six
scalar ABI registers; exits retain the scalar return value. Pointer-referenced
memory is never read.

Named tracepoints attach by category and name and retain timestamp, PID/TID,
CPU, and selector identity without copying payload fields. The two endpoint
links are armed together after attachment, so setup events cannot enter the
capture. Linux records use a `--max-events`-sized ring buffer and fixed record
layout. Ring exhaustion, scalar-read failure, malformed records, and
duration-capacity exhaustion remain explicit failures. Rust ownership detaches
all links on every return path.

CUDA events use an in-process CUPTI Agent. CUDA 12 and CUDA 13 builds share the
same source and capture ABI but link their matching CUPTI SONAME. Loading the
Agent creates a control socket; `measure` separately arms one fresh,
`--max-events`-bounded capture with filters for its CUDA endpoints. Runtime and
Driver callbacks plus kernel, memcpy, and memset activity are filtered before
fixed records consume capacity. Callback hot paths do not perform blocking I/O
or allocation.

Broad GPU inventory uses the same `measure` primitive with aggregate mode. The
Agent updates a `--max-groups`-bounded table for matching kernel, memcpy, or
memset activity and returns only final count/duration/byte summaries. Exact
measurement remains the evidence path; aggregate output has a separate result
contract and cannot be exported as event JSONL.

CUPTI activity timestamps are normalized to `CLOCK_MONOTONIC` through its
timestamp callback or an explicit CUDA 12 clock calibration. Activity that
began before the ARM epoch is excluded. The Agent verifies the retained window
before setting the host-monotonic ABI feature, preserving GPU same-domain
durations while preventing invalid cross-domain subtraction.

Snapshot flushes and reads only records after a checked caller watermark. The
CLI rejects noncontiguous offsets and counter rollback while accumulating the
bounded capture. Stop flushes the final delta and disables CUPTI but retains an
externally managed socket for a later ARM. Automatically injected collection
closes its private socket after the final capture. Neither path unloads the
shared object.

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
| `exact` | CUPTI correlation ID or same-thread syscall lifecycle | exact |
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

Public records use schema version `2.0`; generated schemas are checked in and
tested for drift. Unknown fields and unsupported versions fail deserialization.
Expected capability absence is represented as available/restricted/unavailable
data. Unexpected I/O, malformed procfs/ELF/capture data, target changes,
collector errors, and cleanup failures return errors rather than partial
success.
