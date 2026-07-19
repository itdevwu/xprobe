# Architecture

This document describes the implemented architecture and the boundaries that
new components must preserve. Future ideas live in `PLAN.md` until code and
tests make them real.

## System boundary

```text
Human or coding agent
        |
        | shell + versioned JSON
        v
xprobe CLI
        |
        | typed Rust API
        v
core inspection and measurement orchestration
        |
        +-- host collector (eBPF uprobe entry events)
        +-- device collector (in-process CUPTI agent)
        +-- Event normalization and JSONL export
        +-- clock normalization and correlation (planned)
```

The caller selects targets and events and interprets results. `xprobe` performs
deterministic discovery, validation, collection, correlation, statistics, and
cleanup. It does not contain an agent runtime or model integration.

## Workspace ownership

| Path | Responsibility | Current state |
| --- | --- | --- |
| `xprobe/cli` | Arguments, rendering, exit codes | `doctor`, `inspect`, `dev uprobe` |
| `xprobe/core` | Deterministic environment and process logic | Inspection and identity verification |
| `xprobe/protocol` | Public serde types and schema generation | Implemented |
| `xprobe/collector` | Host and device collector interfaces | Host uprobe collector and CUPTI decoder |
| `xprobe/correlator` | Event matching and statistics | Skeleton |
| `xprobe/exporter` | JSONL and trace export | Event JSONL |
| `xprobe/daemon` | Future privilege-separated sessions | Skeleton |
| `bpf/` | eBPF programs and build | PID-scoped uprobe and ring buffer |
| `cupti/` | In-process CUPTI agent | Raw launch and kernel capture |

## Public contracts

All public records carry schema version `1.0`. Rust protocol types generate the
checked-in files under `schemas/`; `just schemas` regenerates them and tests
reject drift. Unknown fields and unsupported versions are rejected.

Current schemas cover:

- normalized events;
- structured errors;
- environment capabilities;
- process inspection;
- bounded host capture results;
- measurement specifications and results.

## Process identity

A PID alone is not a stable identity. Process operations read Linux procfs
start-time field 22 before and after inspection and represent the target as:

```text
PID + process start time in kernel clock ticks
```

A changed start time produces `TARGET_REUSED`; disappearance during inspection
or collection produces `TARGET_EXITED`. The CLI verifies the identity again
after detaching the probe. No result is returned for a reused or exited target.

## Host and device collection

The implemented host collector embeds a Clang-built BPF object, loads it with
libbpf-rs, attaches one PID-scoped function-entry uprobe, and consumes fixed-size
records from a ring buffer. The target PID namespace device and inode are passed
to BPF so emitted PID/TID values match the namespace used by the CLI. Collection
stops at a caller-supplied sample limit or deadline, reports ring-buffer drops,
and detaches through Rust ownership on every return path.

The BPF hot path performs only namespace identity filtering, timestamp and CPU
capture, sequence/drop accounting, and ring-buffer submission. Symbol lookup,
JSON construction, and timeout handling remain in userspace.

CUPTI callback and activity collection runs inside the target process. The
agent subscribes only to `cudaLaunchKernel` entry/exit callbacks and concurrent
kernel activity. Both carry CUPTI correlation IDs, which provide the exact join
key between API and GPU records. Callback paths reserve slots in a bounded
in-memory array; activity parsing, draining, and binary output happen outside
the runtime API callback.

The collector decodes the fixed CUPTI ABI into the same protocol `Event` type
used by eBPF collectors. The exporter writes either source as compact JSONL.
Clock domains remain explicit; cross-domain normalization and correlation are
not yet implemented.

Supported loading paths are CUDA startup injection through
`CUDA_INJECTION64_PATH` and explicit application/plugin initialization before
the first CUDA API. Runtime `ptrace` plus `dlopen` injection is outside the
default architecture and requires a separate security design. See
[CUPTI agent](cupti-agent.md) for the raw ABI and lifecycle.

## Failure model

Expected absence is data: a missing optional kernel interface or uninstalled
tool becomes an explicit `unavailable` or `unknown` check. Unexpected I/O,
malformed procfs data, and failed required commands return errors immediately.
The implementation does not silently substitute defaults.
