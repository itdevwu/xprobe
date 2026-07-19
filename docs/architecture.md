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
        +-- host collector (eBPF, planned)
        +-- device collector (in-process CUPTI agent, planned)
        +-- correlation and exporters (planned)
```

The caller selects targets and events and interprets results. `xprobe` performs
deterministic discovery, validation, collection, correlation, statistics, and
cleanup. It does not contain an agent runtime or model integration.

## Workspace ownership

| Path | Responsibility | Current state |
| --- | --- | --- |
| `xprobe/cli` | Arguments, rendering, exit codes | `doctor`, `inspect` |
| `xprobe/core` | Deterministic environment and process logic | `doctor`, `inspect` |
| `xprobe/protocol` | Public serde types and schema generation | Implemented |
| `xprobe/collector` | Host and device collector interfaces | Skeleton |
| `xprobe/correlator` | Event matching and statistics | Skeleton |
| `xprobe/exporter` | JSONL and trace export | Skeleton |
| `xprobe/daemon` | Future privilege-separated sessions | Skeleton |
| `bpf/` | eBPF programs and build | Minimal object |
| `cupti/` | In-process CUPTI agent | ABI skeleton |

## Public contracts

All public records carry schema version `1.0`. Rust protocol types generate the
checked-in files under `schemas/`; `just schemas` regenerates them and tests
reject drift. Unknown fields and unsupported versions are rejected.

Current schemas cover:

- normalized events;
- structured errors;
- environment capabilities;
- process inspection;
- measurement specifications and results.

## Process identity

A PID alone is not a stable identity. Process operations read Linux procfs
start-time field 22 before and after inspection and represent the target as:

```text
PID + process start time in kernel clock ticks
```

A changed start time produces `TARGET_REUSED`; disappearance during inspection
produces `TARGET_EXITED`. No partial report is returned.

## Host and device collection

Host probes are designed to attach externally with eBPF. The hot path must not
perform symbol resolution, regular-expression matching, unbounded reads, or
analysis.

CUPTI callback and activity collection requires code inside the target process.
The supported direction is startup-time loading or explicit application/plugin
integration. Runtime `ptrace` plus `dlopen` injection is outside the default
architecture and requires a separate security design.

## Failure model

Expected absence is data: a missing optional kernel interface or uninstalled
tool becomes an explicit `unavailable` or `unknown` check. Unexpected I/O,
malformed procfs data, and failed required commands return errors immediately.
The implementation does not silently substitute defaults.
