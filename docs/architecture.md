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
        +-- CUPTI-to-host clock normalization
        +-- completed-capture correlation and statistics
```

The caller selects targets and events and interprets results. `xprobe` performs
deterministic discovery, validation, collection, correlation, statistics, and
cleanup. It does not contain an agent runtime or model integration.

## Workspace ownership

| Path | Responsibility | Current state |
| --- | --- | --- |
| `xprobe/cli` | Arguments, rendering, exit codes | `doctor`, `inspect`, `resolve`, development capture commands |
| `xprobe/core` | Deterministic environment and process logic | Inspection, identity verification, ELF probe resolution |
| `xprobe/protocol` | Public serde types and schema generation | Implemented |
| `xprobe/collector` | Host and device collector interfaces | Host uprobe collector and CUPTI decoder |
| `xprobe/correlator` | Event matching and statistics | Multi-source completed-capture measurement |
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
- resolved userspace probes;
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

## Probe resolution

The core resolver parses a userspace event selector, reads the selected ELF
file, and matches it against file-backed regions in `/proc/<pid>/maps`. Symbol
virtual addresses are converted through ELF load segments to file offsets; the
file offset and matching process map then determine the runtime address. This
calculation handles fixed-address executables, PIE executables, and shared
libraries without treating a process mapping base as a symbol address.

Resolution reports the canonical binary path, GNU Build ID when present,
symbol metadata, probe kind, file offset, runtime address, and exact map used as
evidence. The target identity is checked before and after resolution. Resolution
does not attach a probe or mutate the target.

Validation composes process inspection and probe resolution with CUDA selector
parsing and a correlation-policy compatibility matrix. Input errors fail
immediately; unavailable runtime requirements produce a successful validation
report with `valid: false` and structured issues. Heuristic temporal policies
are always labeled as warnings. Validation performs no collection and reports
`target_mutation: false`. Cross-domain selectors expose
`needs_clock_alignment: true`. The capture
`HOST_MONOTONIC_TIMESTAMPS` feature provides the required CUPTI-to-host
normalization; validation retains the requirement so orchestration can select a
compatible collector.

## Host and device collection

The implemented host collector embeds a Clang-built BPF object, loads it with
libbpf-rs, attaches one PID-scoped function-entry uprobe or function-return
uretprobe, and consumes fixed-size records from a ring buffer. The target PID
namespace device and inode are passed to BPF so emitted PID/TID values match the
namespace used by the CLI. Collection stops at a caller-supplied sample limit
or deadline, reports ring-buffer drops, and detaches through Rust ownership on
every return path.

The BPF hot path performs only namespace identity filtering, timestamp and CPU
capture, sequence/drop accounting, and ring-buffer submission. Symbol lookup,
JSON construction, and timeout handling remain in userspace.

CUPTI callback and activity collection runs inside the target process. The
agent subscribes to all CUDA Runtime/Driver API entry/exit callbacks and
concurrent kernel, memcpy, and memset activity. CUPTI correlation IDs provide the exact
join key for start/end intervals and API-to-kernel records. Callback paths
reserve slots in a bounded in-memory array; activity parsing, draining, and
binary output happen outside the runtime API callback.

The collector decodes the fixed CUPTI ABI into the same protocol `Event` type
used by eBPF collectors. Before enabling activity collection, the agent
registers `CLOCK_MONOTONIC` as CUPTI's timestamp callback. CUPTI linearly maps
GPU timestamps into that clock during activity post-processing. Capture ABI v1
uses feature flags to declare this timestamp semantic and transfer record
support while retaining the 200-byte record layout. The exporter writes either
source as compact JSONL.

The correlator can measure a completed CUPTI capture within one clock domain or
between host callback and normalized GPU timestamps.
Exact matching groups events by CUPTI correlation ID and rejects ambiguous
groups. First-after matching is chronological, one-to-one, and explicitly
heuristic. Both paths enforce sample, duration, and event-count bounds and
report dropped, unmatched, and ambiguous records. API-to-GPU subtraction from
a capture without host-monotonic timestamps returns `CLOCK_ALIGNMENT_FAILED`.

The completed-capture importer accepts CUPTI binary, host capture JSON, and
Event JSONL inputs. It rejects mixed target PIDs, accumulates source drop
counters, sorts all events by normalized timestamp, and assigns one measurement
session identity. Repeated `--input` arguments therefore support host-to-GPU
`first-after` measurement without implying that the files prove causality.

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
