# CLI contract

xprobe exposes exactly four public commands: `doctor`, `discover`, `validate`,
and `measure`.

## Common behavior

All commands support `--json --non-interactive --no-color`. JSON mode writes one
versioned document to stdout. Diagnostics, including the online-injection
warning, go to stderr. Commands never prompt.

All success and error records carry `schema_version: "2.0"`. Unknown JSON
fields and unsupported schema versions are rejected. xprobe maintains only the
current schema during the pre-1.0 protocol transition.

| Exit | Meaning |
| --- | --- |
| `0` | Command completed and emitted a result |
| `1` | Validation, collection, decode, export, cleanup, or internal failure |
| `2` | Invalid CLI syntax from Clap |
| `3` | Target missing, exited, or reused |
| `4` | Permission denied for inspection, eBPF, or ptrace |

Runtime failures use `schemas/error.schema.json` and include a stable code,
message, recoverability, details, and hints.

## `doctor`

```bash
xprobe doctor --json --non-interactive --no-color
```

Reports Linux/kernel identity, BTF, BPF/perf permissions, lockdown, ptrace
policy, NVIDIA driver, CUDA toolkit/driver, CUPTI, namespaces, and conservative
capability booleans. `ok: true` means diagnosis completed, not that every
capability is available. The CUPTI check lists each supported installed major
and its resolved library path.

## `discover`

```bash
xprobe discover --pid 4242 [--limit 200] \
  --json --non-interactive --no-color
```

Treats the PID as a process-tree root and queries NVML for active CUDA compute
processes without attaching. It returns only root/descendant context holders,
including PID plus procfs start time, parent PID, executable, command line, and
GPU UUIDs. `limit` must be positive. `total_candidates` and `truncated`
describe bounded output. The caller chooses one candidate and passes its PID to
`validate` and `measure`; xprobe does not guess among workers.

This process-candidate response is discovery schema `2.0`. xprobe does not emit
or maintain the pre-0.3 event-discovery shape.

An unavailable or failed NVML query is an explicit command error, not an empty
candidate list.

## Selectors

Selectors are supplied by the caller and checked by `validate` before any
attachment. Host selector forms are:

```text
uprobe:<binary>:<symbol>:entry
uprobe:<binary>:<symbol>:return
uprobe:<binary>:symbol=<full-demangled-c++-signature>:entry
uprobe:<binary>:symbol=<full-demangled-c++-signature>:return
uprobe:<binary>:+0x<file-offset>:entry
uprobe:<binary>:+0x<file-offset>:return
syscall:<name>:entry
syscall:<name>:exit
tracepoint:<category>:<name>
```

The `symbol=` form allows `::` and other punctuation in a full C++ signature.
Resolution returns the attachable mangled ELF name in `symbol` and its readable
signature in `symbol_demangled`; captured host events retain both. It works for
mapped CPython, native extension, and framework libraries, but does not resolve
Python frames or `module.qualname` names.

Named syscall selectors are Linux x86_64 endpoints resolved by `validate`.
Their eBPF path filters PID and syscall number before reserving an event,
records the six scalar syscall ABI registers on entry, and records the scalar
return value on exit. It never dereferences pointer arguments. Named
tracepoints record identity and timestamp only; they do not copy the tracepoint
payload. Unsupported syscall names and unavailable tracepoints fail explicitly.

CUDA forms include Runtime/Driver API entry/exit and kernel, memcpy, or memset
activity start/end. Kernel selectors accept `name~REGEX`; memcpy selectors
accept `kind=<HtoD|DtoH|DtoD|HtoH|PtoP>`.

## `validate`

```bash
xprobe validate --pid 4242 \
  --from 'cuda:runtime_api:cudaLaunchKernel:exit' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match exact --json --non-interactive --no-color
```

Validation is read-only. It verifies target identity, resolves host selectors,
parses CUDA filters, and checks collection and correlation requirements.
Results conform to `schemas/validate.schema.json`.

Supported policies are `exact`, `first-after`, `nearest`, `stack-nested`, and
`stream-order`. Exact uses deterministic CUPTI correlation IDs or one named
syscall's per-thread entry/exit lifecycle. Nested requires entry/return of the
same host function. Stream order requires GPU activity endpoints. Temporal
policies always warn that they are heuristic.
`policy_recommendation` reports the strongest compatible policy, a stable
machine-readable reason, and all compatible alternatives. The caller still
chooses the policy; xprobe does not silently replace or retry it.

`requirements.agent_activation` is `not_required`, `already_loaded`, or
`injection_required`. The last value sets `target_mutation: true` and emits
`TARGET_PROCESS_WILL_BE_MODIFIED`; it does not make an otherwise collectable
request invalid. Callers must still stop on `valid: false`.
Mapped CUDA/CUPTI majors that conflict or fall outside 12 and 13 produce
`UNSUPPORTED_CUDA_VERSION`.
CUDA major support does not imply host-clock alignment: `measure` accepts
GPU-only pairs in the CUPTI clock and rejects CPU/GPU subtraction when the
capture omits the host-monotonic feature flag.

## `measure`

Live target:

```bash
xprobe measure --pid 4242 \
  --from 'cuda:runtime_api:cudaLaunchKernel:exit' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match exact --samples 100 --timeout-ms 30000 \
  --events-out /tmp/xprobe-events.jsonl \
  --json --non-interactive --no-color
```

Linux syscall duration:

```bash
xprobe measure --pid 4242 \
  --from 'syscall:mmap:entry' --to 'syscall:mmap:exit' \
  --match exact --samples 100 --max-events 1000 \
  --json --non-interactive --no-color
```

Completed captures:

```bash
xprobe measure --input host.json --input cupti.bin \
  --from 'uprobe:/srv/app/server:request:entry' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match first-after --samples 100 \
  --json --non-interactive --no-color
```

Versioned live spec:

```bash
xprobe measure --spec measurement.json \
  --json --non-interactive --no-color
```

Broad GPU activity inventory:

```bash
xprobe measure --pid 4242 \
  --from 'cuda:kernel_start' --to 'cuda:kernel_end' \
  --match exact --aggregate --duration-ms 1000 --max-groups 4096 \
  --json --non-interactive --no-color
```

Exactly one source mode is used: `--pid`, one or more `--input`, or `--spec`.
At least one positive `--samples` or `--duration-ms` bound is required in direct
mode. `--timeout-ms` defaults to 30 seconds and `--max-events` to 100,000.
`--aggregate` is live-only, duration-bounded, and accepts one matching kernel,
memcpy, or memset activity start/end pair. It uses `--max-groups` (default
4,096), does not accept `--samples` or `--events-out`, and emits
`schemas/aggregate-inventory-result.schema.json`. The result is a coarse
inventory, not exact event evidence: it reports count, total/min/max/mean
duration, optional transferred bytes, table occupancy, and drop completeness.
Aggregate kernel regex must be reducible to an exact, prefix, suffix, or
contains filter because this mode intentionally has no Rust-side event pass.
Each kernel group reports `name_complete`. CUPTI names that fill the fixed
127-byte observed prefix are marked `false`; their selector hints use that
prefix instead of claiming an exact full name, so the next capture can still
filter in the Agent hot path.

Live host endpoints attach PID-scoped eBPF probes. Linux syscall endpoints use
raw tracepoints so they do not depend on tracingfs event IDs; ordinary named
tracepoints use their kernel category and name. A samples-bound Linux capture
allows bounded startup slack for a target already inside an event boundary. A
duration capture that fills `--max-events` returns `EVENT_RATE_TOO_HIGH` rather
than reporting partial success. CUDA endpoints automatically activate the CUPTI
agent. If it is absent, `--agent` or
`XPROBE_CUPTI_AGENT_PATH` selects the shared object; otherwise xprobe searches
`../lib/xprobe/cuda12` or `../lib/xprobe/cuda13` according to the target and
then the matching development build path. An unobservable target major is
accepted only when exactly one supported CUPTI major is installed. Injection
requires Linux x86_64, a shared mount namespace, and ptrace permission. It emits
a stderr warning and `CUPTI_AGENT_INJECTED`. Each live call arms a fresh
`--max-events`-bounded capture with endpoint filters. Final stop disables CUPTI;
automatic injection also removes its private socket while leaving the `.so`
mapped.

Completed inputs may be CUPTI ABI binary, bounded host-capture JSON, or Event
JSONL. Repeated inputs are merged after target-PID checks. Unknown records,
mixed targets, malformed captures, and excessive event counts fail explicitly.

Results conform to `schemas/measurement-result.schema.json` and contain:

- status and latency statistics;
- matched, unmatched, ambiguous, and dropped counts;
- method, confidence, and score;
- clock alignment and optional estimated error;
- collection completeness, host/CUDA totals, and CUPTI capacity, observed,
  retained, dropped, and utilization values when an ABI envelope provides them;
- full start/end events plus latency for each evidence pair;
- structured warnings.

`--events-out PATH` atomically writes the complete bounded capture with mode
`0600`. The default format is JSONL; `--format chrome` writes Chrome Trace Event
Format. Once collection has produced a capture, correlation, clock, drop, or
capacity failures still write it and identify its path, format, and event count
in the JSON error. Artifact failure returns `TRACE_EXPORT_FAILED` and preserves
the original measurement error code in `details`.

No matched pairs return `NO_MATCHED_SAMPLES`. Cross-clock subtraction without
declared alignment returns `CLOCK_ALIGNMENT_FAILED`. Drops and unknown clock
error are never silently converted to high-quality results. Error `details` and
`hints` carry selectors, policies, counters, clock domains, and explicit next
actions where applicable; callers must not infer these fields from messages.

## Compatibility

Earlier low-level command spellings remain hidden during the pre-1.0 transition so
existing integration fixtures can decode captures. They are not public API and
must not be used by Skills or new automation.
