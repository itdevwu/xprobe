# CLI contract

xprobe exposes exactly four public commands: `doctor`, `discover`, `validate`,
and `measure`.

## Common behavior

When stdout is not a terminal, every command writes one versioned JSON document
to stdout; on a terminal it prints a human-readable report. `--json` forces
JSON and `--human` forces the report; they cannot be combined.
`--non-interactive` and `--no-color` are accepted for compatibility: commands
never prompt and never color. Diagnostics, including the online-injection
warning, go to stderr.

Measurement results carry `schema_version: "3.0"`; every other success record,
error record, and Event JSONL line carries `"2.0"`. Unknown JSON fields and
unsupported schema versions are rejected. xprobe maintains only the
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
xprobe doctor
```

Reports Linux/kernel identity, BTF, BPF/perf permissions, lockdown, ptrace
policy, NVIDIA driver, CUDA toolkit/driver, CUPTI, namespaces, and conservative
capability booleans. `ok: true` means diagnosis completed, not that every
capability is available. The CUPTI check lists each supported installed major
and its resolved library path. Privilege checks read the effective capability set
(`CapEff`), not the user ID: root inside a container without `CAP_BPF` and
`CAP_PERFMON` (or `CAP_SYS_ADMIN`) reports eBPF as restricted, and online
injection needs `CAP_SYS_PTRACE` unless `ptrace_scope` permits same-user
tracing.

## `discover`

```bash
xprobe discover --pid 4242 [--limit 200]
```

Treats the PID as a process-tree root and queries NVML for active CUDA compute
processes without attaching. It returns only root/descendant context holders,
including PID plus procfs start time, parent PID, executable, command line, and
GPU UUIDs. `limit` must be positive. `total_candidates` and `truncated`
describe bounded output. The caller chooses one candidate and passes its PID to
`validate` and `measure`; xprobe does not guess among workers.

NVML lists compute processes from every container sharing the GPU. A listed PID
that is not visible in the caller's PID namespace, or that exits before
inspection, cannot be a candidate; it is reported in a
`NVML_PROCESS_UNAVAILABLE` warning with its `nvml_pids` instead of failing the
command. When none of them is visible, a `NVML_PID_NAMESPACE_MISMATCH`
warning explains that NVML reported host PIDs: inside a container, pass the
worker's namespace-local PID directly to `validate` and `measure`. Root exit and other inspection failures remain errors.

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
python:gc_start
python:gc_end
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

Python GC selectors are capability-based, not process-name based. Validation
reads the target's mapped CPython executable and `libpython` ELF metadata and
requires both `python:gc__start` and `python:gc__done` USDT markers. Captured
events contain process/thread identity, timestamp, mapped binary, provider, and
marker name without copying generation or object payloads.

CUDA forms include Runtime/Driver API entry/exit, kernel/memcpy/memset activity
start/end, and NVTX range boundaries. `cuda:launch_api:entry|exit` matches every
kernel launch API in one endpoint: Runtime `cudaLaunchKernel`,
`cudaLaunchKernelExC`, and `cudaLaunchCooperativeKernel`, and Driver
`cuLaunchKernel`, `cuLaunchKernelEx`, and `cuLaunchCooperativeKernel`, so
launches from cuBLAS and from Triton or other Driver API callers pair exactly
with their kernels. A Runtime launch and the Driver launch it makes internally
count once, as the Runtime call. It uses two of the eight Agent name filters. Kernel selectors accept `name~REGEX`;
memcpy selectors accept `kind=<HtoD|DtoH|DtoD|HtoH|PtoP>`. NVTX selectors are
`cuda:nvtx_range_start:name~REGEX` and
`cuda:nvtx_range_end:name~REGEX`; their name expression must reduce to one
nonempty exact, prefix, suffix, or contains filter shorter than 128 bytes.

## `validate`

```bash
xprobe validate --pid 4242 \
  --from 'cuda:launch_api:exit' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match exact
```

Validation is read-only. It verifies target identity, resolves host and Python
USDT selectors, parses CUDA filters, and checks collection and correlation
requirements. `validate --cpu-sample` checks target threads, perf-event access,
and Python symbolization status. `validate --syscall-aggregate` checks the
bounded eBPF aggregate path. Inventory modes do not take event-pair selectors.
Results conform to `schemas/validate.schema.json`.

`validate --spec graph.json` validates a measurement graph without `--pid`; the
spec's target selects the process. It emits
`schemas/measurement-graph-validate.schema.json` (schema `3.0`) with each named
endpoint's resolution, each edge's policy recommendation, requirements merged
across edges, and issues scoped to the graph, an endpoint, or an edge. Unknown
or unused endpoints, duplicate edge names, missing bounds, and more than two
syscall, tracepoint, or USDT endpoints are issues, not command errors.

Supported policies are `exact`, `first-after`, `nearest`, `stack-nested`, and
`stream-order`. Exact uses deterministic CUPTI correlation IDs, NVTX range
kind/ID, one named syscall's per-thread entry/exit lifecycle, or one CPython GC
start/end lifecycle on the same thread. Nested
requires entry/return of the same host function. Stream order pairs a GPU
activity end with the start of the next kernel, copy, or memset on the same
device, context, and stream, whether or not that activity matches either
selector; it pairs only when the next activity is the selected end. To see
every successor it records all GPU activity, using six of the eight Agent
filters, and `validate` warns `STREAM_ORDER_CAPTURES_ALL_ACTIVITY`. An end
that overlaps other activity on its stream, whose successor ties with another
start, or whose successor's truncated kernel name cannot decide the selector
is ambiguous. Temporal policies always warn that they are heuristic.
`policy_recommendation` reports the strongest compatible policy, a stable
machine-readable reason, and all compatible alternatives. The caller still
chooses the policy; xprobe does not silently replace or retry it.

`requirements.agent_activation` is `not_required`, `already_loaded`,
`injection_required`, or `startup_required`. Online injection handles ordinary
CUDA callbacks and activity; `injection_required` sets `target_mutation: true`
and emits `TARGET_PROCESS_WILL_BE_MODIFIED`. NVTX dispatch is fixed by its first
API initialization, so an unmapped Agent produces `startup_required` and an
invalid result. Restart the target with `NVTX_INJECTION64_PATH` set to the
matching xprobe Agent before its first NVTX call. A mapped Agent is verified
again at ARM through the capture feature flag. Callers must stop on
`valid: false`.
Mapped CUDA/CUPTI majors that conflict or fall outside 12 and 13 produce
`UNSUPPORTED_CUDA_VERSION`.
CUDA major support does not imply host-clock alignment: `measure` accepts
GPU-only pairs in the CUPTI clock and rejects CPU/GPU subtraction when the
capture omits the host-monotonic feature flag.

## `measure`

Live target:

```bash
xprobe measure --pid 4242 \
  --from 'cuda:launch_api:exit' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match exact --samples 100 --timeout-ms 30000 \
  --events-out /tmp/xprobe-events.jsonl
```

Linux syscall duration:

```bash
xprobe measure --pid 4242 \
  --from 'syscall:mmap:entry' --to 'syscall:mmap:exit' \
  --match exact --samples 100 --max-events 1000
```

CPU/Python hotspot inventory:

```bash
xprobe measure --pid 4242 --cpu-sample --duration-ms 1000 \
  --frequency-hz 99 --max-samples 10000 --max-groups 256 \
  --stack-depth 64 --max-threads 1024
```

Syscall lifecycle inventory:

```bash
xprobe measure --pid 4242 --syscall-aggregate --duration-ms 1000 \
  --max-groups 256 --max-inflight 1024
```

CPython garbage-collection duration:

```bash
xprobe measure --pid 4242 \
  --from python:gc_start --to python:gc_end \
  --match exact --samples 100 --max-events 1000
```

NVTX application range:

```bash
xprobe measure --pid 4242 \
  --from 'cuda:nvtx_range_start:name~^forward$' \
  --to 'cuda:nvtx_range_end:name~^forward$' \
  --match exact --samples 100 --max-events 1000
```

Completed captures:

```bash
xprobe measure --input host.json --input cupti.bin \
  --from 'uprobe:/srv/app/server:request:entry' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match first-after --samples 100
```

Versioned live spec:

```bash
xprobe measure --spec measurement.json
```

Same-window triage of an unknown live workload:

```bash
xprobe measure --pid 4242 --triage --duration-ms 2000
```

Broad GPU activity inventory:

```bash
xprobe measure --pid 4242 \
  --from 'cuda:kernel_start' --to 'cuda:kernel_end' \
  --match exact --aggregate --duration-ms 1000 --max-groups 4096
```

Exactly one source mode is used: `--pid`, one or more `--input`, or `--spec`.
Live measurement requires at least one positive `--samples` or `--duration-ms`
bound; completed `--input` captures are already bounded and correlate every
event when neither is set. `--timeout-ms` defaults to 30 seconds and
`--max-events` to 100,000.

`--cpu-sample` is live-only and requires `--duration-ms`. It opens bounded
userspace callchain sampling events for the target's current threads. Defaults
are 99 Hz, 10,000 observed samples, 256 retained stack groups, depth 64, and
1,024 threads. The result uses
`schemas/cpu-sample-inventory-result.schema.json`: exact raw stack counts are
grouped deterministically, hotspots report inclusive/exclusive counts and
proportions, and attachable native frames include uprobe selector hints. Native
ELF and `/tmp/perf-<pid>.map` Python symbols are resolved independently.
`python_status` and resolved/unresolved frame counts prevent native fallback
from being mislabeled as Python semantic coverage. Lost samples, truncated
stacks, thread coverage, and capacity pressure remain visible.

`--python-sample` is live-only and requires `--duration-ms`. It reads CPython
3.9 through 3.14 interpreter state from outside the target with
`process_vm_readv`, without perf events, eBPF, `-X perf`, injection, or
stopping the target; it needs ptrace access (the same user under
`kernel.yama.ptrace_scope` 0, or `CAP_SYS_PTRACE`). The thread holding the GIL
is sampled at `--python-hz` (default 2000) and every thread at
`--python-threads-hz` (default 100). Interpreter offsets are built in per minor
version and checked against `_Py_DebugOffsets` on 3.13 and newer; a
free-threaded or differently laid out build returns
`UNSUPPORTED_PYTHON_VERSION`. A stack that changes while it is read is
discarded and counted in `inconsistent_reads`. Frames name the function and
the line where it starts, not the line that was running. For threads that are
not running in a sweep, `/proc/<pid>/task/<tid>/syscall` adds the system call
and symbolized native program counter they are blocked in. Results use
`schemas/python-sample-result.schema.json` (schema `3.0`): GIL-holder stack
groups and hotspots as shares of GIL ticks, the share of ticks with the GIL
released, all-thread stack groups, native waits, achieved rates, read latency,
and TID mapping. Every sample is written with its `CLOCK_MONOTONIC` timestamp
to the artifact, one `schemas/python-sample-record.schema.json` record per
line.

`--triage` is live-only, requires `--duration-ms`, and emits
`schemas/triage-result.schema.json` (schema `3.0`). Within one window it
concurrently collects procfs per-thread on-CPU, runqueue, and blocked time;
cgroup CPU throttling; a CPU sample inventory; a syscall aggregate; NVML device
health (utilization, clock event reasons, temperature, power, PCIe link); and,
when the target has loaded libcuda, a CUDA kernel aggregate, which may inject
the CUPTI Agent under the same rules as `measure`. The result keeps the top
five hotspots, syscall groups, and kernel groups inline and writes each full
inventory to a private artifact referenced from `sources`. `findings` are
deterministic and ranked by an estimated share of the window; a finding whose
impact cannot be bounded has `impact_share: null` and ranks last. Each finding
carries an environment action or a ready `MeasurementSpec` for `measure
--spec`, with record capacity sized from the observed rate. A source that is not
permitted, absent, or exceeds its bounded capacity is `unavailable` with a
reason and a `TRIAGE_SOURCE_UNAVAILABLE` warning; target exit or reuse, cleanup,
and internal failures fail the command. `not_covered` lists what triage cannot
answer, including where blocked threads wait. Blocked time includes idle
waiting, so read it per thread. NVML utilization is a device-wide sampled
estimate.

`--syscall-aggregate` is live-only and requires `--duration-ms`. PID-filtered
raw syscall entry/exit programs retain at most `--max-inflight` thread starts
and `--max-groups` syscall groups in BPF maps, then emit one bounded summary.
Known x86_64 numbers include names and exact entry/exit selector hints; unknown
numbers remain numeric. `schemas/syscall-aggregate-result.schema.json` exposes
entries, matched and unmatched exits, inflight-at-end, drops, occupancy, errors,
and total/min/max/mean duration. It contains no pointer values or per-call event
stream.

`--aggregate` is live-only, duration-bounded, and accepts one matching kernel,
memcpy, or memset activity start/end pair. It uses `--max-groups` (default
4,096), does not accept `--samples` or `--events-out`, and emits
`schemas/aggregate-inventory-result.schema.json`. The result is a coarse
inventory, not exact event evidence: it reports count, total/min/max/mean
duration, optional transferred bytes, table occupancy, and drop completeness.
Memcpy groups also split by `src_memory` and `dst_memory` (`pageable`,
`pinned`, `device`, `managed`, ...); pageable host memory forces staged,
synchronous copies. Aggregate results use schema `3.0`.
Aggregate kernel regex must be reducible to an exact, prefix, suffix, or
contains filter because this mode intentionally has no Rust-side event pass.
Each kernel group reports `name_complete`. CUPTI names that fill the fixed
127-byte observed prefix are marked `false`; their selector hints use that
prefix instead of claiming an exact full name, so the next capture can still
filter in the Agent hot path.

The three inventory modes have distinct result contracts and contain no exact
event timeline. They cannot be passed to `measure --input` or exported with
`--events-out`. Their groups and hotspots are evidence for choosing selectors;
read-only validation still precedes the resulting exact measurement.

Live host endpoints attach PID-scoped eBPF probes. Linux syscall endpoints use
raw tracepoints so they do not depend on tracingfs event IDs; ordinary named
tracepoints use their kernel category and name. CPython GC endpoints attach to
the exact mapped ELF selected by validation. Every endpoint link is attached
before collection is armed. A samples-bound Linux capture
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

NVTX thread ranges preserve nesting through the thread ID and zero-based push
level. Process ranges preserve the NVTX range ID and may end on a different
thread; evidence reports both boundary threads plus `start_tid`. Names are
copied into the fixed record bound with `name_complete`. ASCII
`nvtxRangePushA`/`nvtxRangeStartA` and ASCII messages in their `Ex` forms are
supported; wide and registered-string messages are not collected. This is
timeline boundary collection only. It does not enable CUPTI Range Profiling,
metric replay, or kernel performance-counter passes.

Completed inputs may be CUPTI ABI binary, bounded host-capture JSON, or Event
JSONL. Repeated inputs are merged after target-PID checks. Unknown records,
mixed targets, malformed captures, and excessive event counts fail explicitly.
An input's capture manifest, `<input>.manifest.json`, restores what its live
capture recorded: drops, record limits, and collector failures fail the
measurement as they did live, and its coverage sets `collection.coverage`. A
manifest whose size or SHA-256 no longer matches its input is an error. Without
manifests, coverage is `unverified`, or `unverified_merge` for several inputs,
which is a caution because their events may not share one window of one
target; stream order without a capture of every GPU activity is heuristic and
cautioned.

Results conform to `schemas/measurement-result.schema.json` (schema `3.0`) and
contain:

- status and latency statistics;
- a `quality` verdict (`good` or `caution`) with coded issues;
- matched, unmatched, ambiguous, and dropped counts; a samples limit keeps the
  earliest pairs, while unmatched counts and the score cover the whole window;
- method, confidence, and score;
- clock alignment and optional estimated error;
- collection completeness, host/CUDA totals, and CUPTI capacity, observed,
  retained, dropped, and utilization values when an ABI envelope provides them;
- `evidence`: one exemplar start/end pair per latency rank (min, p50, p90,
  p99, max), the artifact path, format, and event count, and with
  `--evidence full` every matched pair;
- structured warnings.

Live captures always write the complete bounded capture with mode `0600`:
`--events-out PATH` chooses the file; otherwise it goes to a new mode `0700`
directory under the temporary directory. `measure --input` with the same
selectors re-correlates it deterministically. Completed `--input` measurements
write an artifact only with `--events-out`. The default format is JSONL; `--format chrome` writes Chrome Trace Event
Format. Beside an Event JSONL artifact, xprobe writes its capture manifest
(`schemas/capture-manifest.schema.json`, schema `1.0`): target identity, the
`CLOCK_MONOTONIC` capture window, armed selectors, whether every GPU activity
and peer copy was recorded, losses, and the artifact's size and SHA-256. A
re-exported input keeps its manifest only when exactly one input had one; an
artifact without known coverage removes a stale manifest at its path. Once collection has produced a capture, correlation, clock, drop, or
capacity failures still write it and identify its path, format, and event count
in the JSON error. Artifact failure returns `TRACE_EXPORT_FAILED` and preserves
the original measurement error code in `details`.

### Triggered capture

```bash
xprobe measure --pid 4242 --trigger-gap-ms 10 --pre-ms 50 --post-ms 50 \
  --timeout-ms 300000 --max-events 400000 --events-out /tmp/spikes
```

A triggered capture waits for one rare slow span instead of recording a fixed
window. `--trigger-gap-ms` fires on idle time between an activity's end and
the next kernel, copy, or memset on its stream, `--trigger-duration-ms` on a
kernel, copy, or memset that lasts at least the threshold, and
`--trigger-latency-ms` on a `--from`/`--to` pair under `--match`; latency
triggers accept CUDA endpoints only. Gap and duration triggers, and latency
triggers under `stream-order`, record every GPU activity.

The CUPTI Agent keeps the newest `--max-events` records in a ring, and xprobe
evaluates every new span on each snapshot with the same pairing rules as
`measure`. When a span crosses the threshold, xprobe waits for the post-roll,
writes the events from `--pre-ms` before the span to `--post-ms` after it as
`window-N.events.jsonl` with its capture manifest, and continues until
`--windows` windows (default one) are written; each window starts after the
previous one ends. `--events-out` names the directory for the windows.
Results conform to `schemas/trigger-result.schema.json` (schema `3.0`): the
condition, every span evaluated and the longest seen, each window's firing
span and longest spans, and ring capacity, overwrites, and drops.

Records overwritten before a snapshot read them or dropped by CUPTI invalidate
any window they may overlap; such windows are counted in `lost_windows` and
never written. Without a written window, a timeout returns
`TRIGGER_NOT_OBSERVED` with the longest span seen as the observed bound, and
fired windows that all lost records return `EVENTS_DROPPED`.

No matched pairs return `NO_MATCHED_SAMPLES`. Cross-clock subtraction without
declared alignment returns `CLOCK_ALIGNMENT_FAILED`. Drops and unknown clock
error are never silently converted to high-quality results. Error `details` and
`hints` carry selectors, policies, counters, clock domains, and explicit next
actions where applicable; callers must not infer these fields from messages.

## Measurement graphs

A graph measures several edges from one bounded capture of one process:

```json
{
  "schema_version": "3.0",
  "name": "request_path",
  "target": {"pid": 4242, "process_start_time": 123456},
  "endpoints": {
    "request": "uprobe:/srv/app/server:handle_request:entry",
    "launch_exit": "cuda:launch_api:exit",
    "kernel_start": "cuda:kernel_start:name~^flash",
    "kernel_end": "cuda:kernel_end:name~^flash"
  },
  "edges": [
    {"name": "request_to_launch", "from": "request", "to": "launch_exit",
     "match_policy": "first_after", "samples": 100},
    {"name": "launch_to_kernel", "from": "launch_exit", "to": "kernel_start",
     "match_policy": "exact", "samples": 100},
    {"name": "kernel_duration", "from": "kernel_start", "to": "kernel_end",
     "match_policy": "exact", "samples": 100}
  ],
  "duration_ms": null,
  "timeout_ms": 30000,
  "max_events": 20000
}
```

`measure --spec graph.json` accepts this `schemas/measurement-graph-spec.schema.json`
document. `target.process_start_time` may be omitted: xprobe then reads
the current start time of `pid` and verifies that identity around attach, as
`measure --pid` does. A spec that does not match the schema fails with an error
naming the schema and the offending field. A graph has 1–8 named endpoints and 1–8 edges; every edge sets
`samples` or the graph sets `duration_ms`. Collectors attach once per unique
endpoint: uprobes have no further limit, CUDA endpoints share up to eight Agent
filters, and syscall, tracepoint, and USDT endpoints share two Linux collector
slots. `max_events` bounds the whole capture. Collection ends when every edge
reaches its samples or the duration elapses.

The capture is validated once, then each edge is correlated independently with
the single-edge rules. A graph never joins edges into per-request paths and
never implies causality between edges. Results use
`schemas/measurement-graph-result.schema.json` (schema `3.0`): per-edge
statistics, quality verdict, correlation, clock quality, and evidence, one
shared collection summary, and the shared event artifact. Each edge's
`evidence.artifact` also points at that artifact, so single-edge and graph
consumers read the path from the same place. Any invalid edge or
edge correlation failure fails the whole command with the edge name in the
message and `details.edge`; the captured events are still written to the
artifact so the caller can re-correlate edges with `measure --input`.

## Compatibility

Earlier low-level command spellings remain hidden during the pre-1.0 transition so
existing integration fixtures can decode captures. They are not public API and
must not be used by Skills or new automation.
