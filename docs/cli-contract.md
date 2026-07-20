# CLI contract

The CLI is designed for deterministic use by both humans and programs.

## Common behavior

Implemented commands accept:

```text
--json
--non-interactive
--no-color
```

In JSON mode, non-streaming commands write exactly one JSON document. Event
stream commands write one JSON document per line. Human diagnostics and logs
belong on stderr. Commands never prompt for a target or wait for Enter.

Every JSON success or error carries `schema_version: "1.0"`. The checked-in
schemas are the machine-readable contract.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Command completed and emitted a result |
| `1` | Internal, I/O, or malformed-system-data failure |
| `2` | Invalid command-line arguments, emitted by Clap |
| `3` | Target not found, exited, or was reused |
| `4` | Permission denied while inspecting or attaching to the target |

Capability absence does not make `doctor` fail. `ok: true` means the inspection
completed; callers must read individual capability and check statuses.

## Errors

Runtime failures use the stable error envelope:

```json
{
  "schema_version": "1.0",
  "ok": false,
  "error": {
    "code": "TARGET_NOT_FOUND",
    "message": "target PID 4294967295 was not found",
    "recoverable": true,
    "details": {},
    "hints": []
  }
}
```

Unknown or malformed procfs data is not converted to a successful partial
result.

## `doctor`

```bash
xprobe doctor --json --non-interactive --no-color
```

`doctor` checks kernel and architecture information, BTF, effective BPF/perf
privileges, kernel lockdown, perf and ptrace settings, NVIDIA runtime access,
CUDA driver/toolkit visibility, CUPTI, containers, and the PID namespace.

Check status values are `available`, `restricted`, `unavailable`, or `unknown`.
The capability booleans are conservative summaries of those checks.

## `inspect`

```bash
xprobe inspect --pid 1234 --json --non-interactive --no-color
```

`inspect` is read-only and does not attach probes. It reports:

- PID and process start time;
- executable and complete command line;
- real, effective, saved, and filesystem UID/GID;
- namespace PID chain and mount namespace;
- cgroup membership;
- mapped shared libraries;
- `libcuda`, `libcudart`, and xprobe CUPTI agent presence;
- target-specific collection capabilities.

The external presence of `libcuda` does not prove that a CUDA context exists.
That field remains `unknown` until an in-process signal can establish it.

Process command lines may contain sensitive arguments. Callers must treat the
inspection result accordingly; xprobe does not read environment variables or
process memory.

## `dev uprobe`

```bash
xprobe dev uprobe \
  --pid 1234 \
  --binary /srv/app/server \
  --symbol handle_request \
  [--return] \
  --probe-id 7 \
  --samples 100 \
  --timeout-ms 5000 \
  --json --non-interactive --no-color
```

The command captures function-entry events by default. `--return` attaches a
uretprobe and captures function-return events instead. `--binary` must resolve
to the target executable or a shared library visible in `/proc/<pid>/maps`;
otherwise the command returns `BINARY_NOT_MAPPED`. `--samples` and
`--timeout-ms` must both be greater than zero.

The result conforms to `schemas/host-capture.schema.json`. Reaching the deadline
before the requested sample count is a successful bounded capture with
`timed_out: true`; attachment, map, malformed-record, permission, and target
identity failures use the standard error envelope. Events contain host
monotonic nanoseconds, a sequence number, namespace-local PID/TID, CPU, probe
id, binary path, symbol, and probe kind. Argument capture is not implemented;
return events currently report `return_value: null`.

Use `--jsonl` instead of `--json` to emit only the normalized `Event` values,
one compact JSON object per line. This is the same event stream format produced
by the CUPTI decoder.

## `resolve`

```bash
xprobe resolve \
  --pid 1234 \
  --selector 'uprobe:/srv/app/libserver.so:handle_request:entry' \
  --json --non-interactive --no-color
```

`--event` is accepted as an alias for `--selector`. Supported selector forms
are:

```text
uprobe:<binary>:<symbol>:entry
uprobe:<binary>:<symbol>:return
uprobe:<binary>:+0x<file-offset>:entry
uprobe:<binary>:+0x<file-offset>:return
```

Resolution is read-only and does not attach a probe. The command verifies the
PID plus process start time, requires the binary to be present in
`/proc/<pid>/maps`, parses ELF load segments and symbol tables, reads the GNU
Build ID when present, and returns the file offset, matching process mapping,
and computed runtime address. PIE executables and `ET_DYN` shared libraries are
reported separately. Hexadecimal `+0x...` values always mean ELF file offsets,
not virtual addresses.

The result conforms to `schemas/resolve.schema.json`. Malformed selectors,
missing symbols, unmapped binaries, and offsets outside loadable or mapped
regions use the standard error envelope. An absent Build ID is represented by
`null`; invalid ELF metadata is an error.

## `validate`

```bash
xprobe validate \
  --pid 1234 \
  --from 'uprobe:/srv/app/libserver.so:handle_request:entry' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match first-after \
  --json --non-interactive --no-color
```

`validate` reads process and ELF metadata but does not attach probes, initialize
CUPTI, or modify the target. It resolves host selectors, validates CUDA filters
and regular expressions, checks the correlation policy against available keys,
and reports required eBPF, CUPTI, and clock-alignment capabilities.

The current selector grammar recognizes CUDA runtime and driver API callbacks,
kernel, memcpy, and memset activity. This build can collect
`cudaLaunchKernel` runtime callbacks, kernel, memcpy, and memset activity, and
host entry/return probes. Other recognized CUDA API events are returned with
`collectable: false` and make the result invalid until their collectors are
implemented.

Supported match policy spellings are `exact`, `first-after`, `nearest`,
`stack-nested`, and `stream-order`. `exact` is valid only when both endpoints
share a deterministic CUPTI correlation key and their clocks are the same or
already aligned. `stack-nested` requires entry and return selectors for the
same host function. `stream-order` requires two GPU activity endpoints.
Temporal policies emit `HEURISTIC_CORRELATION`; broad kernel selectors emit
`BROAD_EVENT_SELECTOR`.

Malformed input, invalid regex syntax, unresolved symbols, and unknown policies
use the error envelope and a nonzero exit code. A well-formed request that
cannot run in the current target returns exit code zero with `ok: true`,
`valid: false`, and explicit issues. A missing CUPTI agent also reports whether
a target restart is required. Results conform to
`schemas/validate.schema.json`.

## `measure`

```bash
xprobe measure \
  --input /tmp/xprobe-host.json \
  --input /tmp/xprobe-cupti.bin \
  --from 'uprobe:/srv/app/libserver.so:handle_request:entry' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match first-after \
  --samples 100 \
  --json --non-interactive --no-color
```

For same-source exact correlation:

```bash
xprobe measure \
  --input /tmp/xprobe-cupti.bin \
  --from 'cuda:kernel_start:name~flash.*' \
  --to 'cuda:kernel_end:name~flash.*' \
  --match exact \
  --samples 100 \
  --json --non-interactive --no-color
```

For foreground collection from a running target:

```bash
xprobe measure \
  --pid 4242 \
  --cupti-socket /run/user/1000/xprobe-4242.sock \
  --from 'uprobe:/srv/app/libserver.so:handle_request:entry' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match first-after \
  --samples 100 \
  --timeout-ms 30000 \
  --json --non-interactive --no-color
```

The completed mode consumes one or more `--input` values. Supported formats are
CUPTI binary, a host capture result emitted by `dev uprobe --json`, and Event
JSONL. Repeat `--input` to merge sources. Inputs must contain events from one
PID; events are sorted and assigned a new measurement session identity. Drop
counters from capture envelopes are accumulated. Event JSONL has no envelope,
so it cannot carry a source-level drop count.

The live mode uses `--pid` instead of `--input`. It resolves and attaches each
unique host selector, waits for every BPF link to report readiness, and polls
the read-only CUPTI snapshot socket when either endpoint is CUDA. The agent must
have been loaded at target startup with `XPROBE_CUPTI_SOCKET` set. A baseline
snapshot excludes CUDA events recorded before the measurement. `--timeout-ms`
bounds collection and cleanup; reaching the sample limit returns `completed`,
while a timeout with partial matches returns `timed_out`. No matched pairs use
the standard `NO_MATCHED_SAMPLES` error envelope.

Host function entry/return, `cudaLaunchKernel` runtime API, kernel start/end,
memcpy start/end, and memset start/end selectors are supported. Memcpy
selectors accept the optional `kind=<HtoD|DtoH|DtoD|HtoH|PtoP>` filter. `exact`
joins CUDA endpoints on CUPTI correlation ID; host endpoints do not have that
key and reject `exact`. `first-after` performs a chronological one-to-one greedy
match and is always labeled `HEURISTIC_CORRELATION`.

At least one of `--samples` or `--duration-ms` is required. `--max-events`
defaults to 100,000 and rejects larger captures before correlation. Source
drops are included in the result and produce an `EVENTS_DROPPED` warning.
Unknown source records fail instead of being ignored.

Latency is calculated only when both endpoints use the same clock domain or
have already been normalized. Captures with the
`HOST_MONOTONIC_TIMESTAMPS` feature normalize GPU activity to host monotonic
time, so API-to-GPU measurement is supported. Captures without that feature
keep GPU activity in the CUPTI clock and API-to-GPU subtraction returns
`CLOCK_ALIGNMENT_FAILED`.

The result conforms to `schemas/measurement-result.schema.json`. No matched
pairs return `NO_MATCHED_SAMPLES`; unsupported policies and unbounded requests
use the standard error envelope.

## `dev cupti`

```bash
xprobe dev cupti \
  --input /tmp/xprobe-cupti.bin \
  --session-id xp_cuda_1 \
  --json --non-interactive --no-color
```

The command strictly validates the xprobe CUPTI binary ABI and emits one
versioned `Event` per line. CUDA API names are stored in
`attributes.cuda_api_name`; GPU records preserve the name supplied by CUPTI in
`cuda.kernel_name`. Transfer records expose byte count, memcpy kind, and memset
value; the latter is stored in `attributes.memset_value`. API and GPU records
expose the exact CUPTI correlation ID. The `HOST_MONOTONIC_TIMESTAMPS` feature
marks GPU records as CUPTI-normalized host monotonic timestamps, while
`TRANSFER_RECORDS` declares memcpy/memset record support. The serialized
activity value is preserved in `timestamp_raw`; CUPTI does not expose an
interpolation error bound, so `timestamp_error_ns` is null and measurement
emits `CLOCK_ERROR_UNAVAILABLE`.

Malformed headers, unsupported ABI versions or feature flags, invalid lengths,
unknown record kinds, and invalid names return `TRACE_EXPORT_FAILED`. Nonzero
dropped or unknown record counts are reported on stderr and are never silently
discarded.
