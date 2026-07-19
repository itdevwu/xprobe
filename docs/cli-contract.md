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
  --probe-id 7 \
  --samples 100 \
  --timeout-ms 5000 \
  --json --non-interactive --no-color
```

The command captures function-entry events only. `--binary` must resolve to the
target executable or a shared library visible in `/proc/<pid>/maps`; otherwise
the command returns `BINARY_NOT_MAPPED`. `--samples` and `--timeout-ms` must both
be greater than zero.

The result conforms to `schemas/host-capture.schema.json`. Reaching the deadline
before the requested sample count is a successful bounded capture with
`timed_out: true`; attachment, map, malformed-record, permission, and target
identity failures use the standard error envelope. Events contain host
monotonic nanoseconds, a sequence number, namespace-local PID/TID, CPU, probe
id, binary path, and symbol. Argument capture and return probes are not yet
implemented.

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
`cuda.kernel_name`. API and GPU records expose the exact CUPTI correlation ID.
Their clock domains remain explicit until a later clock normalization stage.

Malformed headers, unsupported ABI versions, invalid lengths, unknown record
kinds, and invalid names return `TRACE_EXPORT_FAILED`. Nonzero dropped or
unknown record counts are reported on stderr and are never silently discarded.
