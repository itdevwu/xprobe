# CLI contract

The CLI is designed for deterministic use by both humans and programs.

## Common behavior

Implemented commands accept:

```text
--json
--non-interactive
--no-color
```

In JSON mode, stdout contains exactly one JSON document. Human diagnostics and
logs belong on stderr. Commands never prompt for a target or wait for Enter.

Every JSON success or error carries `schema_version: "1.0"`. The checked-in
schemas are the machine-readable contract.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Command completed and emitted a result |
| `1` | Internal, I/O, or malformed-system-data failure |
| `2` | Invalid command-line arguments, emitted by Clap |
| `3` | Target not found, exited, or was reused |
| `4` | Permission denied while inspecting the target |

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
