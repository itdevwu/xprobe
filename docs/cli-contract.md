# CLI contract

xprobe 0.2.1 exposes exactly four public commands: `doctor`, `discover`,
`validate`, and `measure`.

## Common behavior

All commands support `--json --non-interactive --no-color`. JSON mode writes one
versioned document to stdout. Diagnostics, including the online-injection
warning, go to stderr. Commands never prompt.

Success and error records carry `schema_version: "1.0"`. Unknown JSON fields
and unsupported schema versions are rejected.

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
xprobe discover --pid 4242 [--query launch] [--limit 200] \
  --json --non-interactive --no-color
```

Reads target procfs and mapped ELF files without attaching. Results conform to
`schemas/discover.schema.json` and contain selectors, source, event type,
origin, binary/symbol evidence, and `requires_observation`. `limit` must be
positive. `total_matches` and `truncated` describe bounded output. Inaccessible
mapped files produce explicit warnings.

Host selector forms are:

```text
uprobe:<binary>:<symbol>:entry
uprobe:<binary>:<symbol>:return
uprobe:<binary>:+0x<file-offset>:entry
uprobe:<binary>:+0x<file-offset>:return
```

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
`stream-order`. Exact requires deterministic CUPTI correlation IDs. Nested
requires entry/return of the same host function. Stream order requires GPU
activity endpoints. Temporal policies always warn that they are heuristic.

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

Exactly one source mode is used: `--pid`, one or more `--input`, or `--spec`.
At least one positive `--samples` or `--duration-ms` bound is required in direct
mode. `--timeout-ms` defaults to 30 seconds and `--max-events` to 100,000.

Live host endpoints attach PID-scoped eBPF probes. CUDA endpoints automatically
activate the CUPTI agent. If it is absent, `--agent` or
`XPROBE_CUPTI_AGENT_PATH` selects the shared object; otherwise xprobe searches
`../lib/xprobe/cuda12` or `../lib/xprobe/cuda13` according to the target and
then the matching development build path. An unobservable target major is
accepted only when exactly one supported CUPTI major is installed. Injection
requires Linux x86_64, a shared mount namespace, and ptrace permission. It emits
a stderr warning and `CUPTI_AGENT_INJECTED`. Final stop disables CUPTI and
removes the socket while leaving the `.so` mapped.

Completed inputs may be CUPTI ABI binary, bounded host-capture JSON, or Event
JSONL. Repeated inputs are merged after target-PID checks. Unknown records,
mixed targets, malformed captures, and excessive event counts fail explicitly.

Results conform to `schemas/measurement-result.schema.json` and contain:

- status and latency statistics;
- matched, unmatched, ambiguous, and dropped counts;
- method, confidence, and score;
- clock alignment and optional estimated error;
- host/CUDA collection totals;
- full start/end events plus latency for each evidence pair;
- structured warnings.

`--events-out PATH` writes the deduplicated events used by matched pairs with
mode `0600`. The default format is JSONL; `--format chrome` writes Chrome Trace
Event Format. This folds evidence export into `measure` rather than requiring a
separate public command.

No matched pairs return `NO_MATCHED_SAMPLES`. Cross-clock subtraction without
declared alignment returns `CLOCK_ALIGNMENT_FAILED`. Drops and unknown clock
error are never silently converted to high-quality results.

## Compatibility

Earlier low-level command spellings remain hidden during the pre-1.0 transition so
existing integration fixtures can decode captures. They are not public API and
must not be used by Skills or new automation.
