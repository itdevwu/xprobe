# CUPTI agent

The CUPTI agent is a bounded in-process collector. It records:

- `cudaLaunchKernel` API entry and exit;
- concurrent GPU kernel start and end;
- GPU memcpy and memset start and end;
- CUPTI correlation, context, stream, device, grid, and block identifiers.
- transfer byte counts, memcpy direction, and memset value.

The agent does not read kernel arguments or GPU memory.

## Loading

Build `libxprobe-cupti.so` with CUDA and CUPTI development files visible through
`CUDA_PATH`, `CUDA_HOME`, or `/usr/local/cuda`. Without those files, CMake builds
an ABI-only library that reports `XPROBE_CUPTI_AGENT_UNAVAILABLE`.

For an unmodified CUDA application, load the full agent at CUDA startup:

```bash
XPROBE_CUPTI_OUTPUT=/tmp/xprobe-cupti.bin \
CUDA_INJECTION64_PATH=/absolute/path/libxprobe-cupti.so \
./cuda-application
```

CUDA calls the exported `InitializeInjection` function. The agent force-flushes
the capture from an exit handler registered during initialization. Frameworks
that already load plugins may call `xprobe_cupti_agent_initialize` before the
first CUDA API and `xprobe_cupti_agent_flush` after device synchronization.
Initialization is idempotent. Runtime attachment to an already-running process
is not supported.

## Capture ABI

The output begins with a 48-byte `xprobe_cupti_output_header`, followed by
`record_count` fixed 200-byte `xprobe_cupti_record` values. The public C layout
and enum values are defined in `cupti/include/xprobe/cupti_agent.h` and versioned
by `XPROBE_CUPTI_AGENT_ABI_VERSION`.

Record kinds are API entry/exit and GPU kernel, memcpy, and memset start/end.
Related records use the same CUPTI correlation ID. Unknown numeric fields are
`UINT32_MAX`; names are bounded, null-terminated byte strings. The header
reports records dropped after the fixed 65,536-record capacity and unexpected
activity kinds.

ABI v2 registers a `CLOCK_MONOTONIC` timestamp callback before enabling any
activity kind. CUPTI uses that callback to linearly normalize GPU activity
timestamps during post-processing. ABI v3 adds transfer record kinds and
kind-dependent payload fields while retaining the 48-byte header and 200-byte
record layout. ABI v1 and v2 remain supported for existing captures.

The runtime callback performs no allocation or file I/O. It captures a host
timestamp and reserves a record slot atomically. CUPTI activity buffers are
parsed by the activity completion callback. Final flush waits for asynchronous
buffer completion before writing the capture with mode `0600`.

## Verification

```bash
just test-cupti
just test-cupti-live
```

The host test verifies the public ABI even when CUDA development files are not
installed. The live test uses the digest-pinned NGC devel image and requires
Docker GPU access.

Decode a completed capture into the shared Event JSONL format:

```bash
target/debug/xprobe dev cupti \
  --input /tmp/xprobe-cupti.bin \
  --session-id xp_cuda_1 \
  --json --non-interactive --no-color
```

Measure correlated events in a completed capture:

```bash
target/debug/xprobe measure \
  --input /tmp/xprobe-cupti.bin \
  --from 'cuda:kernel_start:name~kernel.*' \
  --to 'cuda:kernel_end:name~kernel.*' \
  --match exact --samples 100 \
  --json --non-interactive --no-color
```

CUPTI API callback timestamps use host monotonic time. In capture ABI v2 and
newer, CUPTI normalizes GPU activity to the same clock before the agent writes
the record. The measurement command therefore supports exact API-to-GPU
subtraction and exact kernel/transfer duration measurement.
