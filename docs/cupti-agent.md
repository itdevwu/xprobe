# CUPTI agent and online injection

`libxprobe-cupti.so` collects CUDA Runtime/Driver callback boundaries and
concurrent kernel, memcpy, and memset activity. The public CLI normally manages
it through `measure --pid`; applications do not need to preload it.

## Lifecycle

1. `measure` validates the selectors and inspects mapped libraries.
2. If the agent is absent, xprobe warns and remotely calls target `dlopen` and
   `dlsym` through ptrace.
3. `xprobe_cupti_agent_start(socket_path)` resets bounded state, subscribes
   callbacks/activity, and starts a mode-0600 Unix socket.
4. Snapshot requests force-flush CUPTI and return one immutable ABI capture.
5. Stop returns a final capture, disables activities, unsubscribes callbacks,
   closes/unlinks the socket, and leaves the library mapped.
6. A later start repeats from fresh counters without another `dlopen`.

The target and xprobe must use the same mount namespace. ptrace credentials,
Yama, seccomp, and LSM policy apply. xprobe does not use a hypothetical
cross-process CUPTI attach API; CUPTI's dynamic attach APIs run inside the
target process.

The exported compatibility entry points remain:

- `InitializeInjection` for `CUDA_INJECTION64_PATH` startup injection;
- `xprobe_cupti_agent_initialize` for environment-configured integration;
- `xprobe_cupti_agent_flush` for completed file output;
- status and ABI-version queries.

Do not `dlclose` the agent in a live CUDA process. Callback or activity code may
still be referenced by the CUDA/CUPTI runtime even after logical stop.

## Control protocol

Each Unix socket connection sends a fixed 16-byte native-endian request:

```text
magic[8] = "XPCTRL\0\0"
version  = 1 (u32)
command  = 1 snapshot | 2 stop (u32)
```

The response is the capture ABI followed by EOF. Invalid requests are logged
and closed without a capture.

## Capture ABI v1

The response starts with a 48-byte header and zero or more 200-byte records.
The header contains magic `XPCUPTI\0`, ABI/header/record sizes, feature flags,
record count, drops, and unknown-record count. The C layout is defined in
`cupti/include/xprobe/cupti_agent.h`.

Feature flags declare host-monotonic activity timestamp normalization and
transfer records. Records preserve PID/TID, device/context/stream, CUPTI
correlation IDs, callback domain/ID, dimensions or transfer metadata, and a
bounded name. The maximum retained record count is 65,536; overflow increments
the drop counter.

CUPTI does not expose a numeric bound for its GPU-to-host interpolation.
Normalized activity therefore has `timestamp_error_ns: null`, and measurement
emits `CLOCK_ERROR_UNAVAILABLE`.

## Callback constraints

The API callback reads time and fixed metadata and commits one preallocated
record. It performs no allocation, file I/O, socket I/O, symbolization, or
blocking synchronization. Activity buffers are allocated and decoded through
CUPTI's activity callbacks. Snapshot/stop flushing runs on the socket thread.

## Build and test

```bash
just test-cupti
just test-cupti-live
just test-injection-live
just test-multisource-live
just benchmark-gpu
```

`test-injection-live` starts a CUDA target with no preload, runs two sequential
measurements, verifies first-load and reactivation behavior, checks socket
cleanup, and confirms one mapped agent path. The pinned CUDA devel container
compiles the agent against CUPTI; the tested device is an NVIDIA GeForce RTX
3060 Laptop GPU, driver 592.00, compute capability 8.6.
