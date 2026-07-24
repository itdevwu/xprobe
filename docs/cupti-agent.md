# CUPTI Agent and online injection

`libxprobe-cupti.so` collects CUDA Runtime/Driver callback boundaries,
kernel/memcpy/memset activity, and selected NVTX timeline range boundaries
inside the target process. Normal users invoke it through `measure --pid`; it
is a bounded collector, not a daemon or a persistent profiling session.

Release packages contain separate Agents linked to `libcupti.so.12` and
`libcupti.so.13`. xprobe selects the major from the target's mapped CUDA
libraries, or from one unambiguous installed CUPTI major when the target does
not expose one. A conflict, unsupported major, or missing Agent fails before
ptrace attachment.

## Measurement lifecycle

Validation is read-only. When it reports `injection_required`, `measure` warns
before remotely calling target-side `dlopen`, `dlsym`, and
`xprobe_cupti_agent_start` through ptrace. Loading the shared object establishes
a mode-0600 Unix control socket but does not start CUPTI collection.

Each measurement sends `ARM` with its event capacity and at most two endpoint
filters. The Agent allocates fresh capture storage, installs the filters, and
then enables callbacks and activity collection. API names and domains, memcpy
directions, and simple kernel-name exact/prefix/suffix/contains patterns are
filtered before they consume capture capacity. Complex kernel regular
expressions use a wider Agent filter and retain exact Rust-side matching.

NVTX differs from ordinary online CUDA injection. Set
`NVTX_INJECTION64_PATH` to the matching Agent before the target's first NVTX
call; an initialized NVTX dispatch cannot be retrofitted by attach. Startup
installs routing and a dormant CUPTI subscriber. ARM enables only range
StartA/StartEx/End and PushA/PushEx/Pop callbacks, with bounded name matching
before timestamping or table insertion. STOP disables those callbacks but
retains the subscriber because CUDA 13 still references it. The Agent copies
only ASCII range names, IDs, kind, and thread identity. It does not copy NVTX
payload, color, category, registered strings, wide strings, or environments.

An aggregate ARM uses a fixed-capacity hash table instead of event records.
Kernel activity is grouped by name and device, memcpy by direction and device,
and memset by device. The activity callback updates count, total/min/max
duration, and transfer bytes without materializing start/end events. Aggregate
collection uses one final CLI read instead of incremental snapshots, and table
saturation fails instead of returning a sampled inventory.

`SNAPSHOT` flushes pending activity and returns records after the caller's
checked record offset. The CLI accumulates only contiguous deltas rather than
retransferring and decoding the growing capture. `STOP` returns the final delta
and disables CUPTI while retaining the socket, so a preloaded Agent can service
a later bounded measurement. An automatically injected measurement uses
`CLOSE`, which performs the same logical stop and then removes its private
socket. In both cases the shared object remains mapped; it must not be passed to
`dlclose` while CUDA may still reference callback code.

Activity records that began before the ARM epoch are excluded as a whole. This
prevents CUPTI's boundary records, which can have an unavailable start
timestamp, from becoming malformed or unmatched in-window evidence.

The target and xprobe must share a mount namespace. ptrace credentials, Yama,
seccomp, and LSM policy still apply. Every remote call restores the stopped
thread's registers and touched stack state before detach, including failure
paths.

## Control and capture ABI

Control version 4 uses one fixed 328-byte native-endian request defined by
`cupti/include/xprobe/cupti_agent.h`. It contains magic, version, command,
capacity, record offset, capture mode, and two fixed endpoint filters. Commands
are `ARM`, `SNAPSHOT`, `STOP`, and `CLOSE`. Exact ARM requires offset zero;
later exact commands return records at or after the requested offset followed
by EOF. Aggregate mode requires offset zero for every command.

Capture ABI v4 starts with an 88-byte header and zero or more 200-byte records.
The header reports capture state and stop reason, configured capacity, observed
and retained counts, Agent and CUPTI drops, unknown activity, record sizes, and
feature flags. It also reports the payload record offset so the caller can
reject gaps, replays, and counter rollback. Exact capacity comes from
`--max-events` and aggregate table capacity from `--max-groups`; there is no
special 2^16 limit. Reaching either configured limit freezes capture and causes
measurement to fail explicitly instead of returning partial success.

Exact records preserve process/thread, device/context/stream, correlation IDs,
callback domain/ID, dimensions or transfer metadata, and one bounded name.
NVTX records reuse the fixed layout for a 64-bit range ID, thread/process kind,
start thread, and explicit name completeness flag. Their exact correlation is
range identity, including a synthesized TID plus nesting level for thread
ranges; it is not a claim that arbitrary adjacent events are causally related.
Aggregate records contain a bounded group key and exact integer counters, not
event evidence or a latency distribution; they therefore do not report
percentiles or correlation confidence.
Activity timestamps are normalized to `CLOCK_MONOTONIC` through the CUPTI
timestamp callback or CUDA 12 clock calibration. If alignment cannot be
established, GPU durations remain usable in the CUPTI domain but host/GPU
subtraction fails with `CLOCK_ALIGNMENT_FAILED`. CUPTI provides no numeric
interpolation error bound, so normalized results emit
`CLOCK_ERROR_UNAVAILABLE`.

## Hot-path constraints

ARM enables only activity families and Runtime/Driver callback IDs required by
the validated endpoints. The API callback checks its fixed filter before
reading time or constructing a record. Activity decoding checks event family,
name, and transfer direction before copying fixed metadata, and stops
converting records after the capture limit. These paths do not allocate,
perform file or socket I/O, symbolize names, or take blocking locks. NVTX range
callbacks use only fixed records and a preallocated table; CUPTI Range
Profiling metrics and replay are outside this timeline collector. Flushing,
control, and incremental response I/O run on the control thread.

## Verification

`just test-cupti-live` checks ABI and activity collection. `just
test-injection-live` performs first-load and reactivation measurements against
one mapped Agent. `just test-multisource-live` covers host/GPU orchestration and
repeated ARM/STOP windows. CUDA 12 variants exercise the same paths against the
other linked major, and `just benchmark-gpu` checks callback overhead and
timestamp precision. `just benchmark-aggregate` drives a high-rate two-kernel
workload and compares bounded aggregation with raw broad capture for collection
completeness, process resources, and artifact size.
