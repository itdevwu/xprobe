# Development environment

## Native toolchain

Rust is managed with `rustup`. Native build tools are isolated in the checked-in
Mamba environment:

```bash
mamba env create --file environment.yml
mamba activate xprobe-dev
just build
just test
```

The environment contains Clang, CMake, Ninja, pkg-config, Just, Python, and the
autotools required to compile vendored libbpf, libelf, and zlib. A system C
compiler and Linux UAPI/multiarch headers are also required. CUDA is not
installed into the Mamba environment. CI compiles CUDA 12 and CUDA 13 CUPTI
Agents without a GPU in pinned NVIDIA devel images, checks their SONAMEs, and
rejects ABI-only output or build-time RPATHs. Live CUDA behavior remains a
hardware test on an NVIDIA runner.

## Release packaging

A release archive requires one Agent built against each supported CUPTI major:

```bash
CUDA_PATH=/opt/cuda-12 cmake -S . -B build/cuda12 -G Ninja \
  -DXPROBE_BUILD_BPF=OFF -DXPROBE_REQUIRE_CUPTI=ON -DXPROBE_CUDA_MAJOR=12
cmake --build build/cuda12 --target xprobe-cupti

CUDA_PATH=/opt/cuda-13 cmake -S . -B build/cuda13 -G Ninja \
  -DXPROBE_BUILD_BPF=OFF -DXPROBE_REQUIRE_CUPTI=ON -DXPROBE_CUDA_MAJOR=13
cmake --build build/cuda13 --target xprobe-cupti

scripts/package-release.sh
tests/install/test_install.sh dist/xprobe-*-linux-x86_64.tar.gz
```

Packaging checks both CUPTI SONAMEs, rejects build-time RPATHs, and includes the
versioned installer. It also rejects CLI or Agent ELF dependencies above
`GLIBC_2.34`, matching the supported runtime floor and preventing a release
runner change from silently raising it. The archive test also accepts a mocked
glibc 2.34 runtime, rejects 2.33, installs into a temporary prefix, runs the
packaged binary, verifies both Agents and shared resources, and uninstalls it.

## eBPF tests

Compile the BPF object without attaching it:

```bash
just test-bpf
```

Run the real PID-scoped ELF and Linux event tests in the pinned container:

```bash
just test-bpf-live
```

The live suite captures function entry/return, mmap/munmap lifecycle, generic
raw tracepoint, and host-capacity failure paths from controlled targets. It
requires Docker daemon access and grants the container `BPF`,
`PERFMON`, `SYS_ADMIN`, and `SYS_RESOURCE`, with seccomp disabled for BPF/perf
syscalls. It does not use `--privileged`, does not require GPU access, mounts the
workspace read-only, and removes the container after the test.

## GPU checks

Run host diagnostics outside restricted sandboxes when GPU device access is
required:

```bash
nvidia-smi
xprobe doctor --json --non-interactive --no-color
```

Record the actual GPU model, driver version, compute capability, and available
memory in test output. Do not infer them from the machine description.

## CUDA container policy

GPU runtime smoke tests use a pinned CUDA 13.3 base image:

```bash
just gpu-smoke
```

The image reference includes the NGC digest in `justfile`. This check verifies
container runtime and driver access only; it does not provide CUDA headers or
CUPTI development files.

Live CUPTI tests use pinned NVIDIA CUDA 12.9 and CUDA 13.3 devel images
containing CUDA headers, `nvcc`, and CUPTI:

```bash
just test-cupti-live-cuda12
just test-cupti-live-cuda12-min
just test-cupti-live
```

The minimum-version check builds the release-style Agent with CUDA 12.9 and
runs it against CUDA 12.0. GPU-only durations remain available when the runtime
cannot prove host-clock alignment; cross CPU/GPU measurement then fails with
`CLOCK_ALIGNMENT_FAILED` instead of reporting a shifted latency.

Run online ptrace injection, stop, and reactivation twice against a target that
does not preload the agent:

```bash
just test-injection-live-cuda12
just test-injection-live
```

This container adds `SYS_PTRACE` and disables seccomp for ptrace only. It mounts
the workspace read-only and does not use `--privileged`.

Run the combined host uprobe and CUPTI measurement test with both GPU and BPF
access:

```bash
just test-multisource-live-cuda12
just test-multisource-live
```

Run the deterministic Agent-facing CLI contract test after changing commands,
schemas, Skills, or platform entry files:

```bash
just test-agent-contract
```

Run the CUDA Event precision and callback overhead benchmark after changing the
CUPTI timing or callback hot path:

```bash
just benchmark-gpu
```

Run the high-rate bounded-inventory benchmark after changing aggregate storage,
capacity, or activity accounting:

```bash
just benchmark-aggregate
```

Run the concurrent worker benchmark after changing multi-process Skill guidance
or per-worker orchestration:

```bash
just benchmark-multiprocess
```

See `docs/agent-integration.md` and `docs/benchmarks.md` for the tested contract
and benchmark interpretation.

The startup-injection test mounts the workspace read-only, compiles the agent
and a CUDA fixture inside the container, and verifies three API
entries, API exits, kernel starts, and kernel ends, three memcpy intervals, and
one memset interval with matching correlation IDs. The resulting capture is
decoded by the host CLI and checked as ordered Event JSONL, then measured for
exact kernel, memcpy, memset, and API-to-kernel durations. The fixture queries
the GPU compute capability and compiles matching SASS so the driver does not
need to JIT toolkit-version PTX.

Container policy:

- pin a concrete image tag and digest in the repository;
- verify host-driver compatibility before compiling examples;
- validate GPU access with `docker run --rm --gpus all <image> nvidia-smi`;
- mount the repository read-only and build in container-local temporary space;
- do not use a floating `latest` tag;
- do not use `--privileged` for GPU-only tests.

eBPF attachment tests are host-sensitive and are separate from CUDA compilation
tests. The target and collector run in the same container PID namespace; host
PID visibility is not required for the current fixture.
