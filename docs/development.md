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
installed into the Mamba environment; reproducible CUPTI compilation and live
GPU tests use the pinned NVIDIA devel container instead.

## eBPF tests

Compile the BPF object without attaching it:

```bash
just test-bpf
```

Run the real PID-scoped uprobe and uretprobe test in the pinned container:

```bash
just test-bpf-live
```

The live test captures function entry and return events from the same target.
It requires Docker daemon access and grants the container `BPF`,
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

The live CUPTI test uses a pinned NVIDIA CUDA 13.3 devel image containing CUDA
headers, `nvcc`, and CUPTI:

```bash
just test-cupti-live
```

Run the combined host uprobe and CUPTI measurement test with both GPU and BPF
access:

```bash
just test-multisource-live
```

The test mounts the workspace read-only, compiles the agent and a CUDA fixture
inside the container, injects the agent at CUDA startup, and verifies three API
entries, API exits, kernel starts, and kernel ends, three memcpy intervals, and
one memset interval with matching correlation IDs. The resulting capture is
decoded by the host CLI and checked as ordered Event JSONL, then measured for
exact kernel, memcpy, memset, and API-to-kernel durations. The fixture queries
the GPU compute capability and compiles matching SASS so an older compatible
driver does not need to JIT CUDA 13.3 PTX.

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
