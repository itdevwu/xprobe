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

The environment contains Clang, CMake, Ninja, pkg-config, and Just. CUDA is not
installed into it yet because the implemented commands do not compile CUPTI or
CUDA code.

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

The CUPTI milestone should use an NVIDIA CUDA or NGC `devel` image containing
the CUDA headers, compiler, and CUPTI development files. When selected:

- pin a concrete image tag and digest in the repository;
- verify host-driver compatibility before compiling examples;
- validate GPU access with `docker run --rm --gpus all <image> nvidia-smi`;
- mount the repository read-write and build into a dedicated container target
  directory;
- do not use a floating `latest` tag;
- do not use `--privileged` for GPU-only tests.

eBPF attachment tests are host-sensitive and are separate from CUDA compilation
tests. Grant only the required BPF/perf capabilities and host PID visibility;
do not assume a CUDA container can attach host probes by default.
