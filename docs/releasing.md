# Releasing

Work on a feature or fix branch, rebase-merge the pull request into `master`,
then tag the merged commit. The steps below gate every release.

## 1. Prepare the version

Bump the workspace version in `Cargo.toml` and `CMakeLists.txt`, the installer
default in `install.sh`, the Skill's supported `major.minor.x` and install
links in `skills/xprobe-measure-latency/references/setup.md`, and the versioned
links in `README.md`, `docs/installation.md`, and `docs/agent-integration.md`.
`just test-agent-contract` checks that these agree.

A development release uses `X.Y.Z-dev.N` (CMake takes `X.Y.Z`). Its wheel is
PEP 440 `X.Y.Z.devN`, which `pip install xprobe` skips unless asked for with
`--pre` or an exact version, and its GitHub release is a prerelease that never
becomes latest. Tag it on the feature branch; it is not merged first.

## 2. Run the local live gate

GitHub Actions runs only what hosted runners support. Before tagging, run the
complete live suite on the NVIDIA development machine:

```bash
mamba env create --file environment-pytorch.yml
PYTORCH_ENV="$(mamba run -n xprobe-pytorch python -c 'import sys; print(sys.prefix)')" \
  just test-release-live
```

`environment-pytorch.yml` pins the PyTorch fixture: Python 3.11, because torch
2.3 Dynamo does not support 3.12, plus Triton and NumPy 1.x. The gate covers
BPF and perf attachment, CUDA 12 and 13, injection, NVTX, mixed host/GPU
collection, triage, PyTorch, concurrent workers, and the release benchmarks.

## 3. Package

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

Packaging checks both CUPTI SONAMEs, rejects build-time RPATHs, and rejects CLI
or Agent ELF dependencies above `GLIBC_2.34`. The archive test accepts a mocked
glibc 2.34 runtime, rejects 2.33, installs into a temporary prefix, runs the
binary, verifies both Agents, and uninstalls. The tag workflow independently
rebuilds both Agents, packages on Ubuntu 22.04, attests the archive and SBOM,
and publishes them.

The same job builds the PyPI wheel from the verified staging directory with
`scripts/build-wheel.py` and installs it with `tests/install/test_wheel.sh`.
After the GitHub release passes public verification, the `pypi` job publishes
the wheel through PyPI trusted publishing (OIDC, environment `pypi`; no token is
stored), then downloads it back from PyPI and repeats the installation test.

## 4. Verify the public release

A release is complete only after the public artifact passes:

```bash
scripts/verify-public-release.sh X.Y.Z
```

It downloads the published archive and checksum, verifies the SBOM, repeats the
installation test, and inspects every shipped ELF against the glibc ceiling.
