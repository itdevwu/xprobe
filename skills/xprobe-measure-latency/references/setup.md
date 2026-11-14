# Setup

The user installs this Skill once; the agent bootstraps and verifies the CLI.
Offline analysis of an existing artifact needs no CLI.

## Check and bootstrap xprobe

This Skill supports xprobe `0.5.x`. Install the matching release when the CLI is
absent, reports another version, or fails a required capability:

```bash
command -v xprobe >/dev/null 2>&1 && xprobe --version
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/itdevwu/xprobe/v0.5.2/install.sh \
  -o /tmp/xprobe-install.sh
sh /tmp/xprobe-install.sh
export PATH="$HOME/.local/bin:$PATH"
xprobe --version
xprobe doctor
```

The bootstrap verifies the archive and installs under `~/.local`; pass
`--prefix DIR` for another root and export its `bin`. Surface PATH,
permission, driver, CUDA, or CUPTI failures from `doctor` details; do not
measure on an unverified installation. CUDA is needed only for GPU selectors.

## Containerized live target

A host-side `measure` cannot inject into a target with a different mount
namespace. Run xprobe in the application container itself, or through a
launcher that enters both its PID and mount namespaces; a sidecar is not
equivalent. Do not guess a pod, container, or PID: identify the container from
workload evidence first.

Inside, resolve the namespace-local PID and its `/proc/PID/stat` start time
again, rerun `doctor` and `validate` there, and write outputs to a path shared
with the caller. Entering a namespace does not add capabilities the container
was not granted: report missing ptrace, perf, BPF, NVIDIA device, or CUPTI
access as an environment failure instead of falling back to host-side
injection.

## Build locally when the release cannot run

The release archive needs host glibc 2.34 or newer. Otherwise build the
matching source with the host glibc:

```bash
git clone --depth 1 --branch v0.5.2 https://github.com/itdevwu/xprobe.git
cd xprobe
mamba env create --file environment.yml
mamba run -n xprobe-dev just build
export PATH="$PWD/target/debug:$PATH"
```

That suffices for CPU work. For GPU work, build one Agent against the target's
CUDA 12 or 13 toolkit and export it:

```bash
mamba run -n xprobe-dev env CUDA_PATH=/opt/cuda-12 cmake -S . -B build/cuda12 -G Ninja \
  -DXPROBE_BUILD_BPF=ON -DXPROBE_REQUIRE_CUPTI=ON -DXPROBE_CUDA_MAJOR=12
mamba run -n xprobe-dev cmake --build build/cuda12 --target xprobe-bpf xprobe-cupti
export XPROBE_CUPTI_AGENT_PATH="$PWD/build/cuda12/cupti/libxprobe-cupti.so"
```

CUDA/CUPTI majors other than 12 or 13 are not supported. Do not use
`scripts/package-release.sh` for a local build; it enforces the release glibc
ceiling.

## NVTX ranges

Online injection cannot attach to an already initialized NVTX dispatch. Restart
the target with the Agent configured before its first NVTX call, record the new
PID and start time, and validate again:

```bash
NVTX_INJECTION64_PATH="$XPROBE_CUPTI_AGENT_PATH" python serve.py
```

## Repair the Skill

When Skill files are missing or mismatched, reinstall the whole directory; its
references, examples, and analyzer are part of the contract:

```bash
npx skills@1 add \
  https://github.com/itdevwu/xprobe/tree/v0.5.2/skills/xprobe-measure-latency \
  --global
```
