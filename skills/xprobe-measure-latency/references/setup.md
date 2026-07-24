# Setup

Use this reference at the start of a task when the CLI is absent or its version
does not match this Skill. The user installs this Skill once; the agent performs
and verifies the CLI bootstrap. Do not ask the user to run a second installation
command unless their environment prevents the agent from writing a usable prefix.

## Check and bootstrap xprobe

Check the executable first. Continue only when it reports 0.3.3; otherwise run
the bootstrap below:

```bash
if command -v xprobe >/dev/null 2>&1; then
  xprobe --version
fi
```

Download the released bootstrap, which verifies the release archive before
installing under `~/.local`:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/itdevwu/xprobe/v0.3.3/install.sh \
  -o /tmp/xprobe-install.sh
sh /tmp/xprobe-install.sh
export PATH="$HOME/.local/bin:$PATH"
xprobe --version
xprobe doctor --json --non-interactive --no-color
```

Use the downloaded script's `--prefix` option for another installation root.
Export that prefix's `bin` directory into `PATH`, rerun `xprobe --version`, then
run `xprobe doctor --json --non-interactive --no-color`. Surface bootstrap,
PATH, permission, driver, CUDA, or CUPTI failures explicitly and adjust from the
reported detail; do not continue to measurement on an unverified installation.
The CLI needs no Node.js. CUDA is optional until a GPU selector is measured.

## Build locally when the release is unsuitable

The `glibc 2.34` requirement applies to the precompiled release archive. When
that archive cannot run on the host, build the matching source locally with the
host glibc instead. This is a local-use fallback, not permission to weaken the
release package's `GLIBC_2.34` ceiling.

```bash
git clone --depth 1 --branch v0.3.3 https://github.com/itdevwu/xprobe.git
cd xprobe
mamba env create --file environment.yml
mamba run -n xprobe-dev just build
export PATH="$PWD/target/debug:$PATH"
xprobe --version
xprobe doctor --json --non-interactive --no-color
```

For CPU-only work, this build is sufficient; no CUDA toolkit or CUPTI Agent is
required. Do not use `scripts/package-release.sh` for this path because it
enforces the distributable archive compatibility policy.

For GPU or mixed work, build one local Agent against the target's CUDA 12 or
CUDA 13 toolkit, then point the CLI at it:

```bash
mamba run -n xprobe-dev env CUDA_PATH=/opt/cuda-12 cmake -S . -B build/cuda12 -G Ninja \
  -DXPROBE_BUILD_BPF=ON -DXPROBE_REQUIRE_CUPTI=ON -DXPROBE_CUDA_MAJOR=12
mamba run -n xprobe-dev cmake --build build/cuda12 --target xprobe-bpf xprobe-cupti
export XPROBE_CUPTI_AGENT_PATH="$PWD/build/cuda12/cupti/libxprobe-cupti.so"
```

Replace `12` and the toolkit path with `13` for CUDA 13. CUDA/CUPTI majors other
than 12 or 13 are not supported: do not force an Agent build or bypass the
version check. For an NVTX range measurement, start or restart the target with
the same local Agent configured before the target's first NVTX call:

```bash
NVTX_INJECTION64_PATH="$XPROBE_CUPTI_AGENT_PATH" python serve.py
```

Record the new PID plus procfs start time and run `validate` again. Do not use
online injection as a fallback for an already initialized NVTX process.

## Repair the Skill only when needed

The user normally installed this Skill before invoking the agent. When its files
are missing or the version is not 0.3.3, install the complete version-matched
directory through the Agent Skills CLI:

```bash
npx skills@1 add \
  https://github.com/itdevwu/xprobe/tree/v0.3.3/skills/xprobe-measure-latency \
  --global
```

For non-interactive automation, select the host explicitly:

```bash
npx --yes skills@1 add \
  https://github.com/itdevwu/xprobe/tree/v0.3.3/skills/xprobe-measure-latency \
  --agent codex --global --copy --yes
```

Replace `codex` with `claude-code` or `cursor` as needed. Omit `--global` for a
repository-scoped installation. Without Node.js, copy the full Skill directory
from the release archive into the target agent's documented Skill location; do
not copy only `SKILL.md`, because its references, examples, and analyzer are
part of the contract.
