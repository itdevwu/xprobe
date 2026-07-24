<div align="center">
  <h1>xprobe</h1>
  <p><strong><i>AI-native heterogeneous profiling tool for CPU and GPU.</i></strong></p>
  <p>
    <a href="https://github.com/itdevwu/xprobe/actions/workflows/ci.yml"><img alt="CI status" src="https://img.shields.io/github/actions/workflow/status/itdevwu/xprobe/ci.yml?branch=master&amp;style=for-the-badge&amp;label=CI"></a>
    <a href="https://github.com/itdevwu/xprobe/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/itdevwu/xprobe?style=for-the-badge&amp;sort=semver"></a>
    <a href="LICENSE"><img alt="Apache-2.0 license" src="https://img.shields.io/github/license/itdevwu/xprobe?style=for-the-badge&amp;label=License"></a>
    <a href="#support"><img alt="CUDA 12.x and 13.x" src="https://img.shields.io/badge/CUDA-12.x%20%7C%2013.x-76B900?style=for-the-badge&amp;logo=nvidia&amp;logoColor=white"></a>
  </p>
</div>

`xprobe` is an AI harness for measuring latency between two observable events
in a process, on the CPU, NVIDIA GPU, or across both. Its bounded native
profiler combines eBPF function, syscall, and tracepoint evidence with NVIDIA
CUPTI, an agent-friendly CLI, strict JSON contracts, explicit correlation
quality, and no daemon or server lifecycle.

## Install

Install the version-matched Skill with the open Agent Skills CLI. This is the
only installation action required from the user:

```bash
npx skills@1 add \
  https://github.com/itdevwu/xprobe/tree/v0.4.0/skills/xprobe-measure-latency \
  --global
```

The installer detects Codex, Claude Code, Cursor, and other compatible agents.
When invoked, the Skill checks for the matching `xprobe` CLI and installs or
repairs it under a writable prefix before profiling. It can then diagnose and
adjust path, permission, NVIDIA, CUDA, or CUPTI problems from live evidence.
Node.js is only needed for Skill installation, not for xprobe itself. See
[Installation](docs/installation.md) for direct CLI use and archive verification.

## Measure

Confirm the local capabilities first. `ok: true` means diagnosis completed;
read the individual checks before selecting events.

```bash
xprobe doctor --json --non-interactive --no-color

xprobe discover --pid 4242 --limit 50 \
  --json --non-interactive --no-color

xprobe validate --pid 4242 \
  --from 'cuda:runtime_api:cudaLaunchKernel:exit' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match exact --json --non-interactive --no-color

xprobe measure --pid 4242 \
  --from 'cuda:kernel_start' --to 'cuda:kernel_end' \
  --match exact --aggregate --duration-ms 1000 --max-groups 4096 \
  --json --non-interactive --no-color

xprobe measure --pid 4242 \
  --from 'cuda:runtime_api:cudaLaunchKernel:exit' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match exact --samples 100 --timeout-ms 30000 \
  --events-out /tmp/xprobe-events.jsonl \
  --json --non-interactive --no-color
```

Kernel launch latency is only one event pair. The same workflow measures host
function spans, syscall latency, named Linux events, CUDA API calls, GPU
operation durations, transfers, NVTX application ranges, and paths across CPU
and GPU events after selecting the correct process. Aggregate mode provides a
bounded coarse inventory of GPU operations before an exact evidence
measurement narrows the question.

`measure` also accepts completed `--input` captures and versioned live
`--spec` files. Evidence can be exported as `jsonl` or `chrome`. JSON results
contain every matched start/end event, latency statistics, unmatched and
ambiguous counts, collection completeness, CUPTI buffer usage, clock quality,
correlation confidence, and warnings. With `--events-out`, the bounded capture
is also preserved when correlation or clock validation fails.

## Public CLI

| Command | Purpose |
| --- | --- |
| `doctor` | Report local eBPF, ptrace, NVIDIA, CUDA, and CUPTI capabilities |
| `discover` | List NVML-confirmed CUDA context holders under a process-tree root |
| `validate` | Resolve two selectors and report collection, mutation, clock, and policy requirements without attaching |
| `measure` | Collect or import bounded events, correlate pairs, emit statistics and full event evidence |

`measure --pid` automatically loads the matching CUDA 12 or CUDA 13 CUPTI Agent
when a selected endpoint requires it. It reports the target mutation on stderr
and in JSON, disables collection afterward, and leaves the shared object mapped
for safe reactivation. NVTX ranges are the exception: set
`NVTX_INJECTION64_PATH` before the target's first NVTX call because online
attach cannot retrofit an initialized NVTX dispatch.

## Support

| Surface | Current support |
| --- | --- |
| OS/architecture | Linux x86_64, glibc 2.34 or newer |
| Host events | PID-scoped ELF function, named syscall, and tracepoint boundaries |
| CUDA callbacks | Runtime and Driver API entry/exit |
| GPU activity | Kernel, memcpy, and memset start/end |
| Application ranges | Bounded ASCII NVTX thread and process ranges |
| CUDA/CUPTI | 12.x and 13.x with automatic major selection |
| Correlation | exact, first-after, nearest, stack-nested, stream-order |
| Online injection | same mount namespace; ptrace permission required |

GPU-to-GPU durations remain available across the supported majors. Cross
CPU/GPU subtraction requires the Agent's runtime alignment check to pass;
otherwise `measure` returns `CLOCK_ALIGNMENT_FAILED` rather than treating an
offset CUPTI clock as host monotonic.

## Documentation

- [Installation](docs/installation.md)
- [Architecture](docs/architecture.md)
- [CLI contract](docs/cli-contract.md)
- [CUPTI agent and injection](docs/cupti-agent.md)
- [Development and hardware tests](docs/development.md)
- [Agent integration](docs/agent-integration.md)
- [Public JSON schemas](schemas/)

Source builds and hardware tests are documented under
[Development](docs/development.md). Implemented behavior is defined by code,
tests, and schemas. Licensed under Apache-2.0.
