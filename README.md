<div align="center">

# xprobe

_AI harness native profiler._

</div>

`xprobe` is a bounded Linux profiler for measuring time between two observable
events in a process, on the CPU, NVIDIA GPU, or across both. It is designed for
coding agents and performance engineers: four commands, strict JSON contracts,
explicit correlation quality, and no daemon or server lifecycle.

## Public CLI

| Command | Purpose |
| --- | --- |
| `doctor` | Report local eBPF, ptrace, NVIDIA, CUDA, and CUPTI capabilities |
| `discover` | List host symbols, CUDA API selectors, and observable GPU activities for a PID |
| `validate` | Resolve two selectors and report collection, mutation, clock, and policy requirements without attaching |
| `measure` | Collect or import bounded events, correlate pairs, emit statistics and full event evidence |

`measure --pid` automatically loads the CUPTI agent when a CUDA endpoint needs
it. CUDA 12 and CUDA 13 use separate shared objects selected from the target's
mapped CUDART/CUPTI major. The command writes a warning to stderr and adds
`CUPTI_AGENT_INJECTED` with the selected paths to the JSON result. After
collection it disables CUPTI and removes its socket, but keeps the Agent mapped
so later measurements can reactivate it.

## Requirements

- Linux x86_64 with glibc 2.35 or newer; Rust 1.85 or newer for source builds
- Mamba/Conda for the native development toolchain
- eBPF privileges for host selectors
- ptrace permission for online CUPTI injection
- NVIDIA driver plus CUDA/CUPTI 12.x or 13.x for GPU selectors

```bash
mamba env create --file environment.yml
mamba activate xprobe-dev
just build
just test
```

## Example

```bash
xprobe doctor --json --non-interactive --no-color

xprobe discover --pid 4242 --query launch --limit 50 \
  --json --non-interactive --no-color

xprobe validate --pid 4242 \
  --from 'cuda:runtime_api:cudaLaunchKernel:exit' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match exact --json --non-interactive --no-color

xprobe measure --pid 4242 \
  --from 'cuda:runtime_api:cudaLaunchKernel:exit' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match exact --samples 100 --timeout-ms 30000 \
  --events-out /tmp/xprobe-events.jsonl \
  --json --non-interactive --no-color
```

Kernel launch latency is only one possible event pair. The same workflow can
measure host function spans, GPU operation durations, transfers, and other
selector pairs exposed by the available collectors.

`measure` also accepts completed `--input` captures and versioned live
`--spec` files. Evidence can be exported as `jsonl` or `chrome`. JSON results
contain every matched start/end event, latency statistics, unmatched and
ambiguous counts, drops, clock quality, correlation confidence, and warnings.

## Install

Release archives contain `bin/xprobe`, CUDA 12 and CUDA 13 Agents under
`lib/xprobe/cuda12` and `lib/xprobe/cuda13`, the C header, schemas, docs, and
the repository Skill. Source packages require one Agent built with each major
toolkit before assembling the archive:

```bash
CUDA_PATH=/opt/cuda-12 cmake -S . -B build/cuda12 -G Ninja \
  -DXPROBE_BUILD_BPF=OFF -DXPROBE_REQUIRE_CUPTI=ON -DXPROBE_CUDA_MAJOR=12
cmake --build build/cuda12 --target xprobe-cupti

CUDA_PATH=/opt/cuda-13 cmake -S . -B build/cuda13 -G Ninja \
  -DXPROBE_BUILD_BPF=OFF -DXPROBE_REQUIRE_CUPTI=ON -DXPROBE_CUDA_MAJOR=13
cmake --build build/cuda13 --target xprobe-cupti

scripts/package-release.sh
```

The packaging script checks both CUPTI SONAMEs and rejects build-time RPATHs.

## Support

| Surface | 0.2.0 support |
| --- | --- |
| OS/architecture | Linux x86_64, glibc 2.35 or newer |
| Host events | ELF function entry/return through PID-scoped uprobes |
| CUDA callbacks | Runtime and Driver API entry/exit |
| GPU activity | Kernel, memcpy, and memset start/end |
| CUDA/CUPTI | 12.x and 13.x with automatic major selection |
| Correlation | exact, first-after, nearest, stack-nested, stream-order |
| Online injection | same mount namespace; ptrace permission required |
| Tested GPU | NVIDIA GeForce RTX 3060 Laptop GPU, driver 592.00, compute capability 8.6 |

GPU-to-GPU durations remain available across the supported majors. Cross
CPU/GPU subtraction requires the Agent's runtime alignment check to pass;
otherwise `measure` returns `CLOCK_ALIGNMENT_FAILED` rather than treating an
offset CUPTI clock as host monotonic.

## Documentation

- [Architecture](docs/architecture.md)
- [CLI contract](docs/cli-contract.md)
- [CUPTI agent and injection](docs/cupti-agent.md)
- [Development and hardware tests](docs/development.md)
- [Agent integration](docs/agent-integration.md)
- [Public JSON schemas](schemas/)

Implemented behavior is defined by code, tests, and schemas. Licensed under
Apache-2.0.
