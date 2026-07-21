<div align="center">

# xprobe

_AI harness native profiler._

</div>

`xprobe` is a bounded Linux profiler for measuring time between host and NVIDIA
GPU events. It is designed for coding agents and performance engineers: four
commands, strict JSON contracts, explicit correlation quality, and no daemon or
server lifecycle.

## Public CLI

| Command | Purpose |
| --- | --- |
| `doctor` | Report local eBPF, ptrace, NVIDIA, CUDA, and CUPTI capabilities |
| `discover` | List host symbols, CUDA API selectors, and observable GPU activities for a PID |
| `validate` | Resolve two selectors and report collection, mutation, clock, and policy requirements without attaching |
| `measure` | Collect or import bounded events, correlate pairs, emit statistics and full event evidence |

`measure --pid` automatically loads the CUPTI agent when a CUDA endpoint needs
it. The command writes a warning to stderr and adds `CUPTI_AGENT_INJECTED` to
the JSON result. After collection it disables CUPTI and removes its socket, but
keeps `libxprobe-cupti.so` mapped so later measurements can reactivate it.

## Requirements

- Linux x86_64 and Rust 1.85 or newer
- Mamba/Conda for the native development toolchain
- eBPF privileges for host selectors
- ptrace permission for online CUPTI injection
- NVIDIA driver, CUDA, and CUPTI for GPU selectors

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

`measure` also accepts completed `--input` captures and versioned live
`--spec` files. Evidence can be exported as `jsonl` or `chrome`. JSON results
contain every matched start/end event, latency statistics, unmatched and
ambiguous counts, drops, clock quality, correlation confidence, and warnings.

## Install

Release archives contain `bin/xprobe`, `lib/xprobe/libxprobe-cupti.so`, the C
header, schemas, docs, and the repository Skill. To build the archive from a
CUDA devel environment:

```bash
just package
```

The packaging script rejects an ABI-only agent that is not linked to CUPTI.

## Support

| Surface | 0.1.0 support |
| --- | --- |
| OS/architecture | Linux x86_64 |
| Host events | ELF function entry/return through PID-scoped uprobes |
| CUDA callbacks | Runtime and Driver API entry/exit |
| GPU activity | Kernel, memcpy, and memset start/end |
| Correlation | exact, first-after, nearest, stack-nested, stream-order |
| Online injection | same mount namespace; ptrace permission required |
| Tested GPU | NVIDIA GeForce RTX 3060 Laptop GPU, driver 592.00, compute capability 8.6 |

## Documentation

- [Architecture](docs/architecture.md)
- [CLI contract](docs/cli-contract.md)
- [CUPTI agent and injection](docs/cupti-agent.md)
- [Development and hardware tests](docs/development.md)
- [Agent integration](docs/agent-integration.md)
- [Public JSON schemas](schemas/)

Implemented behavior is defined by code, tests, and schemas. [`PLAN.md`](PLAN.md)
is design history, not a release contract. Licensed under Apache-2.0.
