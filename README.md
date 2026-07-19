# xprobe

`xprobe` is a deterministic Linux runtime probe for measuring latency between
host events and NVIDIA GPU events. Its public interface is a non-interactive
CLI with versioned JSON contracts, intended for both performance engineers and
coding agents.

The repository is under active development. The current executable discovers
local tracing capabilities and inspects target processes; probe attachment and
CUDA activity collection are not implemented yet.

## Current capabilities

| Area | Status |
| --- | --- |
| `doctor` environment inspection | Implemented |
| `inspect --pid` process inspection | Implemented |
| Versioned Event, Error, Capability, Inspect, and Measurement schemas | Implemented |
| eBPF build pipeline | Minimal buildable probe only |
| CUPTI agent | ABI skeleton only |
| Probe attachment, collection, correlation, and export | Planned |

## Quick start

Requirements:

- Rust 1.85 or newer, managed with `rustup`
- Mamba or Conda
- Linux x86_64

```bash
mamba env create --file environment.yml
mamba activate xprobe-dev
just build
just test
```

Inspect the current environment and a target process:

```bash
target/debug/xprobe doctor --json --non-interactive --no-color
target/debug/xprobe inspect --pid <pid> --json --non-interactive --no-color
```

Machine-readable results are written to stdout. Runtime logs and human errors
are written to stderr.

## Documentation

- [Architecture](docs/architecture.md)
- [CLI contract](docs/cli-contract.md)
- [Development environment](docs/development.md)
- [Public JSON schemas](schemas/)

[`PLAN.md`](PLAN.md) records design exploration and future ideas. It is useful
background, but it is not a normative description of implemented behavior.

## Project principles

```text
The caller decides what to observe.
xprobe validates and measures.
The caller interprets the evidence.
```

`xprobe` does not call model APIs, infer causality from temporal proximity, or
inject libraries into running processes by default.
