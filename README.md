# xprobe

`xprobe` is a deterministic Linux runtime probe for measuring latency between
host events and NVIDIA GPU events. Its public interface is a non-interactive
CLI with versioned JSON contracts, intended for both performance engineers and
coding agents.

The repository is under active development. The current executable discovers
local tracing capabilities, inspects target processes, and captures bounded
userspace function-entry events with eBPF uprobes. It also resolves symbol and
file-offset probe selectors against live PIE executables and shared libraries.
Its in-process CUPTI agent captures CUDA launch boundaries and correlated GPU
kernel intervals to a versioned binary stream.

## Current capabilities

| Area | Status |
| --- | --- |
| `doctor` environment inspection | Implemented |
| `inspect --pid` process inspection | Implemented |
| Versioned public JSON schemas | Implemented |
| `resolve` for PIE, shared libraries, symbols, offsets, and Build IDs | Implemented |
| Deterministic selector and correlation validation | Implemented |
| PID-scoped eBPF uprobe collection | Implemented through `dev uprobe` |
| eBPF build pipeline | Embedded libbpf object and ring buffer |
| CUPTI agent | Runtime launch callbacks and concurrent-kernel activity |
| CUDA raw capture | Startup injection or explicit application integration |
| Unified Event JSONL | Implemented for uprobe and CUPTI captures |
| Completed-capture exact and first-after measurement | Implemented for CUDA API and kernel events |
| CUPTI-to-host clock normalization | Implemented in capture ABI v2 |
| Live host and CUDA capture correlation | Planned |

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
target/debug/xprobe resolve --pid <pid> \
  --selector 'uprobe:/path/to/lib.so:function_name:entry' \
  --json --non-interactive --no-color
target/debug/xprobe validate --pid <pid> \
  --from 'uprobe:/path/to/lib.so:function_name:entry' \
  --to 'cuda:kernel_start:name~kernel.*' --match first-after \
  --json --non-interactive --no-color
target/debug/xprobe dev uprobe --pid <pid> --binary <path> --symbol <symbol> \
  --samples 10 --timeout-ms 5000 --json --non-interactive --no-color
target/debug/xprobe dev cupti --input /tmp/xprobe-cupti.bin \
  --session-id xp_cuda_1 --json --non-interactive --no-color
target/debug/xprobe measure --input /tmp/xprobe-cupti.bin \
  --from 'cuda:kernel_start:name~kernel.*' \
  --to 'cuda:kernel_end:name~kernel.*' --match exact --samples 100 \
  --json --non-interactive --no-color
```

Machine-readable results are written to stdout. Runtime logs and human errors
are written to stderr.

## Documentation

- [Architecture](docs/architecture.md)
- [CLI contract](docs/cli-contract.md)
- [Development environment](docs/development.md)
- [CUPTI agent](docs/cupti-agent.md)
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
