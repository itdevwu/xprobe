# xprobe

`xprobe` is a deterministic Linux runtime probe for measuring latency between
host events and NVIDIA GPU events. It is designed for both performance
engineers and coding agents through a non-interactive CLI and versioned JSON
contracts.

The project is at the initial scaffolding stage. See [PLAN.md](PLAN.md) for the
architecture and delivery plan.

## Build

Requirements:

- Rust 1.85 or newer
- CMake 3.20 or newer
- Clang with the BPF target for the eBPF object
- NVIDIA CUDA Toolkit for the future CUPTI collector implementation

```bash
just build
just test
```

If Clang is unavailable, CMake keeps the host/CUPTI skeleton buildable and
reports that the eBPF object was skipped.

