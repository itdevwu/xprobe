# xprobe engineering rules

- Run `just test` after changing Rust code.
- Run `just test-bpf` after changing files under `bpf/`.
- Run `just test-cupti` after changing files under `cupti/`.
- Never perform blocking I/O inside a CUPTI callback.
- Never perform symbol resolution inside an eBPF hot path.
- Never collect pointer-referenced user data by default.
- Never describe heuristic correlation as exact causality.
- Do not implement runtime process injection without a separately approved design.
- Every attach path must have cleanup and failure-recovery tests.

