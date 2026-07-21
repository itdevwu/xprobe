# xprobe engineering rules

## Sources of truth

- Code, tests, and checked-in JSON schemas define implemented behavior.
- `README.md` and `docs/` describe released behavior. Rewrite stale sections in
  place when behavior changes; do not append historical caveats or parallel
  inventories.

## Boundaries

- The public CLI is exactly `doctor`, `discover`, `validate`, and `measure`.
- Keep public contracts in `xprobe/protocol`, deterministic Linux logic in
  `xprobe/core`, collection in `xprobe/collector`, matching in
  `xprobe/correlator`, export in `xprobe/exporter`, and orchestration in the CLI.
- Do not add a daemon or persistent session service without a concrete workflow
  that cannot be expressed by the four bounded commands.
- Keep eBPF and CUPTI callback hot paths bounded and free of blocking I/O.

## Failures and safety

- Return malformed data, unexpected I/O, command failures, and cleanup failures
  as explicit errors. Do not replace them with defaults or partial success.
- Identify a process by PID plus procfs start time and verify it around attach.
- Every attach and injection path must restore target state on failure and have
  deterministic cleanup tests.
- `validate` is read-only. `measure` may inject CUPTI only after validation
  reports `injection_required`; log the mutation and include a JSON warning.
- Stop CUPTI logically after collection. Do not `dlclose` the injected agent.
- Never collect pointer-referenced payloads, environments, or GPU buffer data by
  default, and never describe temporal correlation as exact causality.

## Agent workflow

- Follow `skills/xprobe-measure-latency/SKILL.md` for measurement tasks.
- Use `doctor`, `discover`, `validate`, then one bounded `measure` call.
- Read evidence pairs and all quality fields before interpreting latency.

## Verification

- Run `just fmt-check`, `just lint`, and `just test` for Rust changes.
- Run `just test-bpf-live` for BPF attachment changes.
- Run `just test-cupti-live` for CUPTI ABI or callback changes.
- Run `just test-injection-live` for injection or agent lifecycle changes.
- Run `just test-multisource-live` for host/GPU orchestration changes.
- Run `just test-agent-contract` for CLI, schema, docs, or Skill changes.
- Run `just benchmark-gpu` for callback hot-path changes.
- Use emoji conventional commits, for example `🐛 fix: restore target registers`.
