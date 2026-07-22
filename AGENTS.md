# xprobe engineering rules

## Sources of truth

- Code, tests, and checked-in JSON schemas define implemented behavior.
- `README.md` and `docs/` describe released behavior. Rewrite stale sections in
  place when behavior changes; do not append historical caveats or parallel
  inventories.
- Treat user reports and external reviews as evidence to investigate, not as
  implemented fact. Verify claims about bounds, clocks, filtering, lifecycle,
  and errors against code and tests before documenting or changing them.

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
- For an unknown workload, progress from readiness and baseline through a short
  survey artifact, evidence-based selector narrowing, validation, and one
  bounded measurement per stated hypothesis. Do not guess selectors.
- Read evidence pairs, artifact analysis, stream identity, collection quality,
  and profiler overhead before interpreting latency. Summed concurrent GPU
  duration is not wall time.
- Keep reusable analysis deterministic and bundled with the Skill. Keep model
  orchestration in the caller rather than adding CLI commands or a service.

## Release discipline

- Start post-release work on a dedicated feature or fix branch. Rebase pull
  requests into `master`; do not create merge commits.
- Build Linux release artifacts on Ubuntu 22.04 and enforce a GLIBC_2.34 ceiling
  for the CLI and every shipped Agent ELF.
- A release is complete only after downloading the public archive, checking its
  digest, testing installation, and inspecting all shipped ELF compatibility.
- Retry CI only when logs identify a transient infrastructure failure. Preserve
  real compiler, test, packaging, and compatibility failures for diagnosis.

## Verification

- Run `just fmt-check`, `just lint`, and `just test` for Rust changes.
- Run `just test-bpf-live` for BPF attachment changes.
- Run `just test-cupti-live` for CUPTI ABI or callback changes.
- Run `just test-injection-live` for injection or agent lifecycle changes.
- Run `just test-multisource-live` for host/GPU orchestration changes.
- Run `just test-agent-contract` for CLI, schema, docs, or Skill changes.
- Test bundled Skill scripts with deterministic fixtures and include them in
  `just test-agent-contract`.
- Run `just benchmark-gpu` for callback hot-path changes.
- Use emoji conventional commits, for example `🐛 fix: restore target registers`.
