# xprobe engineering rules

## Sources of truth

- Implemented behavior is defined by code, tests, and checked-in JSON schemas.
- `README.md` and `docs/` describe supported behavior and must change with it.
- `PLAN.md` is non-normative design input; do not implement a claim solely
  because it appears there.

## Module boundaries

- Keep versioned public data contracts in `xprobe/protocol`.
- Keep deterministic process and environment logic in `xprobe/core`.
- Keep argument parsing, rendering, and exit-code mapping in `xprobe/cli`.
- Keep eBPF hot-path code under `bpf/` minimal: timestamp, identity, bounded
  field reads, filtering, map updates, and ring-buffer writes only.
- Never perform blocking I/O, symbolization, or heavy allocation in a CUPTI
  callback.

## Failure behavior

- Return errors for malformed data and unexpected I/O or command failures.
- Convert an error into unavailable or restricted capability only when that
  state is expected and is reported explicitly.
- Never hide a failed check behind a default value or partial success result.
- Use PID plus process start time as process identity.
- Every attach path must have deterministic detach and failure-cleanup tests.

## Contracts and safety

- Regenerate schemas with `just schemas` after changing protocol types.
- Unknown fields and unsupported schema versions must fail deserialization.
- JSON mode writes only the final result to stdout; diagnostics go to stderr.
- Never collect pointer-referenced memory, payloads, environment variables, or
  GPU buffer contents by default.
- Never describe heuristic correlation as exact causality.
- Do not implement runtime process injection without a separately reviewed
  design and explicit user approval.

## Measurement workflow

- Use `skills/xprobe-measure-latency/SKILL.md` for latency measurement tasks.
- Platform-specific Agent files may point to that Skill but must not duplicate
  measurement logic or redefine the CLI contract.
- Run `doctor`, inspect the target identity, and run `validate` before attaching.
- Keep collection bounded and base conclusions on reported quality fields.

## Verification

- Run `just test` after changing Rust code.
- Run `just lint` and `just fmt-check` before committing.
- Run `just test-bpf` after changing files under `bpf/`.
- Run `just test-bpf-live` after changing BPF maps, records, attachment, or
  userspace ring-buffer handling. This test requires Docker daemon access.
- Run `just test-cupti` after changing files under `cupti/`.
- Run `just test-cupti-live` after changing CUPTI callbacks, activity records,
  capture output, or agent lifecycle. This test requires Docker and a GPU.
- Run `just test-agent-contract` after changing CLI commands, JSON output,
  schemas, Agent entry files, or repository Skills.
- Run `just benchmark-gpu` after changing CUPTI timing or callback hot paths.
- Use emoji conventional commits, for example `🐛 fix: reject reused pid`.
