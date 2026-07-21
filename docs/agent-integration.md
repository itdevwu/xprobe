# Agent integration

xprobe exposes the same shell, JSON, JSON Schema, and Markdown Skill contract to
every coding agent. Core behavior does not depend on a model API or editor API.

The canonical latency workflow is
`skills/xprobe-measure-latency/SKILL.md`. `AGENTS.md`, `CLAUDE.md`, and
`.cursor/rules/xprobe.mdc` are thin discovery points; they must not contain
separate command sequences or correlation rules.

## Deterministic contract test

Run:

```bash
just test-agent-contract
```

The test invokes `doctor`, `inspect`, and `validate` in JSON, non-interactive,
no-color mode. It also verifies the stable command set, checked-in schemas,
required Skill workflow stages, safety constraints, and references from each
platform entry point.

This is an interface conformance test, not a model evaluation. Evaluation of a
specific coding agent should run the fixed tasks described in `PLAN.md` from an
external harness and record success rate, command count, cleanup, unsafe actions,
and interpretation quality without adding model calls to xprobe.
