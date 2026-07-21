# Agent integration

xprobe exposes shell commands, versioned JSON, JSON Schema, and one canonical
Skill. It does not call model APIs or provide an agent daemon.

The canonical workflow is
`skills/xprobe-measure-latency/SKILL.md`. `AGENTS.md`, `CLAUDE.md`, and
`.cursor/rules/xprobe.mdc` are discovery points and must not duplicate command
sequences or correlation rules.

## Contract test

```bash
just test-agent-contract
```

The test requires the visible command set to be exactly `doctor`, `discover`,
`validate`, and `measure`. It invokes the first three in strict JSON mode,
checks injection requirements, verifies schemas, and checks that the Skill uses
only the four-command bounded workflow and inspects result quality/evidence.

This is interface conformance, not model evaluation. External harnesses may
evaluate task success, command count, cleanup, mutation disclosure, and result
interpretation without adding model-specific behavior to xprobe.
