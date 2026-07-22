# Agent integration

xprobe exposes shell commands, versioned JSON, JSON Schema, and one canonical
Skill. It does not call model APIs or provide an agent daemon.

The canonical workflow is
`skills/xprobe-measure-latency/SKILL.md`. `AGENTS.md`, `CLAUDE.md`, and
`.cursor/rules/xprobe.mdc` are discovery points and must not duplicate command
sequences or correlation rules.

## Install the Skill

The canonical directory follows the open Agent Skills format and is shared by
Codex, Claude Code, Cursor, and other compatible clients. Install the released
version through the `skills` CLI so client-specific discovery paths remain the
installer's responsibility:

```bash
npx skills@1 add \
  https://github.com/itdevwu/xprobe/tree/v0.3.0/skills/xprobe-measure-latency \
  --global
```

For automation, add `--agent codex|claude-code|cursor --copy --yes`. Omit
`--global` for repository-scoped installation. The Skill is self-contained;
install its whole directory so its references and example remain available.

The xprobe repository tests installation with `skills` CLI 1.5.20 in isolated
home directories. This pinned test protects released behavior while the
documented `skills@1` selector receives compatible path updates.

## Contract test

```bash
just test-agent-contract
just test-skill-install
```

The test requires the visible command set to be exactly `doctor`, `discover`,
`validate`, and `measure`. It invokes the first three in strict JSON mode,
checks injection requirements, verifies schemas, and checks that the Skill uses
only the four-command bounded workflow and inspects result quality/evidence.
The installation test uses the real third-party CLI with telemetry disabled and
verifies byte-for-byte copies for Codex, Claude Code, and Cursor.

This is interface conformance, not model evaluation. External harnesses may
evaluate task success, command count, cleanup, mutation disclosure, and result
interpretation without adding model-specific behavior to xprobe.
