# Agent integration

xprobe exposes shell commands, versioned JSON, JSON Schema, and one canonical
Skill. It does not call model APIs or provide an agent daemon.

The canonical workflow is
`skills/xprobe-measure-latency/SKILL.md`. `AGENTS.md`, `CLAUDE.md`, and
`.cursor/rules/xprobe.mdc` are discovery points and must not duplicate command
sequences or correlation rules.

## Install the Skill

The canonical directory follows the open Agent Skills format and is shared by
Codex, Claude Code, Cursor, and other compatible clients. The user installs the
released Skill through the `skills` CLI; the activated Skill then bootstraps or
repairs the matching xprobe CLI itself:

```bash
npx skills@1 add \
  https://github.com/itdevwu/xprobe/tree/v0.3.3/skills/xprobe-measure-latency \
  --global
```

For automation, add `--agent codex|claude-code|cursor --copy --yes`. Omit
`--global` for repository-scoped installation. The Skill is self-contained;
install its whole directory so its references, examples, and analysis script
remain available.

The Skill checks, installs, and verifies the CLI before it first runs `doctor`.
It then maps a representative workload broadly, uses artifact evidence to narrow
selectors, and includes `scripts/analyze_trace.py` for deterministic kernel,
copy, overlap, stream, and gap summaries. The xprobe repository tests
installation with `skills` CLI 1.5.20 in isolated
home directories. This pinned test protects released behavior while the
documented `skills@1` selector receives compatible path updates.

For multi-process workloads, the Skill selects explicit PID/start-time
identities, inventories a representative worker when homogeneity is supported
by evidence, and asks the agent framework to launch one independent bounded
measurement per selected worker concurrently. Results, warnings, failures, and
artifacts remain per process; xprobe does not add a multi-process command or
claim cross-process causality.

## Contract test

```bash
just test-agent-contract
just test-skill-install
```

The test requires the visible command set to be exactly `doctor`, `discover`,
`validate`, and `measure`. It invokes the first three in strict JSON mode,
checks injection requirements, verifies schemas, exercises the bundled trace
analyzer, and checks that the Skill uses only the four-command bounded workflow
and inspects result quality/evidence.
The installation test uses the real third-party CLI in isolated home directories
and verifies byte-for-byte copies for Codex, Claude Code, and Cursor.

This is interface conformance, not model evaluation. External harnesses may
evaluate task success, command count, cleanup, mutation disclosure, and result
interpretation without adding model-specific behavior to xprobe.
