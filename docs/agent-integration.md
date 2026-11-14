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
  https://github.com/itdevwu/xprobe/tree/v0.6.0/skills/xprobe-measure-latency \
  --global
```

For automation, add `--agent codex|claude-code|cursor --copy --yes`. Omit
`--global` for repository-scoped installation. The Skill is self-contained;
install its whole directory so its references, examples, and analysis script
remain available.

The Skill's `SKILL.md` is the agent-facing workflow; this page does not
restate it. It drives a two-command path for unknown live work: `measure
--triage` over one representative window, then the ranked finding's ready
`MeasurementSpec` or a measurement graph. Existing artifacts are analyzed
offline without installing a collector, and an escalation ladder covers what
the first pass cannot explain before handing off to kernel or runtime
profilers. Selection and concurrency across processes stay in the agent;
xprobe adds no multi-process command and never claims cross-process causality.

## Contract test

```bash
just test-agent-contract
just test-skill-install
```

The test requires the visible command set to be exactly `doctor`, `discover`,
`validate`, and `measure`, invokes them in strict JSON mode, and verifies
schemas and the bundled trace analyzer. For the Skill it enforces a word budget
for the entry point and all references, resolves every link, rejects orphaned
references, checks that every documented `xprobe` command uses flags its
subcommand accepts, validates the example specs, and checks routing for
existing artifacts, unknown workloads, known boundaries, graphs, deeper
escalation, Python semantics, multiple processes, and containers.
The installation test uses the real third-party CLI in isolated home directories
and verifies byte-for-byte copies for Codex, Claude Code, and Cursor.

This is interface conformance, not model evaluation. External harnesses may
evaluate task success, command count, cleanup, mutation disclosure, and result
interpretation without adding model-specific behavior to xprobe.
