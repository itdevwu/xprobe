# Setup

Use this reference at the start of a task when the CLI is absent or its version
does not match this Skill. The user installs this Skill once; the agent performs
and verifies the CLI bootstrap. Do not ask the user to run a second installation
command unless their environment prevents the agent from writing a usable prefix.

## Check and bootstrap xprobe

Check the executable first. Continue only when it reports 0.3.2; otherwise run
the bootstrap below:

```bash
if command -v xprobe >/dev/null 2>&1; then
  xprobe --version
fi
```

Download the released bootstrap, which verifies the release archive before
installing under `~/.local`:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/itdevwu/xprobe/v0.3.2/install.sh \
  -o /tmp/xprobe-install.sh
sh /tmp/xprobe-install.sh
export PATH="$HOME/.local/bin:$PATH"
xprobe --version
xprobe doctor --json --non-interactive --no-color
```

Use the downloaded script's `--prefix` option for another installation root.
Export that prefix's `bin` directory into `PATH`, rerun `xprobe --version`, then
run `xprobe doctor --json --non-interactive --no-color`. Surface bootstrap,
PATH, permission, driver, CUDA, or CUPTI failures explicitly and adjust from the
reported detail; do not continue to measurement on an unverified installation.
The CLI needs no Node.js. CUDA is optional until a GPU selector is measured.

## Repair the Skill only when needed

The user normally installed this Skill before invoking the agent. When its files
are missing or the version is not 0.3.2, install the complete version-matched
directory through the Agent Skills CLI:

```bash
npx skills@1 add \
  https://github.com/itdevwu/xprobe/tree/v0.3.2/skills/xprobe-measure-latency \
  --global
```

For non-interactive automation, select the host explicitly:

```bash
npx --yes skills@1 add \
  https://github.com/itdevwu/xprobe/tree/v0.3.2/skills/xprobe-measure-latency \
  --agent codex --global --copy --yes
```

Replace `codex` with `claude-code` or `cursor` as needed. Omit `--global` for a
repository-scoped installation. Without Node.js, copy the full Skill directory
from the release archive into the target agent's documented Skill location; do
not copy only `SKILL.md`, because its references, examples, and analyzer are
part of the contract.
