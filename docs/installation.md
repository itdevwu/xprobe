# Installation

The released xprobe package supports Linux x86_64 with glibc 2.34 or newer. It
contains the CLI and separate CUDA 12 and CUDA 13 CUPTI Agents. A CUDA toolkit
is not required to install xprobe; NVIDIA driver and CUPTI availability matter
only when measuring GPU events.

## User installation

The versioned bootstrap installs to `~/.local` without root access:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/itdevwu/xprobe/v0.3.0/install.sh | sh
```

The bootstrap downloads the release archive and its SHA256 file, verifies the
archive, and then installs this layout:

```text
~/.local/bin/xprobe
~/.local/lib/xprobe/cuda12/libxprobe-cupti.so
~/.local/lib/xprobe/cuda13/libxprobe-cupti.so
~/.local/include/xprobe/cupti_agent.h
~/.local/share/xprobe/
```

Add `~/.local/bin` to `PATH` when it is not already present. To use another
prefix, download the script and pass `--prefix`:

```bash
curl --proto '=https' --tlsv1.2 -fsSLO \
  https://raw.githubusercontent.com/itdevwu/xprobe/v0.3.0/install.sh
sh install.sh --prefix /opt/xprobe
```

Writing a system prefix such as `/usr/local` may require running the downloaded
script with `sudo`. The installer never elevates privileges itself.

## Verify before installation

For a fully explicit archive workflow:

```bash
version=0.3.0
base=https://github.com/itdevwu/xprobe/releases/download/v$version
archive=xprobe-$version-linux-x86_64.tar.gz

curl --proto '=https' --tlsv1.2 -fLO "$base/$archive"
curl --proto '=https' --tlsv1.2 -fLO "$base/$archive.sha256"
sha256sum --check "$archive.sha256"
tar -xzf "$archive"
"./xprobe-$version-linux-x86_64/install.sh"
```

The unpacked package can also be run in place as long as its `bin` and `lib`
layout remains together.

## Upgrade and removal

Run the newer version's installer with the same prefix to replace the installed
files. Remove an installation with the matching script:

```bash
sh install.sh --prefix "$HOME/.local" --uninstall
```

The uninstall operation removes only xprobe-owned files below `bin/xprobe`,
`lib/xprobe`, `include/xprobe`, and `share/xprobe`.

## Agent Skill

The xprobe CLI works independently of an AI agent. To let an Agent discover,
validate, and run bounded measurements using the released contract, install the
version-matched Skill:

```bash
npx skills@1 add \
  https://github.com/itdevwu/xprobe/tree/v0.3.0/skills/xprobe-measure-latency \
  --global
```

The command interactively selects among detected agents. A non-interactive
installation names the target explicitly:

```bash
DISABLE_TELEMETRY=1 npx --yes skills@1 add \
  https://github.com/itdevwu/xprobe/tree/v0.3.0/skills/xprobe-measure-latency \
  --agent codex --global --copy --yes
```

Use `claude-code` or `cursor` for those clients. Omit `--global` to install into
the current project. Review the Skill before use because Agent Skills can direct
an agent to execute commands with its granted permissions.

Without Node.js, copy the complete `skills/xprobe-measure-latency` directory
from the release archive into the Skill directory documented by the target
agent. Do not copy only `SKILL.md`; its local references and example are part of
the contract.

## Runtime check

After installing the CLI, run:

```bash
xprobe --version
xprobe doctor --json --non-interactive --no-color
```

Host selectors require eBPF/perf permissions. Online CUDA Agent injection
requires ptrace permission and a shared mount namespace with the target. Read
the individual `doctor` checks rather than treating diagnostic completion as a
claim that every collector is available.
