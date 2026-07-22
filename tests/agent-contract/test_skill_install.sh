#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
temporary_dir=$(mktemp -d)
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM

export DISABLE_TELEMETRY=1
export npm_config_cache=$temporary_dir/npm-cache

install_for() {
  agent=$1
  home=$temporary_dir/$agent
  HOME=$home npx --yes skills@1.5.20 add "$root" \
    --skill xprobe-measure-latency \
    --agent "$agent" \
    --global \
    --copy \
    --yes >/dev/null

  case $agent in
    claude-code) installed=$home/.claude/skills/xprobe-measure-latency ;;
    codex|cursor) installed=$home/.agents/skills/xprobe-measure-latency ;;
    *) printf 'unsupported test agent: %s\n' "$agent" >&2; exit 2 ;;
  esac

  diff -r "$root/skills/xprobe-measure-latency" "$installed"
}

install_for codex
install_for claude-code
install_for cursor
