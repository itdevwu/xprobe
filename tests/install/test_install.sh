#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
temporary_dir=$(mktemp -d)
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM

workspace_version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -n 1)
installer_version=$(sed -n 's/^version=${XPROBE_VERSION:-\([^}]*\)}$/\1/p' "$root/install.sh")
test "$installer_version" = "$workspace_version"

if [ "$#" -eq 1 ]; then
  archive=$(realpath "$1")
  package=$(basename "$archive" .tar.gz)
  mkdir -p "$temporary_dir/archive"
  tar -xzf "$archive" -C "$temporary_dir/archive"
  source_dir=$temporary_dir/archive/$package
elif [ "$#" -eq 0 ]; then
  source_dir=$temporary_dir/xprobe-0.2.1-linux-x86_64
  mkdir -p \
    "$source_dir/bin" \
    "$source_dir/lib/xprobe/cuda12" \
    "$source_dir/lib/xprobe/cuda13" \
    "$source_dir/include/xprobe" \
    "$source_dir/docs" \
    "$source_dir/schemas" \
    "$source_dir/skills"
  cp "$root/install.sh" "$source_dir/install.sh"
  printf '#!/bin/sh\nprintf "xprobe 0.2.1\\n"\n' >"$source_dir/bin/xprobe"
  chmod 0755 "$source_dir/bin/xprobe" "$source_dir/install.sh"
  printf 'cuda12\n' >"$source_dir/lib/xprobe/cuda12/libxprobe-cupti.so"
  printf 'cuda13\n' >"$source_dir/lib/xprobe/cuda13/libxprobe-cupti.so"
  printf 'header\n' >"$source_dir/include/xprobe/cupti_agent.h"
  printf 'license\n' >"$source_dir/LICENSE"
  printf 'readme\n' >"$source_dir/README.md"
  printf 'agents\n' >"$source_dir/AGENTS.md"
else
  printf 'usage: test_install.sh [release-archive]\n' >&2
  exit 2
fi

prefix=$temporary_dir/prefix
HOME=$temporary_dir/home PATH=/usr/bin:/bin \
  "$source_dir/install.sh" --prefix "$prefix"

test -x "$prefix/bin/xprobe"
test -x "$prefix/lib/xprobe/cuda12/libxprobe-cupti.so"
test -x "$prefix/lib/xprobe/cuda13/libxprobe-cupti.so"
test -f "$prefix/include/xprobe/cupti_agent.h"
test -f "$prefix/share/xprobe/LICENSE"
test -d "$prefix/share/xprobe/docs"
test -d "$prefix/share/xprobe/schemas"
test -d "$prefix/share/xprobe/skills"
"$prefix/bin/xprobe" --version

HOME=$temporary_dir/home "$source_dir/install.sh" \
  --prefix "$prefix" --uninstall
test ! -e "$prefix/bin/xprobe"
test ! -e "$prefix/lib/xprobe"
test ! -e "$prefix/share/xprobe"
