#!/bin/sh
set -eu

repository=${XPROBE_REPOSITORY:-itdevwu/xprobe}
version=${XPROBE_VERSION:-0.3.0}
if [ -n "${XPROBE_PREFIX:-}" ]; then
  prefix=$XPROBE_PREFIX
elif [ -n "${HOME:-}" ]; then
  prefix=$HOME/.local
else
  prefix=
fi
uninstall=0

usage() {
  cat <<'EOF'
Install a released xprobe binary and its CUDA Agents.

Usage: install.sh [--version VERSION] [--prefix DIR] [--uninstall]

Options:
  --version VERSION  Release to install (default: 0.3.0)
  --prefix DIR       Installation prefix (default: $HOME/.local)
  --uninstall        Remove xprobe from the selected prefix
  -h, --help         Show this help
EOF
}

fail() {
  printf 'xprobe install: %s\n' "$*" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case $1 in
    --version)
      [ "$#" -ge 2 ] || fail "--version requires a value"
      version=$2
      shift 2
      ;;
    --prefix)
      [ "$#" -ge 2 ] || fail "--prefix requires a value"
      prefix=$2
      shift 2
      ;;
    --uninstall)
      uninstall=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[ -n "$prefix" ] || fail "HOME is not set; pass --prefix"
version=${version#v}
case $version in
  ''|*[!0-9A-Za-z.-]*) fail "invalid release version: $version" ;;
esac

if [ "$uninstall" -eq 1 ]; then
  rm -f "$prefix/bin/xprobe" "$prefix/include/xprobe/cupti_agent.h"
  rm -rf "$prefix/lib/xprobe" "$prefix/share/xprobe"
  printf 'Removed xprobe from %s\n' "$prefix"
  exit 0
fi

[ "$(uname -s)" = Linux ] || fail "only Linux is supported"
case $(uname -m) in
  x86_64|amd64) ;;
  *) fail "only x86_64 is supported" ;;
esac

glibc=$(getconf GNU_LIBC_VERSION) || fail "glibc was not found"
set -- $glibc
[ "${1:-}" = glibc ] && [ -n "${2:-}" ] || fail "glibc was not found"
glibc_major=${2%%.*}
glibc_minor=${2#*.}
glibc_minor=${glibc_minor%%.*}
if [ "$glibc_major" -lt 2 ] || { [ "$glibc_major" -eq 2 ] && [ "$glibc_minor" -lt 34 ]; }; then
  fail "glibc 2.34 or newer is required; found $2"
fi

source_dir=
temporary_dir=

case $0 in
  install.sh|*/install.sh)
    script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    if [ -x "$script_dir/bin/xprobe" ]; then
      source_dir=$script_dir
    fi
    ;;
esac

cleanup() {
  if [ -n "$temporary_dir" ]; then
    rm -rf "$temporary_dir"
  fi
}
trap cleanup EXIT HUP INT TERM

if [ -z "$source_dir" ]; then
  command -v curl >/dev/null 2>&1 || fail "curl is required to download xprobe"
  command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required to verify xprobe"
  temporary_dir=$(mktemp -d)
  package=xprobe-$version-linux-x86_64
  release_url=https://github.com/$repository/releases/download/v$version
  archive=$temporary_dir/$package.tar.gz
  checksum=$archive.sha256

  printf 'Downloading xprobe %s...\n' "$version"
  curl --fail --location --proto '=https' --tlsv1.2 \
    --output "$archive" "$release_url/$package.tar.gz"
  curl --fail --location --proto '=https' --tlsv1.2 \
    --output "$checksum" "$release_url/$package.tar.gz.sha256"
  (cd "$temporary_dir" && sha256sum --check "$(basename "$checksum")")
  tar -xzf "$archive" -C "$temporary_dir"
  source_dir=$temporary_dir/$package
fi

[ -x "$source_dir/bin/xprobe" ] || fail "release package does not contain bin/xprobe"
for major in 12 13; do
  agent=$source_dir/lib/xprobe/cuda$major/libxprobe-cupti.so
  [ -f "$agent" ] || fail "release package does not contain the CUDA $major Agent"
done
[ -f "$source_dir/include/xprobe/cupti_agent.h" ] || \
  fail "release package does not contain the CUPTI Agent header"

install -d \
  "$prefix/bin" \
  "$prefix/lib/xprobe/cuda12" \
  "$prefix/lib/xprobe/cuda13" \
  "$prefix/include/xprobe" \
  "$prefix/share/xprobe"
install -m 0755 "$source_dir/bin/xprobe" "$prefix/bin/xprobe"
for major in 12 13; do
  install -m 0755 \
    "$source_dir/lib/xprobe/cuda$major/libxprobe-cupti.so" \
    "$prefix/lib/xprobe/cuda$major/libxprobe-cupti.so"
done
install -m 0644 \
  "$source_dir/include/xprobe/cupti_agent.h" \
  "$prefix/include/xprobe/cupti_agent.h"

rm -rf "$prefix/share/xprobe/docs" "$prefix/share/xprobe/schemas" \
  "$prefix/share/xprobe/skills"
install -m 0644 "$source_dir/LICENSE" "$source_dir/README.md" \
  "$source_dir/AGENTS.md" "$prefix/share/xprobe/"
cp -R "$source_dir/docs" "$source_dir/schemas" "$source_dir/skills" \
  "$prefix/share/xprobe/"

"$prefix/bin/xprobe" --version
printf 'Installed xprobe %s to %s\n' "$version" "$prefix"
case :${PATH:-}: in
  *:"$prefix/bin":*) ;;
  *) printf 'Add %s/bin to PATH to run xprobe.\n' "$prefix" >&2 ;;
esac
