#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
checker=${root}/scripts/check-glibc-ceiling.sh
fixture=$(command -v env)

"${checker}" "${fixture}" 99.0 >/dev/null
if "${checker}" "${fixture}" 2.0 >/dev/null 2>&1; then
  echo "glibc ceiling check accepted an incompatible ELF" >&2
  exit 1
fi
