#!/usr/bin/env bash
# Install the PyPI wheel into a fresh virtual environment and check that the
# CLI runs and finds both CUPTI Agents through the bin/../lib/xprobe layout.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: test_wheel.sh <wheel>" >&2
  exit 2
fi
wheel=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
python=${PYTHON:-python3}
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

"${python}" -m venv "${work}/venv"
"${work}/venv/bin/python" -m pip install --quiet --no-index "${wheel}"

xprobe="${work}/venv/bin/xprobe"
[[ -x "${xprobe}" ]] || { echo "wheel did not install an executable xprobe" >&2; exit 1; }
version=$("${xprobe}" --version)
# The wheel's PEP 440 X.Y.Z.devN is the CLI's X.Y.Z-dev.N.
expected=$(basename "${wheel}" | sed -n 's/^xprobe-\([0-9]*\.[0-9]*\.[0-9]*\)\(\.dev\([0-9]*\)\)\{0,1\}-.*/\1-dev.\3/p' | sed 's/-dev\.$//')
[[ "${version}" == "xprobe ${expected}" ]] || {
  echo "unexpected version: ${version} (expected ${expected})" >&2
  exit 1
}
for major in 12 13; do
  agent="$(dirname "${xprobe}")/../lib/xprobe/cuda${major}/libxprobe-cupti.so"
  [[ -x "${agent}" ]] || { echo "CUDA ${major} Agent not installed beside the CLI: ${agent}" >&2; exit 1; }
  LC_ALL=C readelf -d "${agent}" | grep -Fq "Shared library: [libcupti.so.${major}]" || {
    echo "CUDA ${major} Agent is not linked to libcupti.so.${major}" >&2
    exit 1
  }
done
[[ -f "${work}/venv/share/xprobe/skills/xprobe-measure-latency/SKILL.md" ]] || {
  echo "Skill was not installed under share/xprobe" >&2
  exit 1
}
"${xprobe}" doctor >/dev/null
"${work}/venv/bin/python" -m pip uninstall --quiet --yes xprobe
[[ ! -e "${xprobe}" && ! -e "${work}/venv/lib/xprobe/cuda12/libxprobe-cupti.so" ]] || {
  echo "uninstall left xprobe files behind" >&2
  exit 1
}
echo "wheel ok: ${version} with python $("${python}" -c 'import sys; print(sys.version.split()[0])')"
