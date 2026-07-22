#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${root}"

version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
[[ -n "${version}" ]] || { echo "workspace version was not found" >&2; exit 1; }

dist_dir=${XPROBE_DIST_DIR:-dist}
package="xprobe-${version}-linux-x86_64"
stage="${dist_dir}/${package}"
agent_cuda12=${XPROBE_CUPTI_AGENT_CUDA12:-build/cuda12/cupti/libxprobe-cupti.so}
agent_cuda13=${XPROBE_CUPTI_AGENT_CUDA13:-build/cuda13/cupti/libxprobe-cupti.so}

cargo build --workspace --release --locked
scripts/check-glibc-ceiling.sh target/release/xprobe 2.34

verify_agent() {
  local agent=$1
  local major=$2
  local dynamic

  [[ -f "${agent}" ]] || {
    echo "CUDA ${major} CUPTI agent was not found: ${agent}" >&2
    exit 1
  }
  dynamic=$(readelf -d "${agent}")
  grep -Fq "Shared library: [libcupti.so.${major}]" <<<"${dynamic}" || {
    echo "${agent} is not linked to libcupti.so.${major}" >&2
    exit 1
  }
  if grep -Eq '\((RPATH|RUNPATH)\)' <<<"${dynamic}"; then
    echo "${agent} contains a build-time RPATH or RUNPATH" >&2
    exit 1
  fi
  scripts/check-glibc-ceiling.sh "${agent}" 2.34
}

verify_agent "${agent_cuda12}" 12
verify_agent "${agent_cuda13}" 13

rm -rf "${stage}"
install -d \
  "${stage}/bin" \
  "${stage}/lib/xprobe/cuda12" \
  "${stage}/lib/xprobe/cuda13" \
  "${stage}/include/xprobe"
install -m 0755 target/release/xprobe "${stage}/bin/xprobe"
install -m 0755 install.sh "${stage}/install.sh"
install -m 0755 "${agent_cuda12}" \
  "${stage}/lib/xprobe/cuda12/libxprobe-cupti.so"
install -m 0755 "${agent_cuda13}" \
  "${stage}/lib/xprobe/cuda13/libxprobe-cupti.so"
install -m 0644 cupti/include/xprobe/cupti_agent.h "${stage}/include/xprobe/"
install -m 0644 LICENSE README.md AGENTS.md "${stage}/"
cp -a docs schemas skills "${stage}/"

tar -C "${dist_dir}" -czf "${dist_dir}/${package}.tar.gz" "${package}"
(
  cd "${dist_dir}"
  sha256sum "${package}.tar.gz" >"${package}.tar.gz.sha256"
)
printf '%s\n' "${dist_dir}/${package}.tar.gz"
