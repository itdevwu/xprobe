#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${root}"

version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
[[ -n "${version}" ]] || { echo "workspace version was not found" >&2; exit 1; }

build_dir=${XPROBE_RELEASE_BUILD_DIR:-build/release}
dist_dir=${XPROBE_DIST_DIR:-dist}
package="xprobe-${version}-linux-x86_64"
stage="${dist_dir}/${package}"

cargo build --workspace --release --locked
cmake -S . -B "${build_dir}" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DXPROBE_BUILD_BPF=OFF \
  -DXPROBE_BUILD_CUPTI=ON \
  -DXPROBE_REQUIRE_CUPTI=ON
cmake --build "${build_dir}" --parallel

agent="${build_dir}/cupti/libxprobe-cupti.so"
if [[ ${XPROBE_ALLOW_ABI_ONLY:-0} != 1 ]] && \
   ! readelf -d "${agent}" | grep -q 'libcupti\.so'; then
  echo "release CUPTI agent is ABI-only; build with CUDA/CUPTI development files" >&2
  exit 1
fi

rm -rf "${stage}"
install -d "${stage}/bin" "${stage}/lib/xprobe" "${stage}/include/xprobe"
install -m 0755 target/release/xprobe "${stage}/bin/xprobe"
install -m 0755 "${agent}" "${stage}/lib/xprobe/libxprobe-cupti.so"
install -m 0644 cupti/include/xprobe/cupti_agent.h "${stage}/include/xprobe/"
install -m 0644 LICENSE README.md AGENTS.md "${stage}/"
cp -a docs schemas skills "${stage}/"

tar -C "${dist_dir}" -czf "${dist_dir}/${package}.tar.gz" "${package}"
(
  cd "${dist_dir}"
  sha256sum "${package}.tar.gz" >"${package}.tar.gz.sha256"
)
printf '%s\n' "${dist_dir}/${package}.tar.gz"
