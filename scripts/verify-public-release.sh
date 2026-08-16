#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: verify-public-release.sh <version>" >&2
  exit 2
fi

version=${1#v}
[[ ${version} =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "invalid release version: ${version}" >&2
  exit 2
}

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
repository=${XPROBE_RELEASE_REPOSITORY:-itdevwu/xprobe}
package=xprobe-${version}-linux-x86_64
release_url=https://github.com/${repository}/releases/download/v${version}
temporary=$(mktemp -d)
trap 'rm -rf "${temporary}"' EXIT HUP INT TERM

archive=${temporary}/${package}.tar.gz
checksum=${archive}.sha256
sbom=${temporary}/${package}.spdx.json

curl --fail --location --proto '=https' --tlsv1.2 \
  --retry 5 --retry-delay 2 --retry-all-errors \
  --output "${archive}" "${release_url}/${package}.tar.gz"
curl --fail --location --proto '=https' --tlsv1.2 \
  --retry 5 --retry-delay 2 --retry-all-errors \
  --output "${checksum}" "${release_url}/${package}.tar.gz.sha256"
curl --fail --location --proto '=https' --tlsv1.2 \
  --retry 5 --retry-delay 2 --retry-all-errors \
  --output "${sbom}" "${release_url}/${package}.spdx.json"
(
  cd "${temporary}"
  sha256sum --check "$(basename "${checksum}")"
)
"${root}/scripts/check-release-sbom.py" "${sbom}"

if [[ ${XPROBE_VERIFY_ATTESTATIONS:-0} == 1 ]]; then
  command -v gh >/dev/null || {
    echo "gh is required to verify release attestations" >&2
    exit 1
  }
  attestation_policy=(
    --repo "${repository}"
    --signer-workflow "${repository}/.github/workflows/release.yml"
    --deny-self-hosted-runners
  )
  gh attestation verify "${archive}" "${attestation_policy[@]}"
  gh attestation verify "${archive}" "${attestation_policy[@]}" \
    --predicate-type https://spdx.dev/Document
fi

"${root}/tests/install/test_install.sh" "${archive}"

extracted=${temporary}/extracted
mkdir -p "${extracted}"
tar -xzf "${archive}" -C "${extracted}"
package_root=${extracted}/${package}
[[ -d ${package_root} ]] || {
  echo "release archive does not contain ${package}" >&2
  exit 1
}

cli=${package_root}/bin/xprobe
cuda12=${package_root}/lib/xprobe/cuda12/libxprobe-cupti.so
cuda13=${package_root}/lib/xprobe/cuda13/libxprobe-cupti.so
for binary in "${cli}" "${cuda12}" "${cuda13}"; do
  [[ -f ${binary} ]] || { echo "release ELF is missing: ${binary}" >&2; exit 1; }
done

mapfile -d '' candidates < <(find "${package_root}" -type f -print0)
elfs=()
for candidate in "${candidates[@]}"; do
  if readelf -h "${candidate}" >/dev/null 2>&1; then
    elfs+=("${candidate}")
  fi
done
[[ ${#elfs[@]} -eq 3 ]] || {
  echo "expected 3 shipped ELFs, found ${#elfs[@]}" >&2
  printf '%s\n' "${elfs[@]}" >&2
  exit 1
}
for binary in "${elfs[@]}"; do
  "${root}/scripts/check-glibc-ceiling.sh" "${binary}" 2.34
done

verify_agent() {
  local agent=$1
  local major=$2
  local dynamic
  dynamic=$(readelf -d "${agent}")
  grep -Fq "Shared library: [libcupti.so.${major}]" <<<"${dynamic}" || {
    echo "${agent} is not linked to libcupti.so.${major}" >&2
    exit 1
  }
  if grep -Eq '\((RPATH|RUNPATH)\)' <<<"${dynamic}"; then
    echo "${agent} contains a build-time RPATH or RUNPATH" >&2
    exit 1
  fi
}

verify_agent "${cuda12}" 12
verify_agent "${cuda13}" 13
[[ $("${cli}" --version) == "xprobe ${version}" ]] || {
  echo "release CLI version does not match ${version}" >&2
  exit 1
}

printf 'Verified public xprobe %s archive, SBOM, installation, and 3 shipped ELFs\n' \
  "${version}"
