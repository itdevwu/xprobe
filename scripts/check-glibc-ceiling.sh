#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: check-glibc-ceiling.sh <elf-file> <maximum-version>" >&2
  exit 2
fi

binary=$1
maximum=$2
[[ -f ${binary} ]] || { echo "ELF file was not found: ${binary}" >&2; exit 1; }
[[ ${maximum} =~ ^[0-9]+\.[0-9]+$ ]] || {
  echo "invalid maximum glibc version: ${maximum}" >&2
  exit 2
}

mapfile -t versions < <(
  LC_ALL=C readelf --version-info "${binary}" |
    sed -nE 's/.*Name: GLIBC_([0-9]+(\.[0-9]+)+).*/\1/p' |
    sort -Vu
)
[[ ${#versions[@]} -gt 0 ]] || {
  echo "${binary} does not declare a GLIBC symbol version" >&2
  exit 1
}

required=${versions[${#versions[@]}-1]}
highest=$(printf '%s\n%s\n' "${required}" "${maximum}" | sort -Vu | tail -n 1)
if [[ ${highest} != "${maximum}" ]]; then
  echo "${binary} requires GLIBC_${required}, above supported GLIBC_${maximum}" >&2
  exit 1
fi
printf '%s requires at most GLIBC_%s\n' "${binary}" "${required}"
