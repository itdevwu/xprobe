#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: run-inject-live.sh <output-directory>" >&2
  exit 2
fi

build_dir=/tmp/xprobe-inject-live
cuda_root=/usr/local/cuda
agent="${build_dir}/libxprobe-cupti.so"
fixture="${build_dir}/xprobe-inject-target"
ready="${build_dir}/ready"
go="${build_dir}/go"
stop="${build_dir}/stop"
compute_capability=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | sed -n '1p')
compute_arch=${compute_capability//./}

mkdir -p "${build_dir}"
rm -f "${ready}" "${go}" "${stop}" /tmp/xprobe-*.sock

gcc \
  -std=c11 -D_GNU_SOURCE -DXPROBE_HAS_CUPTI=1 \
  -fPIC -shared -pthread -O2 -Wall -Wextra -Wpedantic -Werror \
  -I/workspace/cupti/include -isystem "${cuda_root}/include" \
  /workspace/cupti/src/cupti_agent.c \
  -L"${cuda_root}/lib64" -Wl,-rpath,"${cuda_root}/lib64" -lcupti \
  -o "${agent}"

nvcc \
  -std=c++17 -O0 \
  -gencode="arch=compute_${compute_arch},code=sm_${compute_arch}" \
  /workspace/cupti/tests/cuda_multisource_fixture.cu \
  -o "${fixture}"

"${fixture}" "${ready}" "${go}" "${stop}" &
target_pid=$!
trap 'kill "${target_pid}" 2>/dev/null || true; wait "${target_pid}" 2>/dev/null || true' EXIT

for _ in $(seq 1 500); do
  [[ -e "${ready}" ]] && break
  kill -0 "${target_pid}" 2>/dev/null || wait "${target_pid}"
  sleep 0.01
done
[[ -e "${ready}" ]] || { echo "target readiness timed out" >&2; exit 1; }

run_measure() {
  /workspace/target/debug/xprobe measure \
    --pid "${target_pid}" \
    --agent "${agent}" \
    --from 'cuda:kernel_start:name~xprobe_multisource_kernel.*' \
    --to 'cuda:kernel_end:name~xprobe_multisource_kernel.*' \
    --match exact \
    --samples 3 \
    --timeout-ms 10000 \
    --json --non-interactive --no-color \
    >"$1.json" 2>"$1.stderr" &
  measurement_pid=$!
  sleep 1
  touch "${go}"
  wait "${measurement_pid}"
}

run_measure "$1/first"
run_measure "$1/second"

mapped_agents=$(awk -v agent="${agent}" '$0 ~ agent {print $NF}' "/proc/${target_pid}/maps" | sort -u | wc -l)
[[ "${mapped_agents}" -gt 0 ]] || { echo "agent is not mapped" >&2; exit 1; }
if compgen -G "/tmp/xprobe-${target_pid}-*.sock" >/dev/null; then
  echo "snapshot socket leaked" >&2
  exit 1
fi

touch "${stop}"
wait "${target_pid}"
trap - EXIT

printf '%s\n' "${mapped_agents}" >"$1/mapped-agents.txt"
chmod 0644 "$1"/*
