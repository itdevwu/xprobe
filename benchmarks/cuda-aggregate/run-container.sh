#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: run-container.sh <output-directory>" >&2
  exit 2
fi

output_dir=$1
build_dir=/tmp/xprobe-cuda-aggregate
cuda_root=/usr/local/cuda
agent="${build_dir}/libxprobe-cupti.so"
fixture="${build_dir}/xprobe-cuda-aggregate"
resource_runner="${build_dir}/resource-runner"
socket="${build_dir}/agent.sock"
ready="${build_dir}/ready"
stop="${build_dir}/stop"
xprobe_bin=/workspace/target/debug/xprobe
compute_capability=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | sed -n '1p')
compute_arch=${compute_capability//./}

mkdir -p "${build_dir}" "${output_dir}"
rm -f "${socket}" "${ready}" "${stop}"

gcc \
  -std=c11 -D_GNU_SOURCE -DXPROBE_HAS_CUPTI=1 \
  -fPIC -shared -pthread -O2 -Wall -Wextra -Wpedantic -Werror \
  -I/workspace/cupti/include -isystem "${cuda_root}/include" \
  /workspace/cupti/src/cupti_agent.c \
  -L"${cuda_root}/lib64" -Wl,-rpath,"${cuda_root}/lib64" -lcupti \
  -o "${agent}"

nvcc \
  -std=c++17 -O2 \
  -gencode="arch=compute_${compute_arch},code=sm_${compute_arch}" \
  /workspace/benchmarks/cuda-aggregate/cuda_aggregate_benchmark.cu \
  -o "${fixture}"

gcc \
  -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror \
  /workspace/benchmarks/cuda-aggregate/resource_runner.c \
  -o "${resource_runner}"

XPROBE_CUPTI_SOCKET="${socket}" CUDA_INJECTION64_PATH="${agent}" \
  "${fixture}" "${ready}" "${stop}" &
target_pid=$!
trap 'touch "${stop}"; kill "${target_pid}" 2>/dev/null || true; wait "${target_pid}" 2>/dev/null || true' EXIT

for _ in $(seq 1 500); do
  [[ -e "${ready}" && -S "${socket}" ]] && break
  kill -0 "${target_pid}" 2>/dev/null || wait "${target_pid}"
  sleep 0.01
done
[[ -e "${ready}" && -S "${socket}" ]] || {
  echo "aggregate benchmark readiness timed out" >&2
  exit 1
}

"${resource_runner}" "${output_dir}/exact-metrics.txt" "${target_pid}" \
  "${xprobe_bin}" measure \
  --pid "${target_pid}" --cupti-socket "${socket}" \
  --from cuda:kernel_start --to cuda:kernel_end --match exact \
  --duration-ms 1800 --max-events 500000 --timeout-ms 10000 \
  --events-out "${output_dir}/exact-events.jsonl" \
  --json --non-interactive --no-color \
  >"${output_dir}/exact-result.json" 2>"${output_dir}/exact.stderr"

"${resource_runner}" "${output_dir}/aggregate-metrics.txt" "${target_pid}" \
  "${xprobe_bin}" measure \
  --pid "${target_pid}" --cupti-socket "${socket}" \
  --from cuda:kernel_start --to cuda:kernel_end --match exact \
  --aggregate --duration-ms 1800 --max-groups 4 --timeout-ms 10000 \
  --json --non-interactive --no-color \
  >"${output_dir}/aggregate-result.json" 2>"${output_dir}/aggregate.stderr"

nvidia-smi \
  --query-gpu=name,driver_version,compute_cap \
  --format=csv,noheader >"${output_dir}/gpu.txt"

touch "${stop}"
wait "${target_pid}"
trap - EXIT
chmod 0644 "${output_dir}"/*
