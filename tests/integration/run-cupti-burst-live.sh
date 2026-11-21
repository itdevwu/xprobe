#!/usr/bin/env bash
# Measure an exact burst of kernels and record what xprobe reports.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: run-cupti-burst-live.sh <output-directory> <kernels-per-stream>" >&2
  exit 2
fi
output=$1
per_stream=$2
build_dir=/tmp/xprobe-cupti-burst
cuda_root=/usr/local/cuda
agent="${build_dir}/libxprobe-cupti.so"
fixture="${build_dir}/xprobe-burst"
socket="${build_dir}/cupti.sock"
mkdir -p "${build_dir}"
rm -f "${build_dir}"/{ready,go,done,stop} "${socket}"

compute_capability=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | sed -n '1p')
compute_arch=${compute_capability//./}
gcc -std=c11 -D_GNU_SOURCE -DXPROBE_HAS_CUPTI=1 -fPIC -shared -pthread -O2 \
  -Wall -Wextra -Wpedantic -Werror \
  -I/workspace/cupti/include -isystem "${cuda_root}/include" \
  /workspace/cupti/src/cupti_agent.c \
  -L"${cuda_root}/lib64" -Wl,-rpath,"${cuda_root}/lib64" -lcupti -o "${agent}"
nvcc -std=c++17 -O2 -gencode="arch=compute_${compute_arch},code=sm_${compute_arch}" \
  /workspace/cupti/tests/cuda_burst_fixture.cu -o "${fixture}"

XPROBE_CUPTI_SOCKET="${socket}" CUDA_INJECTION64_PATH="${agent}" \
  "${fixture}" "${build_dir}/ready" "${build_dir}/go" "${build_dir}/done" \
  "${build_dir}/stop" "${per_stream}" 2>"${output}/burst-target.stderr" &
target=$!
trap 'touch "${build_dir}/stop"; kill "${target}" 2>/dev/null || true; wait "${target}" 2>/dev/null || true' EXIT
for _ in $(seq 1 1000); do
  [[ -e "${build_dir}/ready" ]] && break
  sleep 0.01
done
[[ -e "${build_dir}/ready" ]] || { echo "fixture did not become ready" >&2; exit 1; }

expected=$((per_stream * 4))
set +e
/workspace/target/debug/xprobe measure --pid "${target}" --cupti-socket "${socket}" \
  --from 'cuda:kernel_start:name~xprobe_burst_kernel' \
  --to 'cuda:kernel_end:name~xprobe_burst_kernel' \
  --match exact --duration-ms 4000 --timeout-ms 30000 \
  --max-events $((expected * 2 + 1000)) \
  --events-out "${output}/burst-events.jsonl" >"${output}/burst-measure.json" &
measurement=$!
sleep 1
touch "${build_dir}/go"
wait "${measurement}"
echo $? >"${output}/burst-exit-status"
set -e
echo "${expected}" >"${output}/burst-expected"
chmod 0644 "${output}"/burst-*
