#!/usr/bin/env bash
# Triggered capture against a CUDA fixture with a rare 30 ms bubble.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: run-trigger-live.sh <output-directory>" >&2
  exit 2
fi

build_dir=/tmp/xprobe-trigger-live
cuda_root=/usr/local/cuda
agent="${build_dir}/libxprobe-cupti.so"
fixture="${build_dir}/xprobe-trigger-target"
ready="${build_dir}/ready"
stop="${build_dir}/stop"
socket="${build_dir}/cupti.sock"
xprobe=/workspace/target/debug/xprobe
compute_capability=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | sed -n '1p')
compute_arch=${compute_capability//./}

mkdir -p "${build_dir}"
rm -f "${ready}" "${stop}" "${socket}"
gcc \
  -std=c11 -D_GNU_SOURCE -DXPROBE_HAS_CUPTI=1 \
  -fPIC -shared -pthread -O2 -Wall -Wextra -Wpedantic -Werror \
  -I/workspace/cupti/include -isystem "${cuda_root}/include" \
  /workspace/cupti/src/cupti_agent.c \
  -L"${cuda_root}/lib64" -Wl,-rpath,"${cuda_root}/lib64" -lcupti \
  -o "${agent}"
nvcc -std=c++17 -O2 \
  -gencode="arch=compute_${compute_arch},code=sm_${compute_arch}" \
  /workspace/cupti/tests/cuda_gap_fixture.cu -o "${fixture}"

XPROBE_CUPTI_SOCKET="${socket}" CUDA_INJECTION64_PATH="${agent}" \
  "${fixture}" "${ready}" "${stop}" &
target_pid=$!
trap 'touch "${stop}"; kill "${target_pid}" 2>/dev/null || true; wait "${target_pid}" 2>/dev/null || true' EXIT
for _ in $(seq 1 500); do
  [[ -e "${ready}" ]] && break
  kill -0 "${target_pid}" 2>/dev/null || wait "${target_pid}"
  sleep 0.01
done
[[ -e "${ready}" ]] || { echo "timed out waiting for the CUDA fixture" >&2; exit 1; }


mkdir -p "$1/fired"
set +e
"${xprobe}" measure --pid "${target_pid}" --cupti-socket "${socket}" --json \
  --trigger-gap-ms 20 --pre-ms 5 --post-ms 5 --windows 2 \
  --max-events 400000 --timeout-ms 20000 --events-out "$1/fired" \
  >"$1/fired.json" 2>"$1/fired.stderr"
echo $? >"$1/fired.status"
"${xprobe}" measure --pid "${target_pid}" --cupti-socket "${socket}" --json \
  --trigger-gap-ms 500 --max-events 400000 --timeout-ms 3000 \
  >"$1/unobserved.json" 2>"$1/unobserved.stderr"
echo $? >"$1/unobserved.status"
"${xprobe}" measure --pid "${target_pid}" --cupti-socket "${socket}" --json \
  --trigger-gap-ms 20 --max-events 2000 --timeout-ms 4000 \
  >"$1/small-ring.json" 2>"$1/small-ring.stderr"
echo $? >"$1/small-ring.status"
set -e

touch "${stop}"
wait "${target_pid}"
trap - EXIT
chmod -R a+rwX "$1"
