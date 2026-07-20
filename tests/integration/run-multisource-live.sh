#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: run-multisource-live.sh <output-directory>" >&2
  exit 2
fi

build_dir=/tmp/xprobe-multisource-live
cuda_root=/usr/local/cuda
agent="${build_dir}/libxprobe-cupti.so"
fixture="${build_dir}/xprobe-multisource-target"
ready="${build_dir}/ready"
go="${build_dir}/go"
stop="${build_dir}/stop"
snapshot_socket="${build_dir}/cupti.sock"
host_capture="$1/host.json"
cupti_capture="$1/cupti.bin"
live_capture="$1/live.jsonl"
live_measurement="$1/live-measure.json"
spec="${build_dir}/measurement-spec.json"
spec_measurement="$1/spec-measure.json"
gpu_info="$1/gpu.txt"
compute_capability=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | sed -n '1p')
compute_arch=${compute_capability//./}
nvidia-smi \
  --query-gpu=name,driver_version,compute_cap \
  --format=csv,noheader | sed -n '1p' >"${gpu_info}"

mkdir -p "${build_dir}"
rm -f "${ready}" "${go}" "${stop}" "${snapshot_socket}"

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

XPROBE_CUPTI_OUTPUT="${cupti_capture}" \
XPROBE_CUPTI_SOCKET="${snapshot_socket}" \
CUDA_INJECTION64_PATH="${agent}" \
  "${fixture}" "${ready}" "${go}" "${stop}" &
target_pid=$!
trap 'kill "${target_pid}" 2>/dev/null || true; wait "${target_pid}" 2>/dev/null || true' EXIT

for _ in $(seq 1 500); do
  if [[ -e "${ready}" ]]; then
    break
  fi
  if ! kill -0 "${target_pid}" 2>/dev/null; then
    wait "${target_pid}"
  fi
  sleep 0.01
done
if [[ ! -e "${ready}" ]]; then
  echo "timed out waiting for CUDA fixture readiness" >&2
  exit 1
fi

/workspace/target/debug/xprobe measure \
  --pid "${target_pid}" \
  --cupti-socket "${snapshot_socket}" \
  --from "uprobe:${fixture}:xprobe_request_marker:entry" \
  --to 'cuda:kernel_start:name~xprobe_multisource_kernel.*' \
  --match first-after \
  --samples 3 \
  --timeout-ms 10000 \
  --json --non-interactive --no-color >"${live_measurement}" &
measurement_pid=$!

sleep 1
touch "${go}"
if ! wait "${measurement_pid}"; then
  cat "${live_measurement}" >&2
  exit 1
fi
process_start_time=$(awk '{print $22}' "/proc/${target_pid}/stat")
printf '{"schema_version":"1.0","name":"spec_host_to_kernel","target":{"pid":%s,"process_start_time":%s},"start_selector":"uprobe:%s:xprobe_request_marker:entry","end_selector":"cuda:kernel_start:name~xprobe_multisource_kernel.*","match_policy":"first_after","samples":3,"duration_ms":null,"timeout_ms":10000,"max_events":100000}\n' \
  "${target_pid}" "${process_start_time}" "${fixture}" >"${spec}"
/workspace/target/debug/xprobe trace \
  --spec "${spec}" \
  --cupti-socket "${snapshot_socket}" \
  --json --non-interactive --no-color >"${spec_measurement}"

/workspace/target/debug/xprobe capture uprobe \
  --pid "${target_pid}" \
  --binary "${fixture}" \
  --symbol xprobe_request_marker \
  --samples 3 \
  --timeout-ms 10000 \
  --json --non-interactive --no-color >"${host_capture}"
if [[ $(stat -c '%a' "${snapshot_socket}") != 600 ]]; then
  echo "CUPTI snapshot socket is not mode 0600" >&2
  exit 1
fi
/workspace/target/debug/xprobe capture cupti \
  --socket "${snapshot_socket}" \
  --timeout-ms 10000 \
  --session-id xp_cupti_snapshot \
  --json --non-interactive --no-color >"${live_capture}"
touch "${stop}"
wait "${target_pid}"
trap - EXIT
chmod 0644 "${host_capture}" "${cupti_capture}" "${live_capture}" \
  "${live_measurement}" "${spec_measurement}" "${gpu_info}"
