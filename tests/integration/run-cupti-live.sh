#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: run-cupti-live.sh <output-path>" >&2
  exit 2
fi

build_dir=/tmp/xprobe-cupti-live
cuda_root=/usr/local/cuda
agent=${XPROBE_PREBUILT_AGENT:-${build_dir}/libxprobe-cupti.so}
fixture="${build_dir}/xprobe-cuda-launch"
compute_capability=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | sed -n '1p')
compute_arch=${compute_capability//./}

mkdir -p "${build_dir}"

if [[ -z ${XPROBE_PREBUILT_AGENT:-} ]]; then
  gcc \
    -std=c11 -D_GNU_SOURCE -DXPROBE_HAS_CUPTI=1 \
    -fPIC -shared -pthread -O2 -Wall -Wextra -Wpedantic -Werror \
    -I/workspace/cupti/include -isystem "${cuda_root}/include" \
    /workspace/cupti/src/cupti_agent.c \
    -L"${cuda_root}/lib64" -Wl,-rpath,"${cuda_root}/lib64" -lcupti \
    -o "${agent}"
fi

nvcc \
  -std=c++17 -O2 \
  -gencode="arch=compute_${compute_arch},code=sm_${compute_arch}" \
  /workspace/cupti/tests/cuda_launch_fixture.cu \
  -o "${fixture}"

XPROBE_CUPTI_OUTPUT="$1" CUDA_INJECTION64_PATH="${agent}" "${fixture}"
chmod 0644 "$1"
