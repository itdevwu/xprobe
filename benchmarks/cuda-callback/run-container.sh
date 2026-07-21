#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: run-container.sh <output-directory>" >&2
  exit 2
fi

output_dir=$1
build_dir=/tmp/xprobe-cuda-benchmark
cuda_root=/usr/local/cuda
agent=${build_dir}/libxprobe-cupti.so
fixture=${build_dir}/xprobe-cuda-benchmark
compute_capability=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | sed -n '1p')
compute_arch=${compute_capability//./}

mkdir -p "${build_dir}" "${output_dir}"

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
  /workspace/benchmarks/cuda-callback/cuda_benchmark.cu \
  -o "${fixture}"

"${fixture}" "${output_dir}/baseline.json" 1000 5
XPROBE_CUPTI_OUTPUT="${output_dir}/capture.bin" \
  CUDA_INJECTION64_PATH="${agent}" \
  "${fixture}" "${output_dir}/instrumented.json" 1000 5
nvidia-smi \
  --query-gpu=name,driver_version,compute_cap \
  --format=csv,noheader >"${output_dir}/gpu.txt"
chmod 0644 "${output_dir}"/*
