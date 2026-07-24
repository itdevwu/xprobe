#!/bin/sh
set -eu

output_dir=$1
agent="${output_dir}/libxprobe-cupti.so"
fixture="${output_dir}/nvtx-range-fixture"
mode="${output_dir}/mode"
xprobe=/workspace/target/debug/xprobe

gcc -std=c11 -D_GNU_SOURCE -DXPROBE_HAS_CUPTI=1 -fPIC -shared -pthread \
  -O2 -Wall -Wextra -Wpedantic -Werror \
  -I/workspace/cupti/include -isystem /usr/local/cuda/include \
  /workspace/cupti/src/cupti_agent.c \
  -L/usr/local/cuda/lib64 -Wl,-rpath,/usr/local/cuda/lib64 -lcupti \
  -o "${agent}"

g++ -std=c++17 -pthread -O2 -Wall -Wextra -Wpedantic -Werror \
  -isystem /usr/local/cuda/include \
  /workspace/cupti/tests/nvtx_range_fixture.cpp -ldl -o "${fixture}"

printf '%s\n' nested >"${mode}"
NVTX_INJECTION64_PATH="${agent}" "${fixture}" "${mode}" \
  >"${output_dir}/fixture.log" 2>"${output_dir}/fixture.stderr" &
pid=$!
trap 'chmod 0644 "${output_dir}"/*.jsonl 2>/dev/null || true; kill "${pid}" 2>/dev/null || true; wait "${pid}" 2>/dev/null || true' EXIT

attempt=0
while ! grep -q '^ready$' "${output_dir}/fixture.log"; do
  if ! kill -0 "${pid}" 2>/dev/null; then
    set +e
    wait "${pid}"
    status=$?
    set -e
    echo "NVTX fixture exited before readiness with status ${status}" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "${attempt}" -ge 100 ]; then
    echo "timed out waiting for NVTX fixture" >&2
    exit 1
  fi
  sleep 0.01
done

measure()
{
  result=$1
  workload_mode=$2
  pattern=$3
  printf '%s\n' "${workload_mode}" >"${mode}.next"
  mv "${mode}.next" "${mode}"
  sleep 0.05
  "${xprobe}" measure \
    --pid "${pid}" \
    --agent "${agent}" \
    --from "cuda:nvtx_range_start:name~${pattern}" \
    --to "cuda:nvtx_range_end:name~${pattern}" \
    --match exact \
    --samples 8 \
    --max-events 4096 \
    --timeout-ms 30000 \
    --events-out "${output_dir}/${result}.jsonl" \
    --json --non-interactive --no-color >"${output_dir}/${result}.json"
}

measure nested nested '^xprobe_outer$'
measure extended nested '^xprobe_inner_ex$'
measure cross cross '^xprobe_cross_thread$'

printf '%s\n' nested >"${mode}.next"
mv "${mode}.next" "${mode}"
sleep 0.05
set +e
"${xprobe}" measure \
  --pid "${pid}" \
  --agent "${agent}" \
  --from 'cuda:nvtx_range_start:name~^xprobe_outer$' \
  --to 'cuda:nvtx_range_end:name~^xprobe_outer$' \
  --match exact \
  --samples 8 \
  --max-events 1 \
  --timeout-ms 30000 \
  --json --non-interactive --no-color >"${output_dir}/limit.json"
limit_status=$?
set -e
if [ "${limit_status}" -eq 0 ]; then
  echo "NVTX record limit capture unexpectedly succeeded" >&2
  exit 1
fi

measure long long '^xprobe_long_range_.*'
