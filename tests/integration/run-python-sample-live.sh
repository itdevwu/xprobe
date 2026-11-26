#!/usr/bin/env bash
# Inside one python:3.N image: check the built-in layout against this
# version's headers, then sample a workload with xprobe.
set -euo pipefail

output=$1
minor=$(python3 -c 'import sys; print(sys.version_info.minor)')
include=$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["include"])')
layout=/workspace/tests/integration/python-layout
gcc -I"${include}" -I"${include}/internal" "${layout}/layout.c" -o /tmp/layout
/tmp/layout >"${output}/layout.json"
if (( minor >= 13 )); then
  gcc -I"${include}" -I"${include}/internal" "${layout}/debug-offsets.c" -o /tmp/debug-offsets
  /tmp/debug-offsets >"${output}/debug-offsets.json"
fi

python3 /workspace/tests/integration/python_sample_workload.py >"${output}/workload.txt" &
target=$!
trap 'kill "${target}" 2>/dev/null || true' EXIT
for _ in $(seq 1 200); do
  grep -q ready "${output}/workload.txt" 2>/dev/null && break
  sleep 0.05
done
sleep 0.5
/workspace/target/debug/xprobe measure --pid "${target}" --python-sample --duration-ms 2000 \
  --json --events-out "${output}/samples.jsonl" >"${output}/result.json"
python3 --version >"${output}/python-version.txt"
chmod -R a+rwX "${output}"
