#!/usr/bin/env bash
set -euo pipefail

target=/workspace/build/tests/xprobe-uprobe-target
entry_capture=/tmp/xprobe-uprobe-entry.json

"${target}" &
target_pid=$!
cleanup() {
  kill "${target_pid}" 2>/dev/null || true
  wait "${target_pid}" 2>/dev/null || true
  rm -f "${entry_capture}"
}
trap cleanup EXIT

/workspace/target/debug/xprobe dev uprobe \
  --pid "${target_pid}" \
  --binary "${target}" \
  --symbol xprobe_test_marker \
  --probe-id 7 \
  --samples 3 \
  --timeout-ms 5000 \
  --json \
  --non-interactive \
  --no-color >"${entry_capture}"

printf '{"entry":'
cat "${entry_capture}"
printf ',"return":'
/workspace/target/debug/xprobe dev uprobe \
  --pid "${target_pid}" \
  --binary "${target}" \
  --symbol xprobe_test_marker \
  --return \
  --probe-id 8 \
  --samples 3 \
  --timeout-ms 5000 \
  --json \
  --non-interactive \
  --no-color
printf '}\n'
