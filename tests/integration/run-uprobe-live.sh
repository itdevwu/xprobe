#!/usr/bin/env bash
set -euo pipefail

target=/workspace/build/tests/xprobe-uprobe-target

"${target}" &
target_pid=$!
trap 'kill "${target_pid}" 2>/dev/null || true; wait "${target_pid}" 2>/dev/null || true' EXIT

/workspace/target/debug/xprobe dev uprobe \
  --pid "${target_pid}" \
  --binary "${target}" \
  --symbol xprobe_test_marker \
  --probe-id 7 \
  --samples 3 \
  --timeout-ms 5000 \
  --json \
  --non-interactive \
  --no-color
