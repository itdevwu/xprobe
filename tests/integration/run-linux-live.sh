#!/usr/bin/env bash
set -euo pipefail

target=/workspace/build/tests/xprobe-syscall-target
binary=/workspace/target/debug/xprobe
mmap_capture=/tmp/xprobe-mmap.json
munmap_capture=/tmp/xprobe-munmap.json
tracepoint_capture=/tmp/xprobe-tracepoint.json
capacity_capture=/tmp/xprobe-capacity.json
capacity_stderr=/tmp/xprobe-capacity.stderr

"${target}" &
target_pid=$!
cleanup() {
  kill "${target_pid}" 2>/dev/null || true
  wait "${target_pid}" 2>/dev/null || true
  rm -f "${mmap_capture}" "${munmap_capture}" "${tracepoint_capture}" \
    "${capacity_capture}" "${capacity_stderr}"
}
trap cleanup EXIT

"${binary}" measure \
  --pid "${target_pid}" \
  --from syscall:mmap:entry \
  --to syscall:mmap:exit \
  --match exact \
  --samples 3 \
  --max-events 64 \
  --timeout-ms 5000 \
  --json --non-interactive --no-color >"${mmap_capture}"

"${binary}" measure \
  --pid "${target_pid}" \
  --from syscall:munmap:entry \
  --to syscall:munmap:exit \
  --match exact \
  --samples 3 \
  --max-events 64 \
  --timeout-ms 5000 \
  --json --non-interactive --no-color >"${munmap_capture}"

"${binary}" measure \
  --pid "${target_pid}" \
  --from tracepoint:raw_syscalls:sys_enter \
  --to tracepoint:raw_syscalls:sys_exit \
  --match first-after \
  --samples 3 \
  --max-events 64 \
  --timeout-ms 5000 \
  --json --non-interactive --no-color >"${tracepoint_capture}"

if "${binary}" measure \
  --pid "${target_pid}" \
  --from syscall:mmap:entry \
  --to syscall:mmap:exit \
  --match exact \
  --duration-ms 500 \
  --max-events 4 \
  --timeout-ms 5000 \
  --json --non-interactive --no-color \
  >"${capacity_capture}" 2>"${capacity_stderr}"; then
  echo "Linux capacity test unexpectedly succeeded" >&2
  exit 1
fi

printf '{"mmap":'
cat "${mmap_capture}"
printf ',"munmap":'
cat "${munmap_capture}"
printf ',"tracepoint":'
cat "${tracepoint_capture}"
printf ',"capacity":'
cat "${capacity_capture}"
printf '}\n'
