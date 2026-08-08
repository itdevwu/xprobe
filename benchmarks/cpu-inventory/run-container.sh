#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  linux-tools-common linux-tools-generic python3 python3-pip
python3 -m pip install --break-system-packages --disable-pip-version-check \
  py-spy==0.4.2

perf_path=$(find /usr/lib/linux-tools-* -type f -name perf -print | sort -V | tail -n 1)
[[ -x "${perf_path}" ]] || {
  echo "installed perf executable was not found" >&2
  exit 1
}

exec python3 /workspace/benchmarks/cpu-inventory/run.py \
  --xprobe /workspace/target/debug/xprobe \
  --python /usr/bin/python3 \
  --perf "${perf_path}" \
  --py-spy "$(command -v py-spy)"
