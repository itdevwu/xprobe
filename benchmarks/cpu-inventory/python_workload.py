#!/usr/bin/env python3
import gc
import json
import pathlib
import sys
import time


def write_metrics(path: pathlib.Path, count: int) -> None:
    replacement = path.with_name(f"{path.name}.next")
    replacement.write_text(
        json.dumps({"count": count, "timestamp_ns": time.monotonic_ns()})
    )
    replacement.replace(path)


def python_leaf(seed: int) -> int:
    return sum((seed + index) & 0xFFFF for index in range(4000))


def python_hot_loop(seed: int) -> int:
    return python_leaf(seed) ^ python_leaf(seed + 1)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python_workload.py <metrics-output>")
    metrics = pathlib.Path(sys.argv[1])
    count = 0
    value = 0
    write_metrics(metrics, count)
    print(
        json.dumps(
            {
                "language": "python",
                "pid": __import__("os").getpid(),
                "python": sys.version.split()[0],
                "perf_map": sys._xoptions.get("perf") is not None,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    while True:
        value ^= python_hot_loop(value)
        count += 1
        if count % 64 == 0:
            cycle: list[object] = []
            cycle.append(cycle)
            del cycle
            gc.collect()
            write_metrics(metrics, count)


if __name__ == "__main__":
    main()
