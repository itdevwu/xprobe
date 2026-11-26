#!/usr/bin/env python3
"""Target throughput with and without xprobe Python sampling, in one image."""

import json
import os
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
XPROBE = "/workspace/target/debug/xprobe"
SECONDS = 2.0
DEPTH = 30
ROUNDS = 3


def run_case(sampled: bool) -> tuple[float, dict | None]:
    with tempfile.TemporaryDirectory() as directory:
        go = os.path.join(directory, "go")
        workload = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "workload.py"), str(DEPTH), str(SECONDS), go],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert workload.stdout.readline().strip() == "ready"
        sampler = None
        if sampled:
            sampler = subprocess.Popen(
                [
                    XPROBE, "measure", "--pid", str(workload.pid), "--python-sample",
                    "--duration-ms", str(int(SECONDS * 1000) + 300), "--json",
                    "--events-out", os.path.join(directory, "samples.jsonl"),
                ],
                stdout=subprocess.PIPE,
                text=True,
            )
            # Let the sampler locate the interpreter before the window opens.
            time.sleep(0.15)
        open(go, "w").close()
        iterations = int(workload.stdout.readline())
        workload.wait(timeout=10)
        result = None
        if sampler is not None:
            stdout, _ = sampler.communicate(timeout=30)
            result = json.loads(stdout)
            assert result["ok"] is True, result
        return iterations / SECONDS, result


def main() -> None:
    baseline, sampled, results = [], [], []
    for _ in range(ROUNDS):
        baseline.append(run_case(False)[0])
        throughput, result = run_case(True)
        sampled.append(throughput)
        results.append(result)
    collection = results[-1]["collection"]
    print(
        json.dumps(
            {
                "python": sys.version.split()[0],
                "stack_depth": DEPTH,
                "baseline_iterations_per_second": statistics.median(baseline),
                "sampled_iterations_per_second": statistics.median(sampled),
                "overhead_ratio": statistics.median(baseline) / statistics.median(sampled),
                "gil_hz_achieved": collection["gil_hz_achieved"],
                "inconsistent_reads": collection["inconsistent_reads"],
                "gil_samples": collection["gil_samples"],
                "read_latency": collection["read_latency"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
