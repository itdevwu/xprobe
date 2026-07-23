#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile


def read_metrics(path: pathlib.Path) -> dict[str, int]:
    return {
        key: int(value)
        for key, value in (line.split() for line in path.read_text().splitlines())
    }


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: run.py <container-image>")

    workspace = pathlib.Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="xprobe-cuda-aggregate-") as temporary:
        output = pathlib.Path(temporary)
        completed = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--gpus",
                "all",
                "--volume",
                f"{workspace}:/workspace:ro",
                "--volume",
                f"{output}:/output",
                "--workdir",
                "/workspace",
                sys.argv[1],
                "/workspace/benchmarks/cuda-aggregate/run-container.sh",
                "/output",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            raise SystemExit(completed.returncode)

        exact = json.loads((output / "exact-result.json").read_text())
        aggregate = json.loads((output / "aggregate-result.json").read_text())
        exact_metrics = read_metrics(output / "exact-metrics.txt")
        aggregate_metrics = read_metrics(output / "aggregate-metrics.txt")
        exact_artifact_bytes = (output / "exact-events.jsonl").stat().st_size
        aggregate_artifact_bytes = (output / "aggregate-result.json").stat().st_size
        gpu = (output / "gpu.txt").read_text().strip()

    assert exact["ok"] is True
    assert exact["status"] == "completed"
    assert exact["collection"]["cuda_events"] > 10_000
    assert exact["collection"]["dropped_events"] == 0
    assert aggregate["ok"] is True
    assert aggregate["status"] == "completed"
    collection = aggregate["collection"]
    assert collection["observed_activities"] > 10_000
    assert collection["observed_activities"] == collection["grouped_activities"]
    assert collection["observed_activities"] > collection["group_capacity"]
    assert collection["groups"] == 2
    assert collection["occupied_slots"] == 2
    assert collection["dropped_activities"] == 0
    assert exact_artifact_bytes > aggregate_artifact_bytes * 100
    exact_cpu_us = exact_metrics["user_us"] + exact_metrics["system_us"]
    aggregate_cpu_us = aggregate_metrics["user_us"] + aggregate_metrics["system_us"]
    exact_target_growth = (
        exact_metrics["target_peak_rss_kib"] - exact_metrics["target_start_rss_kib"]
    )
    aggregate_target_growth = (
        aggregate_metrics["target_peak_rss_kib"]
        - aggregate_metrics["target_start_rss_kib"]
    )
    assert aggregate_cpu_us < exact_cpu_us
    assert aggregate_metrics["max_rss_kib"] < exact_metrics["max_rss_kib"]
    assert aggregate_target_growth < exact_target_growth

    print(
        json.dumps(
            {
                "schema_version": "2.0",
                "ok": True,
                "gpu": gpu,
                "resources": {
                    "exact": exact_metrics,
                    "aggregate": aggregate_metrics,
                    "exact_cpu_us": exact_cpu_us,
                    "aggregate_cpu_us": aggregate_cpu_us,
                    "exact_target_growth_kib": exact_target_growth,
                    "aggregate_target_growth_kib": aggregate_target_growth,
                },
                "artifacts": {
                    "exact_bytes": exact_artifact_bytes,
                    "aggregate_bytes": aggregate_artifact_bytes,
                    "reduction": exact_artifact_bytes / aggregate_artifact_bytes,
                },
                "collection": collection,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
