#!/usr/bin/env python3
"""Run the Python sampling overhead benchmark in each listed python image."""

import json
import pathlib
import subprocess
import sys

TARGET_RATIO = 1.02


def main() -> None:
    images = sys.argv[1:] or ["python:3.10", "python:3.12"]
    workspace = pathlib.Path(__file__).resolve().parents[2]
    reports = []
    for image in images:
        completed = subprocess.run(
            [
                "docker", "run", "--rm",
                "--volume", f"{workspace}:/workspace:ro",
                image, "python3", "/workspace/benchmarks/python-sampling/run-inside.py",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            raise SystemExit(completed.returncode)
        report = json.loads(completed.stdout.strip().splitlines()[-1])
        report["image"] = image
        report["project_target_ratio"] = TARGET_RATIO
        report["project_target_met"] = report["overhead_ratio"] <= TARGET_RATIO
        reports.append(report)
    print(json.dumps({"ok": True, "reports": reports}, sort_keys=True))


if __name__ == "__main__":
    main()
