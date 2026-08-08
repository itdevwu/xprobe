#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: run-container.py <container-image>")

    workspace = pathlib.Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--cap-add",
            "BPF",
            "--cap-add",
            "PERFMON",
            "--cap-add",
            "SYS_ADMIN",
            "--cap-add",
            "SYS_RESOURCE",
            "--cap-add",
            "SYS_PTRACE",
            "--security-opt",
            "seccomp=unconfined",
            "--volume",
            f"{workspace}:/workspace:ro",
            "--workdir",
            "/workspace",
            sys.argv[1],
            "/workspace/benchmarks/cpu-inventory/run-container.sh",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise SystemExit(completed.returncode)

    reports = [line for line in completed.stdout.splitlines() if line.startswith("{")]
    if not reports:
        raise AssertionError(
            f"CPU inventory benchmark emitted no JSON report:\n{completed.stdout}"
        )
    print(json.dumps(json.loads(reports[-1]), sort_keys=True))


if __name__ == "__main__":
    main()
