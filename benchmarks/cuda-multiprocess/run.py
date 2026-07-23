#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import sys
import tempfile


def dump_failure_artifacts(output: pathlib.Path) -> None:
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.suffix not in {".json", ".stderr", ".stdout"}:
            continue
        sys.stderr.write(f"\n--- {path.relative_to(output)} ---\n")
        sys.stderr.write(path.read_text(errors="replace"))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: run.py <container-image>")

    workspace = pathlib.Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="xprobe-cuda-multiprocess-") as temporary:
        output = pathlib.Path(temporary)
        completed = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--gpus",
                "all",
                "--cap-add",
                "SYS_PTRACE",
                "--security-opt",
                "seccomp=unconfined",
                "--env",
                f"XPROBE_HOST_UID={os.getuid()}",
                "--env",
                f"XPROBE_HOST_GID={os.getgid()}",
                "--volume",
                f"{workspace}:/workspace:ro",
                "--volume",
                f"{output}:/output",
                "--workdir",
                "/workspace",
                sys.argv[1],
                "/usr/bin/perl",
                "/workspace/benchmarks/cuda-multiprocess/run-container.pl",
                "/output",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            dump_failure_artifacts(output)
            raise SystemExit(completed.returncode)

        report = json.loads((output / "report.json").read_text())
        if report.get("schema_version") != "2.0" or report.get("ok") is not True:
            raise RuntimeError("multiprocess benchmark report is malformed or unsuccessful")
        print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
