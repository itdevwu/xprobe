#!/usr/bin/env python3
import pathlib
import subprocess
import sys


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_pytorch.py <container-image> <pytorch-env>")

    workspace = pathlib.Path(__file__).resolve().parents[2]
    pytorch_env = pathlib.Path(sys.argv[2]).resolve()
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
            "--security-opt",
            "seccomp=unconfined",
            "--volume",
            f"{workspace}:/workspace:ro",
            "--volume",
            f"{pytorch_env}:/opt/xprobe-pytorch:ro",
            "--workdir",
            "/workspace",
            sys.argv[1],
            "/opt/xprobe-pytorch/bin/python",
            "/workspace/tests/integration/test_pytorch_symbols.py",
            "--python",
            "/opt/xprobe-pytorch/bin/python",
            "--xprobe",
            "/workspace/target/debug/xprobe",
            "--measure",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise SystemExit(completed.returncode)
    sys.stdout.write(completed.stdout)


if __name__ == "__main__":
    main()
