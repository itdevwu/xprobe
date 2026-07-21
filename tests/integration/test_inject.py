#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_inject.py <container-image>")
    workspace = pathlib.Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="xprobe-inject-") as output_dir:
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
                "--volume",
                f"{workspace}:/workspace:ro",
                "--volume",
                f"{output_dir}:/output",
                "--workdir",
                "/workspace",
                sys.argv[1],
                "/workspace/tests/integration/run-inject-live.sh",
                "/output",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            for path in sorted(pathlib.Path(output_dir).glob("*")):
                sys.stderr.write(f"\n--- {path.name} ---\n{path.read_text()}\n")
            raise SystemExit(completed.returncode)

        output = pathlib.Path(output_dir)
        for name in ("first", "second"):
            result = json.loads((output / f"{name}.json").read_text())
            assert result["ok"] is True
            assert result["status"] == "completed"
            assert result["measurement"]["samples"]["matched"] == 3
            stderr = (output / f"{name}.stderr").read_text()
            assert "activating the CUPTI agent modifies target PID" in stderr
        first = json.loads((output / "first.json").read_text())
        second = json.loads((output / "second.json").read_text())
        assert any(warning["code"] == "CUPTI_AGENT_INJECTED" for warning in first["warnings"])
        assert all(warning["code"] != "CUPTI_AGENT_INJECTED" for warning in second["warnings"])
        assert int((output / "mapped-agents.txt").read_text()) == 1
        print(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "ok": True,
                    "gpu": "NVIDIA GeForce RTX 3060 Laptop GPU",
                    "measurements": 2,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
