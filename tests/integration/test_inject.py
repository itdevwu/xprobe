#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile


def main() -> None:
    if len(sys.argv) not in (2, 3):
        raise SystemExit("usage: test_inject.py <container-image> [package-root]")
    workspace = pathlib.Path(__file__).resolve().parents[2]
    package = pathlib.Path(sys.argv[2]).resolve() if len(sys.argv) == 3 else None
    with tempfile.TemporaryDirectory(prefix="xprobe-inject-") as output_dir:
        command = [
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
        ]
        if package is not None:
            command.extend(
                [
                    "--volume",
                    f"{package}:/package:ro",
                    "--env",
                    "XPROBE_BIN=/package/bin/xprobe",
                    "--env",
                    "XPROBE_AUTO_AGENT=1",
                ]
            )
        command.extend(
            [
                "--workdir",
                "/workspace",
                sys.argv[1],
                "/workspace/tests/integration/run-inject-live.sh",
                "/output",
            ]
        )
        completed = subprocess.run(
            command,
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
        for name in ("first", "second", "api"):
            result = json.loads((output / f"{name}.json").read_text())
            assert result["ok"] is True
            assert result["status"] == "completed"
            assert result["measurement"]["samples"]["matched"] == 3
            assert result["collection"]["cuda_events"] >= 6
            assert result["collection"]["cuda_events"] % 2 == 0
            cupti = result["collection"]["cupti"]
            assert cupti["observed_records"] == cupti["retained_records"]
            assert cupti["retained_records"] == result["collection"]["cuda_events"]
            stderr = (output / f"{name}.stderr").read_text()
            assert "activating the CUPTI agent modifies target PID" in stderr
        first = json.loads((output / "first.json").read_text())
        second = json.loads((output / "second.json").read_text())
        api = json.loads((output / "api.json").read_text())
        assert any(warning["code"] == "CUPTI_AGENT_INJECTED" for warning in first["warnings"])
        assert all(warning["code"] != "CUPTI_AGENT_INJECTED" for warning in second["warnings"])
        assert all(warning["code"] != "CUPTI_AGENT_INJECTED" for warning in api["warnings"])
        assert int((output / "mapped-agents.txt").read_text()) == 1
        if package is not None:
            expected_major = 12 if ":12." in sys.argv[1] else 13
            injected = next(
                warning
                for warning in first["warnings"]
                if warning["code"] == "CUPTI_AGENT_INJECTED"
            )
            assert injected["details"]["cuda_major"] == expected_major
            assert f"/cuda{expected_major}/" in injected["details"]["agent_path"]
            assert "libcupti.so" in injected["details"]["cupti_path"]
        print(
            json.dumps(
                {
                    "schema_version": "2.0",
                    "ok": True,
                    "gpu": "NVIDIA GeForce RTX 3060 Laptop GPU",
                    "measurements": 3,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
