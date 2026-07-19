#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_uprobe.py <container-image>")

    workspace = pathlib.Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--privileged",
            "--security-opt",
            "seccomp=unconfined",
            "--volume",
            f"{workspace}:/workspace:ro",
            "--workdir",
            "/workspace",
            sys.argv[1],
            "/workspace/tests/integration/run-uprobe-live.sh",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise SystemExit(completed.returncode)
    result = json.loads(completed.stdout)

    assert result["schema_version"] == "1.0"
    assert result["ok"] is True
    assert result["probe_id"] == 7
    assert result["captured"] == 3
    assert result["dropped"] == 0
    assert result["timed_out"] is False
    assert len(result["events"]) == 3
    assert all(event["source"] == "ebpf" for event in result["events"])
    assert all(event["pid"] == result["target"]["pid"] for event in result["events"])
    assert all(event["tid"] == result["target"]["pid"] for event in result["events"])
    assert all(
        event["host"]["symbol"] == "xprobe_test_marker" for event in result["events"]
    )

    print(
        f"captured {result['captured']} uprobe events "
        f"from PID {result['target']['pid']}"
    )


if __name__ == "__main__":
    main()
