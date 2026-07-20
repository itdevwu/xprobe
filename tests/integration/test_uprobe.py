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
    captures = json.loads(completed.stdout)
    entry = captures["entry"]
    returned = captures["return"]

    assert_capture(entry, probe_id=7, event_type="host_function_entry", kind="uprobe")
    assert_capture(
        returned,
        probe_id=8,
        event_type="host_function_exit",
        kind="uretprobe",
    )
    assert entry["target"] == returned["target"]

    print(
        f"captured {entry['captured']} uprobe and {returned['captured']} "
        f"uretprobe events from PID {entry['target']['pid']}"
    )


def assert_capture(result: dict, probe_id: int, event_type: str, kind: str) -> None:
    assert result["schema_version"] == "1.0"
    assert result["ok"] is True
    assert result["probe_id"] == probe_id
    assert result["captured"] == 3
    assert result["dropped"] == 0
    assert result["timed_out"] is False
    assert len(result["events"]) == 3
    assert all(event["source"] == "ebpf" for event in result["events"])
    assert all(event["event_type"] == event_type for event in result["events"])
    assert all(event["pid"] == result["target"]["pid"] for event in result["events"])
    assert all(event["tid"] == result["target"]["pid"] for event in result["events"])
    assert all(event["host"]["probe_kind"] == kind for event in result["events"])
    assert all(event["host"]["return_value"] is None for event in result["events"])
    assert all(
        event["host"]["symbol"] == "xprobe_test_marker" for event in result["events"]
    )


if __name__ == "__main__":
    main()
