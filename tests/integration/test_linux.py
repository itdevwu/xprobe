#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_linux.py <container-image>")

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
            "/workspace/tests/integration/run-linux-live.sh",
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
    assert_syscall_capture(captures["mmap"], "mmap")
    assert_syscall_capture(captures["munmap"], "munmap")
    assert_tracepoint_capture(captures["tracepoint"])
    assert_capacity_failure(captures["capacity"])
    print("captured mmap, munmap, and named tracepoint latency evidence")


def assert_syscall_capture(result: dict, name: str) -> None:
    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["measurement"]["samples"]["matched"] == 3
    assert result["measurement"]["samples"]["dropped"] == 0
    assert result["correlation"]["method"] == "exact_syscall_tid_lifecycle"
    assert result["correlation"]["confidence"] == "exact"
    assert 0 < result["correlation"]["score"] <= 1
    assert result["collection"]["host_events"] == 8
    assert result["collection"]["cuda_events"] == 0
    assert result["collection"]["dropped_events"] == 0
    assert len(result["evidence"]) == 3
    for pair in result["evidence"]:
        start = pair["start"]
        end = pair["end"]
        assert start["event_type"] == "syscall_entry"
        assert end["event_type"] == "syscall_exit"
        assert start["pid"] == end["pid"]
        assert start["tid"] == end["tid"]
        assert start["process_start_time"] == end["process_start_time"]
        assert start["host"]["probe_kind"] == "syscall"
        assert end["host"]["probe_kind"] == "syscall"
        assert start["host"]["symbol"] == name
        assert end["host"]["symbol"] == name
        assert len(start["host"]["arguments"]) == 6
        assert all(argument["read_error"] is None for argument in start["host"]["arguments"])
        assert end["host"]["arguments"] == []
        assert end["host"]["return_value"] is not None
        assert pair["latency_ns"] == end["timestamp_ns"] - start["timestamp_ns"]


def assert_tracepoint_capture(result: dict) -> None:
    assert result["ok"] is True
    assert result["measurement"]["samples"]["matched"] == 3
    assert result["correlation"]["method"] == "first_after"
    assert result["correlation"]["confidence"] == "heuristic"
    assert result["collection"]["dropped_events"] == 0
    for pair in result["evidence"]:
        assert pair["start"]["host"]["probe_kind"] == "tracepoint"
        assert pair["start"]["host"]["symbol"] == "sys_enter"
        assert pair["end"]["host"]["symbol"] == "sys_exit"
        assert pair["start"]["attributes"]["tracepoint_category"] == "raw_syscalls"
        assert pair["end"]["attributes"]["tracepoint_category"] == "raw_syscalls"


def assert_capacity_failure(result: dict) -> None:
    assert result["ok"] is False
    assert result["error"]["code"] == "EVENT_RATE_TOO_HIGH"
    assert result["error"]["details"]["record_capacity"] == 4


if __name__ == "__main__":
    main()
