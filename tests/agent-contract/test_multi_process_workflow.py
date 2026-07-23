#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile
import time


def identity(target: dict) -> tuple[int, int]:
    return target["pid"], target["process_start_time"]


def verified_selection(fixture: dict, validations: list[dict]) -> list[dict]:
    candidates = {
        identity(candidate["target"]): candidate
        for candidate in fixture["discovery"]["candidates"]
    }
    selected = fixture["selected"]
    assert len(selected) == len({identity(target) for target in selected})
    assert identity(fixture["representative"]) == identity(selected[0])
    for target, validation in zip(selected, validations, strict=True):
        assert identity(target) in candidates
        if not validation["valid"] or identity(validation["target"]) != identity(target):
            raise ValueError("worker identity changed before measurement")
    return selected


def fake_measure(spec_path: pathlib.Path, events_path: pathlib.Path) -> int:
    spec = json.loads(spec_path.read_text())
    target = spec["target"]
    started_ns = time.monotonic_ns()
    time.sleep(0.15)
    events_path.write_text(
        json.dumps(
            {
                "schema_version": "2.0",
                "pid": target["pid"],
                "process_start_time": target["process_start_time"],
            }
        )
        + "\n"
    )
    finished_ns = time.monotonic_ns()
    if target["pid"] == 4102:
        print("fixture worker failed", file=sys.stderr)
        print(
            json.dumps(
                {
                    "schema_version": "2.0",
                    "ok": False,
                    "error": {"code": "FIXTURE_FAILURE"},
                    "started_ns": started_ns,
                    "finished_ns": finished_ns,
                }
            )
        )
        return 7
    print("fixture injection warning", file=sys.stderr)
    print(
        json.dumps(
            {
                "schema_version": "2.0",
                "ok": True,
                "status": "completed",
                "started_ns": started_ns,
                "finished_ns": finished_ns,
            }
        )
    )
    return 0


def run_contract() -> None:
    workspace = pathlib.Path(__file__).resolve().parents[2]
    fixture = json.loads(
        (workspace / "tests/agent-contract/fixtures/multi-process.json").read_text()
    )
    selected = verified_selection(fixture, fixture["validations"])
    try:
        verified_selection(
            fixture, [fixture["validations"][0], fixture["stale_validation"]]
        )
    except ValueError:
        pass
    else:
        raise AssertionError("stale worker identity was accepted")

    with tempfile.TemporaryDirectory(prefix="xprobe-multi-process-") as directory:
        root = pathlib.Path(directory)
        processes = []
        paths = []
        for target in selected:
            suffix = f"{target['pid']}-{target['process_start_time']}"
            spec_path = root / f"spec-{suffix}.json"
            result_path = root / f"result-{suffix}.json"
            stderr_path = root / f"stderr-{suffix}.log"
            events_path = root / f"events-{suffix}.jsonl"
            spec_path.write_text(
                json.dumps(
                    {
                        "schema_version": "2.0",
                        "target": target,
                        "start_selector": "cuda:kernel_start:name~^fixture_kernel$",
                        "end_selector": "cuda:kernel_end:name~^fixture_kernel$",
                        "match_policy": "exact",
                        "samples": 10,
                        "duration_ms": None,
                        "timeout_ms": 5000,
                        "max_events": 100,
                        "measurement_mode": "exact",
                        "max_groups": None,
                        "name": suffix,
                    }
                )
            )
            command = [
                sys.executable,
                __file__,
                "--fake-measure",
                str(spec_path),
                str(events_path),
            ]
            processes.append(
                (
                    target,
                    subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    ),
                    result_path,
                    stderr_path,
                )
            )
            paths.extend((spec_path, result_path, stderr_path, events_path))

        outcomes = []
        for target, process, result_path, stderr_path in processes:
            stdout, stderr = process.communicate(timeout=5)
            result_path.write_text(stdout)
            stderr_path.write_text(stderr)
            outcomes.append(
                {
                    "target": target,
                    "returncode": process.returncode,
                    "result": json.loads(stdout),
                    "stderr": stderr,
                }
            )

        assert len(paths) == len(set(paths))
        assert {outcome["returncode"] for outcome in outcomes} == {0, 7}
        assert any(outcome["result"]["ok"] for outcome in outcomes)
        assert any(not outcome["result"]["ok"] for outcome in outcomes)
        latest_start = max(outcome["result"]["started_ns"] for outcome in outcomes)
        earliest_finish = min(outcome["result"]["finished_ns"] for outcome in outcomes)
        assert latest_start < earliest_finish
        assert all(path.is_file() for path in paths)

    print(
        json.dumps(
            {
                "schema_version": "2.0",
                "ok": True,
                "selected": [identity(target) for target in selected],
                "representative": identity(fixture["representative"]),
                "partial_failure_preserved": True,
            },
            sort_keys=True,
        )
    )


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "--fake-measure":
        return fake_measure(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
    if len(sys.argv) != 1:
        raise SystemExit(f"usage: {sys.argv[0]}")
    run_contract()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
