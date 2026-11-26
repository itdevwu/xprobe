#!/usr/bin/env python3
"""External CPython sampling across every supported minor version."""

import json
import pathlib
import subprocess
import sys
import tempfile

MINORS = (9, 10, 11, 12, 13, 14)


def check(minor: int, output: pathlib.Path, expected: dict) -> dict:
    version = f"3.{minor}"
    # The built-in layout is the one this version's headers produce.
    layout = json.loads((output / "layout.json").read_text())
    layout.pop("end")
    assert layout.pop("version") == version
    assert layout == expected["layouts"][version], (version, layout)
    if minor >= 13:
        debug = json.loads((output / "debug-offsets.json").read_text())
        debug.pop("end")
        assert debug == expected["debug_offsets"][version], (version, debug)

    result = json.loads((output / "result.json").read_text())
    assert result["ok"] is True, result
    collection = result["collection"]
    assert collection["python_version"] == version, collection
    assert collection["tid_source"] == ("native" if minor >= 11 else "pthread"), collection
    assert collection["gil_hz_achieved"] >= 1800, collection
    assert collection["threads"] == 2, collection
    reads = collection["gil_samples"] + collection["thread_samples"]
    assert collection["inconsistent_reads"] <= reads * 0.05, collection
    hottest = result["inventory"]["gil_hotspots"][0]
    assert hottest["frame"]["function"] == "hot_inner", hottest
    assert hottest["exclusive_proportion"] >= 0.8, hottest
    sleeper = [
        group
        for group in result["inventory"]["thread_stack_groups"]
        if group["frames"][0]["function"] == "sleeper"
    ]
    assert sleeper, result["inventory"]["thread_stack_groups"]
    records = [
        json.loads(line) for line in (output / "samples.jsonl").read_text().splitlines()
    ]
    assert len(records) == result["artifact"]["events"]
    assert all(record["tid"] is not None for record in records)
    return {
        "python": (output / "python-version.txt").read_text().split()[1],
        "gil_hz": round(collection["gil_hz_achieved"]),
        "hot_inner": round(hottest["exclusive_proportion"], 3),
        "inconsistent": collection["inconsistent_reads"],
        "read_p50_us": collection["read_latency"]["p50_ns"] // 1000,
        "read_p99_us": collection["read_latency"]["p99_ns"] // 1000,
    }


def main() -> None:
    workspace = pathlib.Path(__file__).resolve().parents[2]
    expected = json.loads(
        (workspace / "tests/integration/python-layout/expected.json").read_text()
    )
    summary = {}
    for minor in MINORS:
        with tempfile.TemporaryDirectory(prefix=f"xprobe-python-3{minor}-") as output_dir:
            output = pathlib.Path(output_dir)
            completed = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "--volume", f"{workspace}:/workspace:ro",
                    "--volume", f"{output}:/output",
                    f"python:3.{minor}",
                    "/workspace/tests/integration/run-python-sample-live.sh", "/output",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                sys.stdout.write(completed.stdout)
                sys.stderr.write(completed.stderr)
                result = output / "result.json"
                if result.exists():
                    sys.stderr.write(result.read_text())
                raise SystemExit(completed.returncode)
            summary[f"3.{minor}"] = check(minor, output, expected)
    print(json.dumps({"ok": True, "versions": summary}, sort_keys=True))


if __name__ == "__main__":
    main()
