#!/usr/bin/env python3
"""Every kernel in an exact burst is either measured or reported as dropped."""

import json
import pathlib
import subprocess
import sys
import tempfile


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_cupti_burst.py <container-image> <kernels-per-stream>")
    workspace = pathlib.Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="xprobe-cupti-burst-") as directory:
        output = pathlib.Path(directory)
        completed = subprocess.run(
            [
                "docker", "run", "--rm", "--gpus", "all",
                "--volume", f"{workspace}:/workspace:ro",
                "--volume", f"{output}:/output",
                "--workdir", "/workspace",
                sys.argv[1],
                "/workspace/tests/integration/run-cupti-burst-live.sh", "/output", sys.argv[2],
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            raise SystemExit(completed.returncode)
        expected = int((output / "burst-expected").read_text())
        status = int((output / "burst-exit-status").read_text())
        result = json.loads((output / "burst-measure.json").read_text())

    if status == 0:
        matched = result["measurement"]["samples"]["matched"]
        report = {
            "expected": expected,
            "matched": matched,
            "dropped": result["collection"]["dropped_events"],
            "verdict": result["quality"]["verdict"],
        }
        # A complete result must contain every launched kernel.
        assert matched == expected, report
    else:
        error = result["error"]
        report = {"expected": expected, "error": error["code"], "details": error["details"]}
        # Loss is acceptable only when it is reported explicitly.
        assert error["code"] in {"EVENTS_DROPPED", "EVENT_RATE_TOO_HIGH"}, report
    print(json.dumps({"ok": True, **report}, sort_keys=True))


if __name__ == "__main__":
    main()
