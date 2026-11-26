#!/usr/bin/env python3
"""Triggered capture against a CUDA fixture with a rare 30 ms bubble."""

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

MS = 1_000_000


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_trigger.py <container-image> <xprobe-binary>")
    workspace = pathlib.Path(__file__).resolve().parents[2]
    xprobe = workspace / sys.argv[2]
    with tempfile.TemporaryDirectory(prefix="xprobe-trigger-") as output_dir:
        output = pathlib.Path(output_dir)
        completed = subprocess.run(
            [
                "docker", "run", "--rm", "--gpus", "all",
                "--volume", f"{workspace}:/workspace:ro",
                "--volume", f"{output}:/output",
                "--workdir", "/workspace",
                sys.argv[1],
                "/workspace/tests/integration/run-trigger-live.sh", "/output",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            raise SystemExit(completed.returncode)

        def outcome(name: str) -> tuple[int, dict]:
            status = int((output / f"{name}.status").read_text())
            return status, json.loads((output / f"{name}.json").read_text())

        fired_status, fired = outcome("fired")
        assert fired_status == 0, fired
        windows = fired["windows"]
        assert fired["status"] == "completed", fired["status"]
        assert len(windows) == 2, len(windows)
        assert fired["collection"]["overwritten_records"] == 0, fired["collection"]
        assert fired["observed"]["spans"] > 1000, fired["observed"]
        offline = []
        for window in windows:
            assert window["fired"]["latency_ns"] >= 20 * MS, window["fired"]
            # Both windows sit well inside the capture.
            assert window["truncated"] is False, window
            assert window["start_ns"] <= window["fired"]["start"]["timestamp_ns"] - 5 * MS
            artifact = output / pathlib.Path(window["artifact"]["path"]).relative_to("/output")
            manifest = json.loads(
                artifact.with_name(artifact.name + ".manifest.json").read_text()
            )
            assert manifest["artifact"]["sha256"] == hashlib.sha256(
                artifact.read_bytes()
            ).hexdigest()
            assert manifest["all_gpu_activity"] is True, manifest
            assert manifest["dropped_records"] == 0
            # The window re-correlates offline and keeps its coverage.
            measured = subprocess.run(
                [
                    xprobe, "measure", "--input", artifact,
                    "--from", "cuda:kernel_end", "--to", "cuda:kernel_start",
                    "--match", "stream-order", "--json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            assert measured.returncode == 0, measured.stdout
            result = json.loads(measured.stdout)
            assert result["collection"]["coverage"]["source"] == "manifest", result
            assert result["correlation"]["confidence"] == "high", result
            assert result["measurement"]["latency_ns"]["max"] == window["fired"]["latency_ns"]
            offline.append(result["measurement"]["latency_ns"]["max"])
        # The second window starts after the first ends.
        assert windows[1]["start_ns"] >= windows[0]["end_ns"]

        unobserved_status, unobserved = outcome("unobserved")
        assert unobserved_status != 0, unobserved
        error = unobserved["error"]
        assert error["code"] == "TRIGGER_NOT_OBSERVED", error
        assert 0 < error["details"]["longest_ns"] < 500 * MS, error

        # A ring smaller than one snapshot's records loses windows and says so.
        ring_status, ring = outcome("small-ring")
        if ring_status == 0:
            overwritten = ring["collection"]["overwritten_records"]
            assert ring["collection"]["lost_windows"] > 0, ring
        else:
            assert ring["error"]["code"] in {"EVENTS_DROPPED", "TRIGGER_NOT_OBSERVED"}, ring
            overwritten = ring["error"]["details"]["overwritten_records"]
        assert overwritten > 0, ring

    print(
        json.dumps(
            {
                "fired_gaps_ms": [window["fired"]["latency_ns"] / MS for window in windows],
                "offline_max_ms": [value / MS for value in offline],
                "spans": fired["observed"]["spans"],
                "unobserved_longest_ms": error["details"]["longest_ns"] / MS,
                "small_ring_overwritten": overwritten,
                "ok": True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
