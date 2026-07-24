#!/usr/bin/env python3
import argparse
import json
import pathlib
import subprocess
import sys
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    workspace = pathlib.Path(__file__).resolve().parents[2]

    with tempfile.TemporaryDirectory(prefix="xprobe-nvtx-") as output_dir:
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
                args.image,
                "/workspace/tests/integration/run-nvtx-live.sh",
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
                if path.suffix in {".json", ".jsonl", ".log", ".stderr"}:
                    sys.stderr.write(
                        f"\n--- {path.name} ---\n"
                        f"{path.read_text(errors='replace')}\n"
                    )
            raise SystemExit(completed.returncode)

        output = pathlib.Path(output_dir)
        nested = json.loads((output / "nested.json").read_text())
        extended = json.loads((output / "extended.json").read_text())
        cross = json.loads((output / "cross.json").read_text())
        limit = json.loads((output / "limit.json").read_text())
        long_name = json.loads((output / "long.json").read_text())

    assert_measurement(nested, "thread")
    assert_measurement(extended, "thread")
    assert_measurement(cross, "process")
    assert_measurement(long_name, "thread")
    assert limit["ok"] is False
    assert limit["error"]["code"] == "EVENT_RATE_TOO_HIGH"
    assert all(
        pair["start"]["tid"] != pair["end"]["tid"]
        and pair["start"]["nvtx"]["start_tid"] == pair["start"]["tid"]
        and pair["end"]["nvtx"]["start_tid"] == pair["start"]["tid"]
        for pair in cross["evidence"]
    )
    assert all(
        pair["start"]["nvtx"]["name_complete"] is False
        and pair["end"]["nvtx"]["name_complete"] is False
        for pair in long_name["evidence"]
    )
    print(
        json.dumps(
            {
                "cross_thread_samples": cross["measurement"]["samples"]["matched"],
                "extended_samples": extended["measurement"]["samples"]["matched"],
                "nested_samples": nested["measurement"]["samples"]["matched"],
                "ok": True,
            },
            sort_keys=True,
        )
    )


def assert_measurement(result: dict, range_kind: str) -> None:
    assert result["ok"] is True
    assert result["measurement"]["samples"]["matched"] == 8
    assert result["measurement"]["samples"]["dropped"] == 0
    assert result["correlation"]["method"] == "exact_nvtx_range_id"
    assert all(
        pair["start"]["nvtx"]["range_kind"] == range_kind
        and pair["end"]["nvtx"]["range_kind"] == range_kind
        and pair["start"]["nvtx"]["range_id"] == pair["end"]["nvtx"]["range_id"]
        for pair in result["evidence"]
    )


if __name__ == "__main__":
    main()
