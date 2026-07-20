#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: test_multisource.py <container-image> <xprobe-binary>"
        )

    workspace = pathlib.Path(__file__).resolve().parents[2]
    xprobe = workspace / sys.argv[2]
    with tempfile.TemporaryDirectory(prefix="xprobe-multisource-") as output_dir:
        completed = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--gpus",
                "all",
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
                "--volume",
                f"{output_dir}:/output",
                "--workdir",
                "/workspace",
                sys.argv[1],
                "/workspace/tests/integration/run-multisource-live.sh",
                "/output",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            raise SystemExit(completed.returncode)

        live_events = [
            json.loads(line)
            for line in (pathlib.Path(output_dir) / "live.jsonl").read_text().splitlines()
        ]
        assert any(event["event_type"] == "gpu_kernel_start" for event in live_events)
        assert {event["session_id"] for event in live_events} == {"xp_cupti_snapshot"}
        live_result = json.loads(
            (pathlib.Path(output_dir) / "live-measure.json").read_text()
        )
        assert live_result["status"] == "completed"
        assert live_result["measurement"]["samples"]["matched"] == 3
        assert live_result["collection"]["host_events"] == 3
        spec_result = json.loads(
            (pathlib.Path(output_dir) / "spec-measure.json").read_text()
        )
        assert spec_result["status"] == "completed"
        assert spec_result["measurement"]["name"] == "spec_host_to_kernel"
        assert spec_result["measurement"]["samples"]["matched"] == 3

        measured = subprocess.run(
            [
                xprobe,
                "measure",
                "--input",
                pathlib.Path(output_dir) / "host.json",
                "--input",
                pathlib.Path(output_dir) / "cupti.bin",
                "--from",
                "uprobe:/tmp/xprobe-multisource-live/"
                "xprobe-multisource-target:xprobe_request_marker:entry",
                "--to",
                "cuda:kernel_start:name~xprobe_multisource_kernel.*",
                "--match",
                "first-after",
                "--samples",
                "3",
                "--json",
                "--non-interactive",
                "--no-color",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if measured.returncode != 0:
            sys.stdout.write(measured.stdout)
            sys.stderr.write(measured.stderr)
            raise SystemExit(measured.returncode)
        result = json.loads(measured.stdout)
        trace_path = pathlib.Path(output_dir) / "trace.json"
        exported = subprocess.run(
            [
                xprobe,
                "export",
                "--input",
                pathlib.Path(output_dir) / "host.json",
                "--input",
                pathlib.Path(output_dir) / "cupti.bin",
                "--format",
                "chrome",
                "--output",
                trace_path,
                "--json",
                "--non-interactive",
                "--no-color",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if exported.returncode != 0:
            sys.stdout.write(exported.stdout)
            sys.stderr.write(exported.stderr)
            raise SystemExit(exported.returncode)
        export_result = json.loads(exported.stdout)
        chrome_trace = json.loads(trace_path.read_text())
        gpu = (pathlib.Path(output_dir) / "gpu.txt").read_text().strip()

    assert result["measurement"]["samples"]["matched"] == 3
    assert result["measurement"]["samples"]["dropped"] == 0
    assert result["measurement"]["latency_ns"]["min"] > 0
    assert result["correlation"]["confidence"] == "heuristic"
    assert result["clock"]["alignment"] == "cupti_normalized_to_host_monotonic"
    assert result["collection"]["host_events"] == 3
    assert result["collection"]["cuda_events"] >= 12
    assert export_result["format"] == "chrome"
    assert export_result["event_count"] == len(chrome_trace["traceEvents"])
    assert export_result["event_count"] >= result["collection"]["cuda_events"]
    assert [warning["code"] for warning in result["warnings"]] == [
        "HEURISTIC_CORRELATION",
        "CLOCK_ERROR_UNAVAILABLE",
    ]
    print(
        json.dumps(
            {
                "matched": result["measurement"]["samples"]["matched"],
                "host_events": result["collection"]["host_events"],
                "cuda_events": result["collection"]["cuda_events"],
                "live_events": len(live_events),
                "live_matched": live_result["measurement"]["samples"]["matched"],
                "spec_matched": spec_result["measurement"]["samples"]["matched"],
                "trace_events": export_result["event_count"],
                "min_ns": result["measurement"]["latency_ns"]["min"],
                "gpu": gpu,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
