#!/usr/bin/env python3
import json
import pathlib
import statistics
import struct
import subprocess
import sys
import tempfile


HEADER = struct.Struct("<8s6I7Q")
RECORD = struct.Struct("<Q16I128s")
PRECISION_KERNEL = "xprobe_precision_kernel"
TARGET_RATE_KERNEL = "xprobe_target_rate_kernel"


def read_capture(path: pathlib.Path) -> tuple[dict[str, int], list[dict[str, int | str]]]:
    data = path.read_bytes()
    if len(data) < HEADER.size:
        raise AssertionError("CUPTI capture is shorter than its header")
    fields = HEADER.unpack_from(data)
    header = {
        "abi_version": fields[1],
        "header_size": fields[2],
        "record_size": fields[3],
        "feature_flags": fields[4],
        "capture_state": fields[5],
        "stop_reason": fields[6],
        "record_count": fields[7],
        "record_capacity": fields[8],
        "observed_records": fields[9],
        "agent_dropped_records": fields[10],
        "cupti_dropped_records": fields[11],
        "unknown_records": fields[12],
        "record_offset": fields[13],
    }
    assert fields[0] == b"XPCUPTI\0", header
    assert header["abi_version"] == 4, header
    assert header["header_size"] == HEADER.size, header
    assert header["record_size"] == RECORD.size, header
    assert len(data) == HEADER.size + header["record_count"] * RECORD.size, header

    records = []
    for offset in range(HEADER.size, len(data), RECORD.size):
        fields = RECORD.unpack_from(data, offset)
        records.append(
            {
                "timestamp_ns": fields[0],
                "kind": fields[1],
                "correlation_id": fields[7],
                "name": fields[17].split(b"\0", 1)[0].decode("utf-8"),
            }
        )
    return header, records


def precision_duration(records: list[dict[str, int | str]]) -> int:
    starts = [
        record
        for record in records
        if record["kind"] == 3 and PRECISION_KERNEL in str(record["name"])
    ]
    ends = [
        record
        for record in records
        if record["kind"] == 4 and PRECISION_KERNEL in str(record["name"])
    ]
    assert len(starts) == 1 and len(ends) == 1, {"starts": starts, "ends": ends}
    assert starts[0]["correlation_id"] == ends[0]["correlation_id"]
    duration = int(ends[0]["timestamp_ns"]) - int(starts[0]["timestamp_ns"])
    assert duration > 0
    return duration


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: run.py <container-image>")

    workspace = pathlib.Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="xprobe-cuda-benchmark-") as temporary:
        output_dir = pathlib.Path(temporary)
        completed = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--gpus",
                "all",
                "--volume",
                f"{workspace}:/workspace:ro",
                "--volume",
                f"{output_dir}:/output",
                "--workdir",
                "/workspace",
                sys.argv[1],
                "/workspace/benchmarks/cuda-callback/run-container.sh",
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

        baseline = json.loads((output_dir / "baseline.json").read_text())
        instrumented = json.loads((output_dir / "instrumented.json").read_text())
        header, records = read_capture(output_dir / "capture.bin")
        gpu = (output_dir / "gpu.txt").read_text().strip()

    assert baseline["gpu"] == instrumented["gpu"]
    assert baseline["stress_launches_per_round"] == instrumented["stress_launches_per_round"]
    assert baseline["target_rate_launches_per_round"] == instrumented["target_rate_launches_per_round"]
    assert baseline["rounds"] == instrumented["rounds"]
    for field in ("stress_round_host_ns", "target_rate_round_host_ns"):
        assert len(baseline[field]) == baseline["rounds"]
        assert len(instrumented[field]) == instrumented["rounds"]
        assert all(value > 0 for value in baseline[field])
        assert all(value > 0 for value in instrumented[field])
    assert header["capture_state"] == 3, header
    assert header["agent_dropped_records"] == 0, header
    assert header["cupti_dropped_records"] == 0, header
    assert header["unknown_records"] == 0, header
    assert header["record_offset"] == 0, header

    cupti_ns = precision_duration(records)
    reference_ns = instrumented["precision_cuda_event_ns"]
    absolute_error_ns = abs(cupti_ns - reference_ns)
    relative_error = absolute_error_ns / reference_ns
    tolerance_ns = max(250_000, int(reference_ns * 0.10))
    assert absolute_error_ns <= tolerance_ns, {
        "cupti_ns": cupti_ns,
        "reference_ns": reference_ns,
        "absolute_error_ns": absolute_error_ns,
        "tolerance_ns": tolerance_ns,
    }

    stress_baseline_ns = int(statistics.median(baseline["stress_round_host_ns"]))
    stress_instrumented_ns = int(statistics.median(instrumented["stress_round_host_ns"]))
    stress_ratio = stress_instrumented_ns / stress_baseline_ns
    assert stress_ratio < 25.0, {
        "baseline_median_ns": stress_baseline_ns,
        "instrumented_median_ns": stress_instrumented_ns,
        "overhead_ratio": stress_ratio,
    }

    target_baseline_ns = int(statistics.median(baseline["target_rate_round_host_ns"]))
    target_instrumented_ns = int(
        statistics.median(instrumented["target_rate_round_host_ns"])
    )
    target_ratio = target_instrumented_ns / target_baseline_ns
    target_correlations = {
        int(record["correlation_id"])
        for record in records
        if TARGET_RATE_KERNEL in str(record["name"])
    }
    target_record_count = sum(
        int(record["correlation_id"]) in target_correlations for record in records
    )
    target_event_rate = target_record_count / (
        sum(instrumented["target_rate_round_host_ns"]) / 1_000_000_000
    )
    assert target_event_rate < 10_000, target_event_rate

    print(
        json.dumps(
            {
                "schema_version": "2.0",
                "ok": True,
                "gpu": gpu,
                "workload": {
                    "stress_launches_per_round": baseline["stress_launches_per_round"],
                    "target_rate_launches_per_round": baseline[
                        "target_rate_launches_per_round"
                    ],
                    "rounds": baseline["rounds"],
                },
                "precision": {
                    "reference": "cuda_event",
                    "reference_ns": reference_ns,
                    "cupti_activity_ns": cupti_ns,
                    "absolute_error_ns": absolute_error_ns,
                    "relative_error": relative_error,
                    "tolerance_ns": tolerance_ns,
                },
                "overhead": {
                    "metric": "median_host_wall_time",
                    "empty_launch_stress": {
                        "baseline_ns": stress_baseline_ns,
                        "instrumented_ns": stress_instrumented_ns,
                        "ratio": stress_ratio,
                    },
                    "below_10k_events_per_second": {
                        "baseline_ns": target_baseline_ns,
                        "instrumented_ns": target_instrumented_ns,
                        "ratio": target_ratio,
                        "observed_event_rate": target_event_rate,
                        "project_target_ratio": 1.02,
                        "project_target_met": target_ratio <= 1.02,
                    },
                },
                "collection": header,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
