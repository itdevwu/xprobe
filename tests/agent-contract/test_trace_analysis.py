#!/usr/bin/env python3
import json
import pathlib
import subprocess
import tempfile


def event(
    sequence: int,
    event_type: str,
    timestamp_ns: int,
    stream_id: int,
    correlation_id: int,
    *,
    kernel_name: str | None = None,
    grid: tuple[int, int, int] | None = None,
    block: tuple[int, int, int] | None = None,
    memcpy_kind: str | None = None,
    bytes_count: int | None = None,
) -> dict:
    def dim(value: tuple[int, int, int] | None) -> dict | None:
        if value is None:
            return None
        return {"x": value[0], "y": value[1], "z": value[2]}

    return {
        "schema_version": "2.0",
        "event_id": f"event-{sequence}",
        "sequence": sequence,
        "event_type": event_type,
        "pid": 1234,
        "timestamp_ns": timestamp_ns,
        "clock_domain": "cupti",
        "cuda": {
            "device_id": 0,
            "context_id": 1,
            "stream_id": stream_id,
            "correlation_id": correlation_id,
            "kernel_name": kernel_name,
            "grid": dim(grid),
            "block": dim(block),
            "memcpy_kind": memcpy_kind,
            "bytes": bytes_count,
        },
    }


def pair(sequence: int, kind: str, start: int, end: int, **kwargs: object) -> list[dict]:
    return [
        event(sequence, f"gpu_{kind}_start", start, **kwargs),
        event(sequence + 1, f"gpu_{kind}_end", end, **kwargs),
    ]


def main() -> None:
    workspace = pathlib.Path(__file__).resolve().parents[2]
    script = workspace / "skills/xprobe-measure-latency/scripts/analyze_trace.py"
    events = [
        *pair(
            1,
            "kernel",
            0,
            100,
            stream_id=7,
            correlation_id=1,
            kernel_name="vector_add",
            grid=(1, 1, 1),
            block=(32, 1, 1),
        ),
        *pair(
            3,
            "kernel",
            120,
            220,
            stream_id=7,
            correlation_id=2,
            kernel_name="vector_add",
            grid=(2, 1, 1),
            block=(64, 1, 1),
        ),
        *pair(
            5,
            "kernel",
            50,
            150,
            stream_id=9,
            correlation_id=3,
            kernel_name="reduce",
            grid=(1, 1, 1),
            block=(128, 1, 1),
        ),
        *pair(
            7,
            "memcpy",
            220,
            270,
            stream_id=7,
            correlation_id=4,
            memcpy_kind="HtoD",
            bytes_count=4096,
        ),
    ]
    with tempfile.TemporaryDirectory(prefix="xprobe-trace-analysis-") as directory:
        trace = pathlib.Path(directory) / "events.jsonl"
        trace.write_text("".join(json.dumps(item) + "\n" for item in events))
        completed = subprocess.run(
            [script, trace], check=True, capture_output=True, text=True
        )
        unpaired_trace = pathlib.Path(directory) / "unpaired.jsonl"
        unpaired_trace.write_text(json.dumps(events[0]) + "\n")
        unpaired = json.loads(
            subprocess.run(
                [script, unpaired_trace], check=True, capture_output=True, text=True
            ).stdout
        )
        invalid_trace = pathlib.Path(directory) / "invalid.jsonl"
        invalid = dict(events[0], schema_version="1.0")
        invalid_trace.write_text(json.dumps(invalid) + "\n")
        rejected = subprocess.run(
            [script, invalid_trace], check=False, capture_output=True, text=True
        )
    report = json.loads(completed.stdout)
    assert report["events"]["total"] == 8
    assert report["events"]["paired_activities"] == 4
    assert report["gpu"]["busy_union_ns"] == 270
    assert report["gpu"]["summed_activity_ns"] == 350
    assert report["gpu"]["overlap_factor"] == 1.296296
    assert report["kernels"]["busy_union_ns"] == 220
    assert report["kernels"]["overlap_factor"] == 1.363636
    vector_add = report["kernels"]["by_name"][0]
    assert vector_add["name"] == "vector_add"
    assert vector_add["duration"]["count"] == 2
    assert vector_add["duration"]["total_ns"] == 200
    assert len(vector_add["launch_variants"]) == 2
    assert vector_add["selector_hint"]["scope"] == "exact_name"
    assert report["memcpy"]["total_bytes"] == 4096
    assert report["memset"]["duration"]["count"] == 0
    stream = next(item for item in report["streams"] if item["stream_id"] == 7)
    assert stream["adjacent_kernel_gaps"]["count"] == 1
    assert stream["adjacent_kernel_gaps"]["p50_ns"] == 20
    assert report["warnings"] == []
    assert unpaired["events"]["unmatched_activity_starts"] == 1
    assert unpaired["warnings"][0]["code"] == "UNPAIRED_ACTIVITY_BOUNDARIES"
    assert rejected.returncode != 0
    assert "expected schema_version 2.0" in rejected.stderr
    check_gaps_outliers_and_slices(script)


def api_event(sequence: int, timestamp_ns: int, name: str, correlation_id: int) -> dict:
    return {
        "schema_version": "2.0",
        "event_id": f"event-{sequence}",
        "sequence": sequence,
        "event_type": "cuda_api_exit",
        "pid": 1234,
        "tid": 55,
        "timestamp_ns": timestamp_ns,
        "clock_domain": "cupti",
        "cuda": {"stream_id": None, "correlation_id": correlation_id},
        "attributes": {"cuda_api_name": name},
    }


def check_gaps_outliers_and_slices(script: pathlib.Path) -> None:
    # Stream 7: k(0-100) gap 400 k(500-600) gap 50 k(650-700); a 2 KB HtoD copy
    # on stream 9 at 200-300 partly fills the first stream gap on the device.
    events = [
        *pair(1, "kernel", 0, 100, stream_id=7, correlation_id=1, kernel_name="a"),
        *pair(3, "kernel", 500, 600, stream_id=7, correlation_id=2, kernel_name="b"),
        *pair(5, "kernel", 650, 700, stream_id=7, correlation_id=3, kernel_name="c"),
        *pair(7, "memcpy", 200, 300, stream_id=9, correlation_id=4,
              memcpy_kind="HtoD", bytes_count=2000),
        api_event(9, 450, "cudaStreamSynchronize", 5),
    ]
    measurement = {
        "schema_version": "3.0",
        "ok": True,
        "evidence": {
            "mode": "full",
            "exemplars": [],
            "pairs": [
                {"start": events[0], "end": events[1], "latency_ns": 100},
                {"start": events[2], "end": events[3], "latency_ns": 100},
                {"start": events[4], "end": events[5], "latency_ns": 50},
            ],
            "artifact": None,
        },
    }
    with tempfile.TemporaryDirectory(prefix="xprobe-trace-slices-") as directory:
        trace = pathlib.Path(directory) / "events.jsonl"
        trace.write_text("".join(json.dumps(item) + "\n" for item in events))
        result = pathlib.Path(directory) / "measure.json"
        result.write_text(json.dumps(measurement))

        def run(*arguments: str) -> dict:
            return json.loads(
                subprocess.run(
                    [script, trace, *arguments], check=True, capture_output=True, text=True
                ).stdout
            )

        report = run("--top-gaps", "2")
        by_gap = run("--slice-gap", "1", "--window-ms", "0.00005")
        by_outlier = run("--measurement", str(result), "--slice-outlier", "2")
        by_time = run("--around", "440:460", "--max-slice-events", "1")
        missing = subprocess.run(
            [script, trace, "--slice-outlier", "1"], check=False, capture_output=True, text=True
        )

    copy = report["memcpy"]["by_kind"][0]
    assert copy["bandwidth_gbps"] == 20.0, copy
    assert copy["avg_bytes"] == 2000.0, copy
    idle = report["gpu"]["top_idle_gaps"]
    assert [(gap["start_ns"], gap["end_ns"]) for gap in idle] == [(300, 500), (100, 200)], idle
    stream = next(item for item in report["streams"] if item["stream_id"] == 7)
    assert [gap["gap_ns"] for gap in stream["top_gaps"]] == [400, 50]
    assert stream["top_gaps"][0]["after"] == "a" and stream["top_gaps"][0]["before"] == "b"
    assert report["outliers"] is None and report["slice"] is None

    sliced = by_gap["slice"]
    assert sliced["around"] == {"kind": "gap", "start_ns": 300, "end_ns": 500}
    assert (sliced["start_ns"], sliced["end_ns"]) == (250, 550)
    assert [row["name"] for row in sliced["events"]] == ["HtoD", "cudaStreamSynchronize", "b"]
    assert sliced["events"][1]["tid"] == 55

    outliers = by_outlier["outliers"]
    assert outliers["source"] == ["full_evidence"]
    assert [item["latency_ns"] for item in outliers["slowest"]] == [100, 100, 50]
    assert by_outlier["slice"]["around"]["start_ns"] == 500

    assert by_time["slice"]["total_events"] == 1 and not by_time["slice"]["truncated"]
    assert by_time["slice"]["events"][0]["name"] == "cudaStreamSynchronize"
    assert missing.returncode != 0 and "requires --measurement" in missing.stderr


if __name__ == "__main__":
    main()
