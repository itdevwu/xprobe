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


if __name__ == "__main__":
    main()
