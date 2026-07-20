#!/usr/bin/env python3
import collections
import json
import pathlib
import struct
import subprocess
import sys
import tempfile


HEADER_V1 = struct.Struct("<8sIIIIQQQ")
RECORD = struct.Struct("<Q16I128s")
EXPECTED_KINDS = {1, 2, 3, 4}
EXPECTED_EVENT_TYPES = {
    "cuda_api_entry",
    "cuda_api_exit",
    "gpu_kernel_start",
    "gpu_kernel_end",
}


def decode_record(raw: bytes) -> dict[str, int | str]:
    fields = RECORD.unpack(raw)
    return {
        "timestamp_ns": fields[0],
        "kind": fields[1],
        "pid": fields[2],
        "tid": fields[3],
        "device_id": fields[4],
        "context_id": fields[5],
        "stream_id": fields[6],
        "correlation_id": fields[7],
        "callback_domain": fields[8],
        "callback_id": fields[9],
        "runtime_correlation_id": fields[16],
        "name": fields[17].split(b"\0", 1)[0].decode("utf-8"),
    }


def read_capture(path: pathlib.Path) -> tuple[dict[str, int], list[dict[str, int | str]]]:
    data = path.read_bytes()
    if len(data) < HEADER_V1.size:
        raise AssertionError("CUPTI capture is shorter than its header")
    fields = HEADER_V1.unpack_from(data)
    if fields[1] != 2:
        raise AssertionError(f"expected capture ABI 2, found {fields[1]}")
    header = {
        "abi_version": fields[1],
        "header_size": fields[2],
        "record_size": fields[3],
        "record_count": fields[5],
        "dropped_records": fields[6],
        "unknown_records": fields[7],
    }
    assert fields[0] == b"XPCUPTI\0"
    assert header["abi_version"] == 2
    assert header["header_size"] == HEADER_V1.size
    assert header["record_size"] == RECORD.size
    assert len(data) == header["header_size"] + header["record_count"] * RECORD.size
    records = [
        decode_record(data[offset : offset + RECORD.size])
        for offset in range(header["header_size"], len(data), RECORD.size)
    ]
    return header, records


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_cupti.py <container-image> <xprobe-binary>")

    workspace = pathlib.Path(__file__).resolve().parents[2]
    xprobe = workspace / sys.argv[2]
    with tempfile.TemporaryDirectory(prefix="xprobe-cupti-") as output_dir:
        capture = pathlib.Path(output_dir) / "events.bin"
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
                "/workspace/tests/integration/run-cupti-live.sh",
                "/output/events.bin",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            raise SystemExit(completed.returncode)
        header, records = read_capture(capture)
        decoded = subprocess.run(
            [
                xprobe,
                "dev",
                "cupti",
                "--input",
                capture,
                "--session-id",
                "xp_cupti_live",
                "--json",
                "--non-interactive",
                "--no-color",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if decoded.returncode != 0:
            sys.stdout.write(decoded.stdout)
            sys.stderr.write(decoded.stderr)
            raise SystemExit(decoded.returncode)
        assert decoded.stderr == ""
        events = [json.loads(line) for line in decoded.stdout.splitlines()]
        measured = subprocess.run(
            [
                xprobe,
                "measure",
                "--input",
                capture,
                "--from",
                "cuda:kernel_start:name~xprobe_test_kernel.*",
                "--to",
                "cuda:kernel_end:name~xprobe_test_kernel.*",
                "--match",
                "exact",
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
        assert measured.stderr == ""
        measurement = json.loads(measured.stdout)
        cross_domain = subprocess.run(
            [
                xprobe,
                "measure",
                "--input",
                capture,
                "--from",
                "cuda:runtime_api:cudaLaunchKernel:entry",
                "--to",
                "cuda:kernel_start:name~xprobe_test_kernel.*",
                "--match",
                "exact",
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
        if cross_domain.returncode != 0:
            sys.stdout.write(cross_domain.stdout)
            sys.stderr.write(cross_domain.stderr)
            raise SystemExit(cross_domain.returncode)
        assert cross_domain.stderr == ""
        cross_measurement = json.loads(cross_domain.stdout)

    counts = collections.Counter(record["kind"] for record in records)
    diagnostics = {"header": header, "counts": counts, "records": records}
    assert set(counts) == EXPECTED_KINDS, diagnostics
    assert all(counts[kind] == 3 for kind in EXPECTED_KINDS), diagnostics
    assert header["dropped_records"] == 0
    assert header["unknown_records"] == 0
    assert all(record["timestamp_ns"] > 0 for record in records)
    assert all(record["pid"] > 0 and record["tid"] > 0 for record in records)

    api_correlations = {
        record["correlation_id"] for record in records if record["kind"] in {1, 2}
    }
    kernel_correlations = {
        record["correlation_id"] for record in records if record["kind"] in {3, 4}
    }
    assert api_correlations == kernel_correlations
    assert all(
        record["runtime_correlation_id"] > 0
        for record in records
        if record["kind"] in {1, 2}
    )
    assert all(
        "cudaLaunchKernel" in record["name"]
        for record in records
        if record["kind"] in {1, 2}
    )
    assert all(
        "xprobe_test_kernel" in record["name"]
        for record in records
        if record["kind"] in {3, 4}
    )

    assert len(events) == 12
    assert {event["event_type"] for event in events} == EXPECTED_EVENT_TYPES
    assert all(event["session_id"] == "xp_cupti_live" for event in events)
    assert [event["sequence"] for event in events] == list(range(len(events)))
    assert [event["timestamp_ns"] for event in events] == sorted(
        event["timestamp_ns"] for event in events
    )
    event_api_correlations = {
        event["cuda"]["correlation_id"]
        for event in events
        if event["event_type"] in {"cuda_api_entry", "cuda_api_exit"}
    }
    event_kernel_correlations = {
        event["cuda"]["correlation_id"]
        for event in events
        if event["event_type"] in {"gpu_kernel_start", "gpu_kernel_end"}
    }
    assert event_api_correlations == event_kernel_correlations
    assert all(
        event["clock_domain"] == "host_monotonic"
        for event in events
        if event["event_type"] in {"cuda_api_entry", "cuda_api_exit"}
    )
    assert all(
        event["clock_domain"] == "cupti_normalized_to_host_monotonic"
        and event["timestamp_error_ns"] is None
        and event["timestamp_raw"] == event["timestamp_ns"]
        for event in events
        if event["event_type"] in {"gpu_kernel_start", "gpu_kernel_end"}
    )
    assert all(
        "xprobe_test_kernel" in event["cuda"]["kernel_name"]
        for event in events
        if event["event_type"] in {"gpu_kernel_start", "gpu_kernel_end"}
    )
    assert measurement["measurement"]["samples"]["matched"] == 3
    assert measurement["measurement"]["latency_ns"]["min"] > 0
    assert (
        measurement["measurement"]["latency_ns"]["max"]
        >= measurement["measurement"]["latency_ns"]["min"]
    )
    assert measurement["correlation"]["confidence"] == "exact"
    assert (
        measurement["clock"]["alignment"]
        == "cupti_normalized_to_host_monotonic"
    )
    assert measurement["clock"]["estimated_error_ns"] == 0
    assert cross_measurement["measurement"]["samples"]["matched"] == 3
    assert cross_measurement["measurement"]["latency_ns"]["min"] > 0
    assert cross_measurement["correlation"]["confidence"] == "exact"
    assert (
        cross_measurement["clock"]["alignment"]
        == "cupti_normalized_to_host_monotonic"
    )
    assert cross_measurement["clock"]["estimated_error_ns"] == 0
    assert [warning["code"] for warning in cross_measurement["warnings"]] == [
        "CLOCK_ERROR_UNAVAILABLE"
    ]

    print(
        json.dumps(
            {
                "records": len(records),
                "events": len(events),
                "matched": measurement["measurement"]["samples"]["matched"],
                "cross_domain_matched": cross_measurement["measurement"]["samples"][
                    "matched"
                ],
                "api_to_kernel_min_ns": cross_measurement["measurement"]["latency_ns"][
                    "min"
                ],
                "kinds": counts,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
