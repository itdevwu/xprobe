#!/usr/bin/env python3
import collections
import json
import pathlib
import struct
import subprocess
import sys
import tempfile


HEADER = struct.Struct("<8sIIIIQQQ")
RECORD = struct.Struct("<Q16I128s")
EXPECTED_KINDS = {1, 2, 3, 4}


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
    if len(data) < HEADER.size:
        raise AssertionError("CUPTI capture is shorter than its header")
    fields = HEADER.unpack_from(data)
    header = {
        "abi_version": fields[1],
        "header_size": fields[2],
        "record_size": fields[3],
        "record_count": fields[5],
        "dropped_records": fields[6],
        "unknown_records": fields[7],
    }
    assert fields[0] == b"XPCUPTI\0"
    assert header["abi_version"] == 1
    assert header["header_size"] == HEADER.size
    assert header["record_size"] == RECORD.size
    assert len(data) == HEADER.size + header["record_count"] * RECORD.size
    records = [
        decode_record(data[offset : offset + RECORD.size])
        for offset in range(HEADER.size, len(data), RECORD.size)
    ]
    return header, records


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_cupti.py <container-image>")

    workspace = pathlib.Path(__file__).resolve().parents[2]
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

    print(json.dumps({"records": len(records), "kinds": counts}, sort_keys=True))


if __name__ == "__main__":
    main()
