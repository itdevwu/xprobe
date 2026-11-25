#!/usr/bin/env python3
import hashlib
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

        graph_validation = json.loads(
            (pathlib.Path(output_dir) / "graph-validate.json").read_text()
        )
        graph_result = json.loads(
            (pathlib.Path(output_dir) / "graph-measure.json").read_text()
        )
        graph_events = (
            pathlib.Path(output_dir) / "graph-events.jsonl"
        ).read_text().splitlines()
        stream_order_result = json.loads(
            (pathlib.Path(output_dir) / "stream-order-measure.json").read_text()
        )
        graph_artifact = pathlib.Path(output_dir) / "graph-events.jsonl"
        graph_manifest = json.loads(
            (pathlib.Path(output_dir) / "graph-events.jsonl.manifest.json").read_text()
        )
        graph_artifact_sha256 = hashlib.sha256(graph_artifact.read_bytes()).hexdigest()
        offline_stream_order = subprocess.run(
            [
                xprobe,
                "measure",
                "--input",
                graph_artifact,
                "--from",
                "cuda:kernel_end:name~xprobe_multisource_kernel.*",
                "--to",
                "cuda:kernel_start:name~xprobe_auxiliary_kernel.*",
                "--match",
                "stream-order",
                "--json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        trace_path = pathlib.Path(output_dir) / "trace.json"
        exported = subprocess.run(
            [
                xprobe,
                "export",
                "--input",
                pathlib.Path(output_dir) / "live.jsonl",
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

    assert live_result["measurement"]["samples"]["dropped"] == 0
    assert live_result["measurement"]["latency_ns"]["min"] > 0
    assert live_result["correlation"]["confidence"] == "heuristic"
    assert live_result["clock"]["alignment"] == "cupti_normalized_to_host_monotonic"
    assert live_result["collection"]["cuda_events"] >= 3
    assert graph_validation["schema_version"] == "3.0", graph_validation
    assert graph_validation["valid"] is True, graph_validation["issues"]
    assert [edge["name"] for edge in graph_validation["edges"]] == [
        "request_to_launch",
        "launch_to_kernel",
        "kernel_duration",
        "kernel_to_auxiliary",
    ]
    assert graph_validation["requirements"]["needs_ebpf"] is True
    assert graph_validation["requirements"]["needs_cupti"] is True
    assert graph_result["schema_version"] == "3.0", graph_result
    assert graph_result["status"] == "completed", graph_result
    edges = {edge["name"]: edge for edge in graph_result["edges"]}
    assert set(edges) == {
        "request_to_launch",
        "launch_to_kernel",
        "kernel_duration",
        "kernel_to_auxiliary",
    }
    for edge in edges.values():
        assert edge["measurement"]["samples"]["matched"] >= 3, edge
        assert edge["measurement"]["latency_ns"]["min"] > 0, edge
        assert edge["evidence"]["exemplars"], edge
        assert edge["evidence"]["artifact"] == graph_result["artifact"], edge
    assert edges["request_to_launch"]["correlation"]["confidence"] == "heuristic"
    assert edges["launch_to_kernel"]["correlation"]["confidence"] == "exact"
    assert edges["kernel_duration"]["correlation"]["confidence"] == "exact"
    assert edges["kernel_to_auxiliary"]["correlation"]["confidence"] == "high"
    # Adjacent kernels on one stream, not the 50 ms between iterations.
    assert edges["kernel_to_auxiliary"]["measurement"]["latency_ns"]["max"] < 10_000_000
    # The graph's artifact carries a manifest proving it holds every GPU
    # activity, so offline stream order keeps its live confidence.
    assert graph_manifest["schema_version"] == "1.0", graph_manifest
    assert graph_manifest["artifact"]["events"] == len(graph_events)
    assert graph_manifest["artifact"]["sha256"] == graph_artifact_sha256
    assert graph_manifest["all_gpu_activity"] is True, graph_manifest
    assert graph_manifest["peer_copies"] is True, graph_manifest
    assert graph_manifest["dropped_records"] == 0
    assert graph_manifest["window"]["start_ns"] < graph_manifest["window"]["end_ns"]
    assert offline_stream_order.returncode == 0, offline_stream_order.stdout
    offline = json.loads(offline_stream_order.stdout)
    assert offline["collection"]["coverage"]["source"] == "manifest", offline
    assert offline["correlation"]["confidence"] == "high", offline
    assert graph_result["collection"]["coverage"] == {
        "source": "live",
        "all_gpu_activity": True,
    }
    assert stream_order_result["ok"] is False, stream_order_result
    assert stream_order_result["error"]["code"] == "NO_MATCHED_SAMPLES", stream_order_result
    assert graph_result["artifact"]["events"] == len(graph_events)
    assert graph_result["collection"]["host_events"] >= 3
    assert export_result["format"] == "chrome"
    assert export_result["event_count"] == len(chrome_trace["traceEvents"])
    assert export_result["event_count"] == len(live_events)
    assert [warning["code"] for warning in live_result["warnings"]] == [
        "HEURISTIC_CORRELATION",
        "CLOCK_ERROR_UNAVAILABLE",
    ]
    print(
        json.dumps(
            {
                "matched": live_result["measurement"]["samples"]["matched"],
                "host_events": live_result["collection"]["host_events"],
                "cuda_events": live_result["collection"]["cuda_events"],
                "live_events": len(live_events),
                "live_matched": live_result["measurement"]["samples"]["matched"],
                "spec_matched": spec_result["measurement"]["samples"]["matched"],
                "graph_p50_ns": {
                    name: edge["measurement"]["latency_ns"]["p50"]
                    for name, edge in edges.items()
                },
                "trace_events": export_result["event_count"],
                "min_ns": live_result["measurement"]["latency_ns"]["min"],
                "gpu": gpu,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
