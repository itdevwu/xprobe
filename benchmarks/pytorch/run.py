#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import statistics
import subprocess
import sys
import tempfile
import time


ROUNDS = 3
TIMED_SECONDS = 1.5
CAPTURE_SECONDS = 1.5


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image")
    parser.add_argument("--pytorch-env")
    parser.add_argument("--inner", action="store_true")
    parser.add_argument("--xprobe", default="/workspace/target/debug/xprobe")
    args = parser.parse_args()
    if args.inner:
        run_inner(pathlib.Path(args.xprobe))
    else:
        run_container(args)


def run_container(args: argparse.Namespace) -> None:
    if not args.image:
        raise SystemExit("--image is required")
    workspace = pathlib.Path(__file__).resolve().parents[2]
    python = "python3"
    environment_arguments = []
    if args.pytorch_env:
        pytorch_env = pathlib.Path(args.pytorch_env).resolve()
        python = "/opt/xprobe-pytorch/bin/python"
        environment_arguments = [
            "--volume",
            f"{pytorch_env}:/opt/xprobe-pytorch:ro",
        ]
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
            *environment_arguments,
            "--workdir",
            "/workspace",
            args.image,
            python,
            "/workspace/benchmarks/pytorch/run.py",
            "--inner",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise SystemExit(completed.returncode)
    lines = [line for line in completed.stdout.splitlines() if line.startswith("{")]
    if not lines:
        raise AssertionError(f"PyTorch benchmark emitted no JSON report:\n{completed.stdout}")
    print(json.dumps(json.loads(lines[-1]), sort_keys=True))


def run_inner(xprobe: pathlib.Path) -> None:
    workspace = pathlib.Path("/workspace")
    with tempfile.TemporaryDirectory(prefix="xprobe-pytorch-benchmark-") as directory:
        root = pathlib.Path(directory)
        agent = root / "libxprobe-cupti.so"
        metrics = root / "metrics.json"
        build_agent(workspace, agent)

        baseline = [run_timed(workspace, profile=False) for _ in range(ROUNDS)]
        profiler = [run_timed(workspace, profile=True) for _ in range(ROUNDS)]

        workload = start_workload(workspace, metrics, agent)
        try:
            assert workload.stdout is not None
            ready = workload.stdout.readline()
            if not ready:
                raise AssertionError("PyTorch benchmark workload exited before readiness")
            workload_metadata = json.loads(ready)
            wait_for_metrics(metrics)
            idle_rates = [sample_rate(metrics, TIMED_SECONDS) for _ in range(ROUNDS)]
            validation = validate(xprobe, workload.pid)
            captures = [
                capture(xprobe, workload.pid, metrics, agent) for _ in range(ROUNDS)
            ]
        finally:
            workload.terminate()
            workload.wait(timeout=10)

    baseline_rate = statistics.median(
        result["iterations_per_second"] for result in baseline
    )
    idle_rate = statistics.median(idle_rates)
    captured_rate = statistics.median(rate for rate, _ in captures)
    profiler_rate = statistics.median(
        result["iterations_per_second"] for result in profiler
    )
    xprobe_ratio = baseline_rate / captured_rate
    idle_ratio = baseline_rate / idle_rate
    profiler_ratio = baseline_rate / profiler_rate
    assert xprobe_ratio < 25.0, xprobe_ratio
    assert profiler_ratio < 25.0, profiler_ratio

    capture_results = [result for _, result in captures]
    for result in capture_results:
        assert result["ok"] is True, result
        assert result["status"] == "completed", result
        assert result["collection"]["completeness"] == "complete", result
        assert result["collection"]["dropped_events"] == 0, result
        assert result["measurement"]["samples"]["matched"] > 0, result
        assert result["correlation"]["confidence"] == "exact", result

    collection = capture_results[-1]["collection"]
    print(
        json.dumps(
            {
                "schema_version": "2.0",
                "ok": True,
                "environment": workload_metadata,
                "workload": {
                    "operation": "torch.mm_256x256_and_stream_synchronize",
                    "rounds": ROUNDS,
                    "seconds_per_rate_round": TIMED_SECONDS,
                },
                "throughput": {
                    "baseline_iterations_per_second": baseline_rate,
                    "idle_agent_iterations_per_second": idle_rate,
                    "xprobe_iterations_per_second": captured_rate,
                    "pytorch_profiler_iterations_per_second": profiler_rate,
                },
                "overhead": {
                    "metric": "baseline_throughput_over_observed_throughput",
                    "idle_agent_ratio": idle_ratio,
                    "xprobe_ratio": xprobe_ratio,
                    "pytorch_profiler_ratio": profiler_ratio,
                    "project_target_ratio": 1.05,
                    "project_target_met": xprobe_ratio <= 1.05,
                    "profiler_subscriber_isolation": "separate_process",
                },
                "validation": {
                    "agent_activation": validation["requirements"][
                        "agent_activation"
                    ],
                    "policy": validation["policy_recommendation"]["policy"],
                    "valid": validation["valid"],
                },
                "collection": {
                    "completeness": collection["completeness"],
                    "dropped_events": collection["dropped_events"],
                    "cupti": collection["cupti"],
                    "matched_samples": capture_results[-1]["measurement"]["samples"][
                        "matched"
                    ],
                    "unmatched_start_samples": capture_results[-1]["measurement"][
                        "samples"
                    ]["unmatched_start"],
                    "unmatched_end_samples": capture_results[-1]["measurement"][
                        "samples"
                    ]["unmatched_end"],
                    "ambiguous_samples": capture_results[-1]["measurement"][
                        "samples"
                    ]["ambiguous"],
                },
            },
            sort_keys=True,
        )
    )


def run_timed(workspace: pathlib.Path, profile: bool) -> dict:
    command = [
        sys.executable,
        str(workspace / "benchmarks/pytorch/workload.py"),
        "--timed",
        "--seconds",
        str(TIMED_SECONDS),
    ]
    if profile:
        command.append("--profile")
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)


def start_workload(
    workspace: pathlib.Path,
    metrics: pathlib.Path,
    agent: pathlib.Path,
) -> subprocess.Popen[str]:
    environment = os.environ.copy()
    environment["NVTX_INJECTION64_PATH"] = str(agent)
    return subprocess.Popen(
        [
            sys.executable,
            "-u",
            str(workspace / "benchmarks/pytorch/workload.py"),
            "--serve",
            "--metrics",
            str(metrics),
        ],
        env=environment,
        stdout=subprocess.PIPE,
        text=True,
    )


def wait_for_metrics(path: pathlib.Path) -> None:
    deadline = time.monotonic() + 10
    while not path.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError("timed out waiting for PyTorch benchmark metrics")
        time.sleep(0.01)


def read_metrics(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())


def sample_rate(path: pathlib.Path, seconds: float) -> float:
    before = read_metrics(path)
    time.sleep(seconds)
    after = read_metrics(path)
    count = after["count"] - before["count"]
    elapsed_ns = after["timestamp_ns"] - before["timestamp_ns"]
    assert count > 0 and elapsed_ns > 0, {"before": before, "after": after}
    return count * 1_000_000_000 / elapsed_ns


def validate(xprobe: pathlib.Path, pid: int) -> dict:
    result = run_xprobe(
        xprobe,
        [
            "validate",
            "--pid",
            str(pid),
            "--from",
            "cuda:runtime_api:cudaStreamSynchronize:entry",
            "--to",
            "cuda:runtime_api:cudaStreamSynchronize:exit",
            "--match",
            "exact",
        ],
    )
    assert result["valid"] is True, result
    assert result["target"]["pid"] == pid, result
    assert result["requirements"]["agent_activation"] == "already_loaded", result
    assert result["policy_recommendation"]["policy"] == "exact", result
    return result


def capture(
    xprobe: pathlib.Path,
    pid: int,
    metrics: pathlib.Path,
    agent: pathlib.Path,
) -> tuple[float, dict]:
    process = subprocess.Popen(
        [
            str(xprobe),
            "measure",
            "--pid",
            str(pid),
            "--agent",
            str(agent),
            "--from",
            "cuda:runtime_api:cudaStreamSynchronize:entry",
            "--to",
            "cuda:runtime_api:cudaStreamSynchronize:exit",
            "--match",
            "exact",
            "--duration-ms",
            str(int(CAPTURE_SECONDS * 1000)),
            "--max-events",
            "8192",
            "--timeout-ms",
            "10000",
            "--json",
            "--non-interactive",
            "--no-color",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.2)
    rate = sample_rate(metrics, 1.0)
    stdout, stderr = process.communicate(timeout=15)
    if process.returncode != 0:
        raise AssertionError(
            f"xprobe benchmark capture failed:\n{stdout}\n{stderr}"
        )
    return rate, json.loads(stdout)


def run_xprobe(xprobe: pathlib.Path, arguments: list[str]) -> dict:
    completed = subprocess.run(
        [
            str(xprobe),
            *arguments,
            "--json",
            "--non-interactive",
            "--no-color",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"xprobe benchmark command failed:\n{completed.stdout}\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def build_agent(workspace: pathlib.Path, output: pathlib.Path) -> None:
    subprocess.run(
        [
            "gcc",
            "-std=c11",
            "-D_GNU_SOURCE",
            "-DXPROBE_HAS_CUPTI=1",
            "-fPIC",
            "-shared",
            "-pthread",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            f"-I{workspace / 'cupti/include'}",
            "-isystem",
            "/usr/local/cuda/include",
            str(workspace / "cupti/src/cupti_agent.c"),
            "-L/usr/local/cuda/lib64",
            "-Wl,-rpath,/usr/local/cuda/lib64",
            "-lcupti",
            "-o",
            str(output),
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
