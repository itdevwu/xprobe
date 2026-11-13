#!/usr/bin/env python3
"""Live two-command flow: triage a PyTorch CUDA workload, then run its next spec."""

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile

EXPECTED_SOURCES = {
    "thread_time",
    "cgroup",
    "cpu_sample",
    "syscall_aggregate",
    "gpu_health",
    "gpu_activity",
}


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
        python = "/opt/xprobe-pytorch/bin/python"
        environment_arguments = [
            "--volume",
            f"{pathlib.Path(args.pytorch_env).resolve()}:/opt/xprobe-pytorch:ro",
        ]
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
            "/workspace/tests/integration/test_triage.py",
            "--inner",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    sys.stdout.write(completed.stdout)
    if completed.returncode != 0:
        sys.stderr.write(completed.stderr)
        raise SystemExit(completed.returncode)


def run_inner(xprobe: pathlib.Path) -> None:
    workspace = pathlib.Path("/workspace")
    with tempfile.TemporaryDirectory(prefix="xprobe-triage-") as temp_dir:
        temp = pathlib.Path(temp_dir)
        agent = temp / "libxprobe-cupti.so"
        build_agent(workspace, agent)
        environment = os.environ.copy()
        environment["NVTX_INJECTION64_PATH"] = str(agent)
        workload = subprocess.Popen(
            [sys.executable, "-u", "-c", WORKLOAD],
            env=environment,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert workload.stdout is not None
            if not workload.stdout.readline():
                raise AssertionError("PyTorch workload exited before readiness")
            triage = run_xprobe(
                xprobe,
                [
                    "measure",
                    "--pid",
                    str(workload.pid),
                    "--agent",
                    str(agent),
                    "--triage",
                    "--duration-ms",
                    "2000",
                ],
            )
            next_spec = first_measure_spec(triage)
            spec_path = temp / "next.json"
            spec_path.write_text(json.dumps(next_spec))
            try:
                measured = run_xprobe(
                    xprobe,
                    ["measure", "--spec", str(spec_path), "--agent", str(agent)],
                )
            except AssertionError as error:
                raise AssertionError(
                    f"next spec failed\nfindings: {json.dumps(triage['findings'], indent=1)}\n{error}"
                ) from None
        finally:
            workload.terminate()
            workload.wait(timeout=10)

    assert_triage(triage, workload.pid)
    assert measured["schema_version"] == "3.0", measured
    assert measured["ok"] is True, measured
    assert measured["measurement"]["samples"]["matched"] > 0, measured
    assert measured["evidence"]["artifact"] is not None, measured
    print(
        json.dumps(
            {
                "findings": [finding["code"] for finding in triage["findings"]],
                "next_selector": next_spec["start_selector"],
                "next_matched": measured["measurement"]["samples"]["matched"],
                "next_max_events": next_spec["max_events"],
                "next_quality": measured["quality"]["verdict"],
                "ok": True,
                "triage_bytes": len(json.dumps(triage)),
                "window_ms": triage["window_ms"],
            },
            sort_keys=True,
        )
    )


def assert_triage(triage: dict, pid: int) -> None:
    assert triage["schema_version"] == "3.0", triage
    assert triage["ok"] is True, triage
    assert triage["target"]["pid"] == pid, triage
    statuses = {source["source"]: source["status"] for source in triage["sources"]}
    assert set(statuses) == EXPECTED_SOURCES, statuses
    collected = {name for name, status in statuses.items() if status == "collected"}
    assert collected >= EXPECTED_SOURCES - {"cgroup"}, statuses
    for source in triage["sources"]:
        if source["source"] in {"cpu_sample", "syscall_aggregate", "gpu_activity"}:
            assert pathlib.Path(source["artifact"]).name.endswith(".json"), source
    assert triage["threads"]["threads_observed"] > 0, triage["threads"]
    assert triage["gpu_activity"], "kernel activity must be grouped"
    assert triage["gpu_devices"], "NVML health must be sampled"
    assert triage["findings"], "a busy CUDA workload must produce findings"
    ranks = [finding["rank"] for finding in triage["findings"]]
    assert ranks == list(range(1, len(ranks) + 1)), ranks
    assert triage["not_covered"], triage


def first_measure_spec(triage: dict) -> dict:
    for finding in triage["findings"]:
        step = finding["next"]
        if step and step["kind"] == "measure" and step["spec"]:
            return step["spec"]
    raise AssertionError(f"no runnable next step: {json.dumps(triage['findings'])}")


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


def run_xprobe(xprobe: pathlib.Path, arguments: list[str]) -> dict:
    completed = subprocess.run(
        [str(xprobe), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(f"xprobe failed:\n{completed.stdout}\n{completed.stderr}")
    return json.loads(completed.stdout)


WORKLOAD = r"""
import json
import time

import torch

device = torch.device("cuda")
a = torch.randn(1024, 1024, device=device)
b = torch.randn(1024, 1024, device=device)
host = torch.randn(256, 256)
torch.cuda.synchronize()
print(json.dumps({"pytorch": torch.__version__}), flush=True)
while True:
    for _ in range(8):
        torch.mm(a, b)
    torch.cuda.synchronize()
    host @ host
    time.sleep(0.001)
"""


if __name__ == "__main__":
    main()
