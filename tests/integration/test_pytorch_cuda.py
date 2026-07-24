#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time


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
    if not args.image or not args.pytorch_env:
        raise SystemExit("--image and --pytorch-env are required")
    workspace = pathlib.Path(__file__).resolve().parents[2]
    pytorch_env = pathlib.Path(args.pytorch_env).resolve()
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
            f"{pytorch_env}:/opt/xprobe-pytorch:ro",
            "--workdir",
            "/workspace",
            args.image,
            "/opt/xprobe-pytorch/bin/python",
            "/workspace/tests/integration/test_pytorch_cuda.py",
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
    sys.stdout.write(completed.stdout)


def run_inner(xprobe: pathlib.Path) -> None:
    workspace = pathlib.Path("/workspace")
    with tempfile.TemporaryDirectory(prefix="xprobe-pytorch-cuda-") as temp_dir:
        temp = pathlib.Path(temp_dir)
        agent = temp / "libxprobe-cupti.so"
        mode = temp / "mode"
        build_agent(workspace, agent)
        set_mode(mode, "mm")
        environment = os.environ.copy()
        environment["NVTX_INJECTION64_PATH"] = str(agent)
        workload = subprocess.Popen(
            [
                sys.executable,
                "-u",
                "-c",
                WORKLOAD,
                str(mode),
            ],
            env=environment,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert workload.stdout is not None
            ready = workload.stdout.readline()
            if not ready:
                raise AssertionError("PyTorch CUDA workload exited before readiness")
            metadata = json.loads(ready)
            pid = workload.pid

            mm = inventory(xprobe, agent, pid, mode, "mm", "kernel")
            conv = inventory(xprobe, agent, pid, mode, "conv", "kernel")
            compiled = inventory(xprobe, agent, pid, mode, "compiled", "kernel")
            transfers = inventory(xprobe, agent, pid, mode, "transfer", "memcpy")

            mm_group = min(mm["inventory"]["groups"], key=lambda group: len(group["name"]))
            exact_kernel = exact_measure(
                xprobe,
                agent,
                pid,
                mode,
                "mm",
                mm_group["start_selector_hint"],
                mm_group["end_selector_hint"],
            )
            synchronization = exact_measure(
                xprobe,
                agent,
                pid,
                mode,
                "mm",
                "cuda:runtime_api:cudaStreamSynchronize:entry",
                "cuda:runtime_api:cudaStreamSynchronize:exit",
            )
            nvtx = exact_measure(
                xprobe,
                agent,
                pid,
                mode,
                "nvtx",
                "cuda:nvtx_range_start:name~^xprobe_pytorch_step$",
                "cuda:nvtx_range_end:name~^xprobe_pytorch_step$",
            )
        finally:
            workload.terminate()
            workload.wait(timeout=10)

    assert_inventory(mm, "kernel")
    assert_inventory(conv, "kernel")
    assert_inventory(compiled, "kernel")
    assert_inventory(transfers, "memcpy")
    compiled_names = [
        group["name"].lower() for group in compiled["inventory"]["groups"]
    ]
    assert any("triton" in name for name in compiled_names), compiled_names
    transfer_hints = {
        group["start_selector_hint"] for group in transfers["inventory"]["groups"]
    }
    assert "cuda:memcpy_start:kind=HtoD" in transfer_hints
    assert "cuda:memcpy_start:kind=DtoH" in transfer_hints
    assert_exact(exact_kernel)
    assert_exact(synchronization)
    assert_exact(nvtx)
    assert nvtx["correlation"]["method"] == "exact_nvtx_range_id"
    assert all(
        pair["start"]["nvtx"]["range_kind"] == "thread"
        and pair["start"]["nvtx"]["range_id"] == pair["end"]["nvtx"]["range_id"]
        for pair in nvtx["evidence"]
    )

    print(
        json.dumps(
            {
                "compiled_kernel_groups": len(compiled["inventory"]["groups"]),
                "conv_kernel_groups": len(conv["inventory"]["groups"]),
                "cuda": metadata["cuda"],
                "device": metadata["device"],
                "eager_mm_kernel_groups": len(mm["inventory"]["groups"]),
                "exact_kernel_records": exact_kernel["collection"]["cupti"][
                    "retained_records"
                ],
                "measured": [
                    "kernel",
                    "memcpy_htod",
                    "memcpy_dtoh",
                    "stream_sync",
                    "nvtx_range",
                ],
                "nvtx_records": nvtx["collection"]["cupti"]["retained_records"],
                "ok": True,
                "pytorch": metadata["pytorch"],
                "stream_sync_records": synchronization["collection"]["cupti"][
                    "retained_records"
                ],
                "triton": metadata["triton"],
            },
            sort_keys=True,
        )
    )


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


def inventory(
    xprobe: pathlib.Path,
    agent: pathlib.Path,
    pid: int,
    mode_path: pathlib.Path,
    mode: str,
    activity: str,
) -> dict:
    set_mode(mode_path, mode)
    time.sleep(0.1)
    return run_xprobe(
        xprobe,
        [
            "measure",
            "--pid",
            str(pid),
            "--agent",
            str(agent),
            "--from",
            f"cuda:{activity}_start",
            "--to",
            f"cuda:{activity}_end",
            "--match",
            "exact",
            "--aggregate",
            "--duration-ms",
            "400",
            "--max-groups",
            "1024",
            "--timeout-ms",
            "30000",
        ],
    )


def exact_measure(
    xprobe: pathlib.Path,
    agent: pathlib.Path,
    pid: int,
    mode_path: pathlib.Path,
    mode: str,
    start_selector: str,
    end_selector: str,
) -> dict:
    set_mode(mode_path, mode)
    time.sleep(0.1)
    return run_xprobe(
        xprobe,
        [
            "measure",
            "--pid",
            str(pid),
            "--agent",
            str(agent),
            "--from",
            start_selector,
            "--to",
            end_selector,
            "--match",
            "exact",
            "--samples",
            "8",
            "--max-events",
            "4096",
            "--timeout-ms",
            "30000",
        ],
    )


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
            f"xprobe failed:\n{completed.stdout}\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def set_mode(path: pathlib.Path, mode: str) -> None:
    replacement = path.with_name(f"{path.name}.next")
    replacement.write_text(mode)
    replacement.replace(path)


def assert_inventory(result: dict, activity: str) -> None:
    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["collection"]["dropped_activities"] == 0
    assert result["collection"]["observed_activities"] > 0
    assert result["inventory"]["groups"]
    assert all(group["activity"] == activity for group in result["inventory"]["groups"])


def assert_exact(result: dict) -> None:
    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["measurement"]["samples"]["matched"] == 8
    assert result["collection"]["dropped_events"] == 0
    retained = result["collection"]["cupti"]["retained_records"]
    assert retained <= 1024, retained


WORKLOAD = r"""
import json
import pathlib
import sys
import time

import torch
import triton

mode_path = pathlib.Path(sys.argv[1])
torch.cuda.init()
device = torch.device("cuda")
stream = torch.cuda.current_stream()
a = torch.randn(256, 256, device=device)
b = torch.randn(256, 256, device=device)
image = torch.randn(8, 16, 64, 64, device=device)
conv = torch.nn.Conv2d(16, 32, 3, padding=1, device=device)
host_input = torch.randn(256, 256, pin_memory=True)
device_transfer = torch.empty_like(host_input, device=device)
host_output = torch.empty_like(host_input, pin_memory=True)

@torch.compile
def compiled_step(left, right):
    return torch.relu(torch.mm(left, right))

compiled_step(a, b)
stream.synchronize()
torch.cuda.nvtx.range_push("xprobe_init")
torch.cuda.nvtx.range_pop()
print(json.dumps({
    "cuda": torch.version.cuda,
    "device": torch.cuda.get_device_name(),
    "pytorch": torch.__version__,
    "triton": triton.__version__,
}), flush=True)

while True:
    mode = mode_path.read_text().strip()
    if mode == "mm":
        torch.mm(a, b)
    elif mode == "conv":
        conv(image)
    elif mode == "compiled":
        compiled_step(a, b)
    elif mode == "transfer":
        device_transfer.copy_(host_input, non_blocking=True)
        host_output.copy_(device_transfer, non_blocking=True)
    elif mode == "nvtx":
        torch.cuda.nvtx.range_push("xprobe_pytorch_step")
        torch.mm(a, b)
        stream.synchronize()
        torch.cuda.nvtx.range_pop()
    else:
        raise RuntimeError(f"unknown workload mode: {mode}")
    stream.synchronize()
    time.sleep(0.001)
"""


if __name__ == "__main__":
    main()
