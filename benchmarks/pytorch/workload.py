#!/usr/bin/env python3
import argparse
import contextlib
import json
import pathlib
import time


def initialize():
    import torch

    torch.cuda.init()
    device = torch.device("cuda")
    stream = torch.cuda.current_stream()
    left = torch.randn(256, 256, device=device)
    right = torch.randn(256, 256, device=device)
    for _ in range(100):
        torch.mm(left, right)
    stream.synchronize()
    torch.cuda.nvtx.range_push("xprobe_pytorch_benchmark_init")
    torch.cuda.nvtx.range_pop()
    return torch, stream, left, right


def iteration(torch, stream, left, right) -> None:
    torch.mm(left, right)
    stream.synchronize()
    time.sleep(0.001)


def metadata(torch) -> dict:
    return {
        "cuda": torch.version.cuda,
        "device": torch.cuda.get_device_name(),
        "pytorch": torch.__version__,
    }


def run_timed(seconds: float, profile: bool) -> None:
    torch, stream, left, right = initialize()
    profiler = (
        torch.profiler.profile(
            activities=[
                torch.profiler.ProfilerActivity.CPU,
                torch.profiler.ProfilerActivity.CUDA,
            ]
        )
        if profile
        else contextlib.nullcontext()
    )
    count = 0
    with profiler:
        started_ns = time.monotonic_ns()
        deadline_ns = started_ns + int(seconds * 1_000_000_000)
        while time.monotonic_ns() < deadline_ns:
            iteration(torch, stream, left, right)
            count += 1
            if profile:
                profiler.step()
        finished_ns = time.monotonic_ns()
    elapsed_ns = finished_ns - started_ns
    print(
        json.dumps(
            {
                **metadata(torch),
                "elapsed_ns": elapsed_ns,
                "iterations": count,
                "iterations_per_second": count * 1_000_000_000 / elapsed_ns,
                "profile": profile,
            },
            sort_keys=True,
        ),
        flush=True,
    )


def write_metrics(path: pathlib.Path, count: int) -> None:
    replacement = path.with_name(f"{path.name}.next")
    replacement.write_text(
        json.dumps(
            {
                "count": count,
                "timestamp_ns": time.monotonic_ns(),
            }
        )
    )
    replacement.replace(path)


def serve(metrics_path: pathlib.Path) -> None:
    torch, stream, left, right = initialize()
    count = 0
    write_metrics(metrics_path, count)
    print(json.dumps(metadata(torch), sort_keys=True), flush=True)
    while True:
        iteration(torch, stream, left, right)
        count += 1
        if count % 8 == 0:
            write_metrics(metrics_path, count)


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--serve", action="store_true")
    mode.add_argument("--timed", action="store_true")
    parser.add_argument("--metrics", type=pathlib.Path)
    parser.add_argument("--seconds", type=float, default=1.5)
    parser.add_argument("--profile", action="store_true")
    args = parser.parse_args()
    if args.serve:
        if args.metrics is None:
            raise SystemExit("--metrics is required with --serve")
        serve(args.metrics)
    else:
        run_timed(args.seconds, args.profile)


if __name__ == "__main__":
    main()
