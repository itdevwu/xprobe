#!/usr/bin/env python3
import argparse
import json
import pathlib
import subprocess
import sys


MM_SYMBOL = "at::_ops::mm::call(at::Tensor const&, at::Tensor const&)"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", required=True)
    parser.add_argument("--xprobe", default="target/debug/xprobe")
    parser.add_argument("--measure", action="store_true")
    args = parser.parse_args()

    workspace = pathlib.Path(__file__).resolve().parents[2]
    workload = subprocess.Popen(
        [args.python, "-u", "-c", WORKLOAD],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert workload.stdout is not None
        metadata = json.loads(workload.stdout.readline())
        pid = workload.pid
        python_probe = resolve(
            workspace,
            args.xprobe,
            pid,
            metadata["cpython"],
            "_PyEval_EvalFrameDefault",
        )
        extension_probe = resolve(
            workspace,
            args.xprobe,
            pid,
            metadata["torch_extension"],
            "PyInit__C",
        )
        torch_probe = resolve(
            workspace,
            args.xprobe,
            pid,
            metadata["libtorch_cpu"],
            MM_SYMBOL,
            demangled=True,
        )
        measurement = (
            measure(workspace, args.xprobe, pid, metadata["libtorch_cpu"])
            if args.measure
            else None
        )
    finally:
        workload.terminate()
        workload.wait(timeout=10)

    assert python_probe["symbol"] == "_PyEval_EvalFrameDefault"
    assert extension_probe["symbol"] == "PyInit__C"
    assert torch_probe["symbol"].startswith("_Z")
    assert torch_probe["symbol_demangled"] == MM_SYMBOL
    assert python_probe["object_kind"] in {"executable", "position_independent_executable"}
    assert extension_probe["object_kind"] == "shared_library"
    assert torch_probe["object_kind"] == "shared_library"
    if measurement is not None:
        assert measurement["measurement"]["samples"]["matched"] == 8
        assert len(measurement["evidence"]) == 8
        for evidence in measurement["evidence"]:
            assert evidence["start"]["host"]["symbol_demangled"] == MM_SYMBOL
            assert evidence["end"]["host"]["symbol_demangled"] == MM_SYMBOL
    print(
        json.dumps(
            {
                "ok": True,
                "measured": measurement is not None,
                "pytorch_version": metadata["torch_version"],
                "resolved": ["cpython", "native_extension", "libtorch_cpp"],
            },
            sort_keys=True,
        )
    )


def resolve(
    workspace: pathlib.Path,
    binary: str,
    pid: int,
    object_path: str,
    symbol: str,
    demangled: bool = False,
) -> dict:
    target = f"symbol={symbol}" if demangled else symbol
    selector = f"uprobe:{object_path}:{target}:entry"
    completed = subprocess.run(
        [
            binary,
            "resolve",
            "--pid",
            str(pid),
            "--selector",
            selector,
            "--json",
            "--non-interactive",
            "--no-color",
        ],
        cwd=workspace,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"resolve failed for {selector!r}:\n{completed.stdout}\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def measure(
    workspace: pathlib.Path,
    binary: str,
    pid: int,
    object_path: str,
) -> dict:
    selector = f"uprobe:{object_path}:symbol={MM_SYMBOL}"
    completed = subprocess.run(
        [
            binary,
            "measure",
            "--pid",
            str(pid),
            "--from",
            f"{selector}:entry",
            "--to",
            f"{selector}:return",
            "--match",
            "stack-nested",
            "--samples",
            "8",
            "--max-events",
            "256",
            "--timeout-ms",
            "30000",
            "--json",
            "--non-interactive",
            "--no-color",
        ],
        cwd=workspace,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"measure failed:\n{completed.stdout}\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


WORKLOAD = r"""
import json
import pathlib
import time

import torch

torch_root = pathlib.Path(torch.__file__).resolve().parent
print(json.dumps({
    "cpython": str(pathlib.Path("/proc/self/exe").resolve()),
    "torch_extension": str(pathlib.Path(torch._C.__file__).resolve()),
    "libtorch_cpu": str((torch_root / "lib" / "libtorch_cpu.so").resolve()),
    "torch_version": torch.__version__,
}), flush=True)
a = torch.randn(64, 64)
b = torch.randn(64, 64)
while True:
    torch.mm(a, b)
    time.sleep(0.01)
"""


if __name__ == "__main__":
    main()
