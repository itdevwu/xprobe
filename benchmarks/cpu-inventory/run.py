#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable


DEFAULT_SECONDS = 2
FREQUENCY_HZ = 199


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--xprobe", type=pathlib.Path, default="target/debug/xprobe")
    parser.add_argument("--python", default="/usr/bin/python3")
    parser.add_argument("--perf", default="perf")
    parser.add_argument("--py-spy", default="py-spy")
    parser.add_argument("--seconds", type=int, default=DEFAULT_SECONDS)
    args = parser.parse_args()
    if args.seconds < 1:
        raise SystemExit("--seconds must be at least 1")

    workspace = pathlib.Path(__file__).resolve().parents[2]
    xprobe = require_executable(args.xprobe)
    python = require_executable(pathlib.Path(args.python))
    perf = require_command(args.perf)
    py_spy = require_command(args.py_spy)
    require_cpython_perf(python)

    with tempfile.TemporaryDirectory(prefix="xprobe-cpu-inventory-") as directory:
        output = pathlib.Path(directory)
        native = output / "native-workload"
        resource_runner = output / "resource-runner"
        compile_fixture(workspace / "benchmarks/cpu-inventory/native_workload.c", native)
        compile_fixture(
            workspace / "benchmarks/cuda-aggregate/resource_runner.c", resource_runner
        )
        report = run_benchmark(
            workspace,
            output,
            xprobe,
            python,
            perf,
            py_spy,
            native,
            resource_runner,
            args.seconds,
        )
    print(json.dumps(report, sort_keys=True))


def run_benchmark(
    workspace: pathlib.Path,
    output: pathlib.Path,
    xprobe: pathlib.Path,
    python: pathlib.Path,
    perf: pathlib.Path,
    py_spy: pathlib.Path,
    native: pathlib.Path,
    resource_runner: pathlib.Path,
    seconds: int,
) -> dict:
    native_cases: dict[str, dict] = {}
    native_cases["baseline"] = run_case(
        "native-baseline", [str(native)], output, resource_runner, ["sleep", str(seconds)]
    )[0]
    native_cpu, native_inventory = run_case(
        "native-xprobe-cpu",
        [str(native)],
        output,
        resource_runner,
        cpu_sample_command(xprobe, seconds),
        prepare=lambda pid: validate_cpu(xprobe, pid),
    )
    native_cases["xprobe_cpu"] = native_cpu
    native_cases["xprobe_cpu"]["quality"] = cpu_quality(native_inventory)
    perf_data = output / "native-perf.data"
    native_perf, _ = run_case(
        "native-perf",
        [str(native)],
        output,
        resource_runner,
        [
            str(perf),
            "record",
            "--quiet",
            "--frequency",
            str(FREQUENCY_HZ),
            "--call-graph",
            "dwarf",
            "--pid",
            "{pid}",
            "--output",
            str(perf_data),
            "--",
            "sleep",
            str(seconds),
        ],
        artifact=perf_data,
    )
    native_perf["quality"] = perf_quality(perf, perf_data)
    native_cases["perf"] = native_perf
    syscall_case, syscall_inventory = run_case(
        "native-xprobe-syscalls",
        [str(native)],
        output,
        resource_runner,
        syscall_command(xprobe, seconds),
        prepare=lambda pid: validate_syscalls(xprobe, pid),
    )
    syscall_case["quality"] = syscall_quality(syscall_inventory)
    native_cases["xprobe_syscalls"] = syscall_case

    entry, returned = native_selector_hints(native_inventory)
    exact_case, exact_result = run_case(
        "native-xprobe-exact",
        [str(native)],
        output,
        resource_runner,
        exact_command(xprobe, entry, returned, "stack-nested", seconds),
        prepare=lambda pid: validate_pair(xprobe, pid, entry, returned, "stack-nested"),
    )
    exact_case["quality"] = exact_quality(exact_result)
    native_cases["xprobe_exact"] = exact_case

    python_target = [
        str(python),
        "-X",
        "perf",
        "-u",
        str(workspace / "benchmarks/cpu-inventory/python_workload.py"),
    ]
    python_cases: dict[str, dict] = {}
    python_cases["baseline"] = run_case(
        "python-baseline", python_target, output, resource_runner, ["sleep", str(seconds)]
    )[0]
    python_cpu, python_inventory = run_case(
        "python-xprobe-cpu",
        python_target,
        output,
        resource_runner,
        cpu_sample_command(xprobe, seconds),
        prepare=lambda pid: validate_cpu(xprobe, pid),
    )
    python_cpu["quality"] = cpu_quality(python_inventory)
    python_cases["xprobe_cpu"] = python_cpu
    py_spy_data = output / "python-py-spy.txt"
    python_py_spy, _ = run_case(
        "python-py-spy",
        python_target,
        output,
        resource_runner,
        [
            str(py_spy),
            "record",
            "--pid",
            "{pid}",
            "--duration",
            str(seconds),
            "--rate",
            str(FREQUENCY_HZ),
            "--format",
            "raw",
            "--output",
            str(py_spy_data),
        ],
        artifact=py_spy_data,
    )
    python_py_spy["quality"] = py_spy_quality(py_spy_data)
    python_cases["py_spy"] = python_py_spy
    gc_case, gc_result = run_case(
        "python-xprobe-gc",
        python_target,
        output,
        resource_runner,
        exact_command(xprobe, "python:gc_start", "python:gc_end", "exact", seconds),
        prepare=lambda pid: validate_pair(
            xprobe, pid, "python:gc_start", "python:gc_end", "exact"
        ),
    )
    gc_case["quality"] = exact_quality(gc_result)
    python_cases["xprobe_gc"] = gc_case

    assert_cpu_inventory(native_inventory, require_python=False)
    assert_cpu_inventory(python_inventory, require_python=True)
    assert syscall_inventory["ok"] is True
    assert syscall_inventory["collection"]["dropped_aggregates"] == 0
    assert exact_result["measurement"]["samples"]["matched"] > 0
    assert gc_result["measurement"]["samples"]["matched"] > 0

    return {
        "schema_version": "2.0",
        "ok": True,
        "environment": {
            "kernel": os.uname().release,
            "python": subprocess.check_output(
                [str(python), "--version"], text=True, stderr=subprocess.STDOUT
            ).strip(),
            "perf": tool_version(perf, ["--version"]),
            "py_spy": tool_version(py_spy, ["--version"]),
            "effective_uid": os.geteuid(),
        },
        "workload": {
            "seconds_per_case": seconds,
            "frequency_hz": FREQUENCY_HZ,
            "fresh_target_per_case": True,
            "profilers_coexist": False,
        },
        "native": summarize_cases(native_cases),
        "python": summarize_cases(python_cases),
        "interpretation": "workload-specific observations; no profiler is universally faster",
    }


def run_case(
    name: str,
    target_prefix: list[str],
    output: pathlib.Path,
    resource_runner: pathlib.Path,
    profiler_template: list[str],
    prepare: Callable[[int], dict] | None = None,
    artifact: pathlib.Path | None = None,
) -> tuple[dict, dict | None]:
    metrics = output / f"{name}-target.json"
    target = subprocess.Popen(
        [*target_prefix, str(metrics)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert target.stdout is not None
        ready_line = target.stdout.readline()
        if not ready_line:
            stderr = target.stderr.read() if target.stderr else ""
            raise AssertionError(f"{name} target exited before readiness: {stderr}")
        metadata = json.loads(ready_line)
        wait_for_metrics(metrics)
        validation = prepare(target.pid) if prepare else None
        before = read_metrics(metrics)
        resource_metrics = output / f"{name}-resources.txt"
        command = [argument.format(pid=target.pid) for argument in profiler_template]
        completed = subprocess.run(
            [str(resource_runner), str(resource_metrics), str(target.pid), *command],
            check=False,
            capture_output=True,
            text=True,
        )
        after = read_metrics(metrics)
        if completed.returncode != 0:
            raise AssertionError(
                f"{name} failed with {completed.returncode}:\n"
                f"stdout={completed.stdout}\nstderr={completed.stderr}"
            )
        result = json.loads(completed.stdout) if completed.stdout.strip() else None
        count = after["count"] - before["count"]
        elapsed_ns = after["timestamp_ns"] - before["timestamp_ns"]
        if count <= 0 or elapsed_ns <= 0:
            raise AssertionError({"name": name, "before": before, "after": after})
        resources = read_resource_metrics(resource_metrics)
        case = {
            "target": metadata,
            "throughput_iterations_per_second": count * 1_000_000_000 / elapsed_ns,
            "collector": {
                "wall_ns": resources["wall_ns"],
                "cpu_us": resources["user_us"] + resources["system_us"],
                "user_us": resources["user_us"],
                "system_us": resources["system_us"],
                "peak_rss_kib": resources["max_rss_kib"],
            },
            "target_memory": {
                "start_rss_kib": resources["target_start_rss_kib"],
                "peak_rss_kib": resources["target_peak_rss_kib"],
                "growth_kib": resources["target_peak_rss_kib"]
                - resources["target_start_rss_kib"],
            },
            "artifact_bytes": artifact.stat().st_size if artifact else len(completed.stdout),
        }
        if validation is not None:
            if validation.get("valid") is not True:
                raise AssertionError({"name": name, "validation": validation})
            case["validation"] = {
                "valid": True,
                "target": validation["target"],
            }
        return case, result
    finally:
        target.terminate()
        try:
            target.wait(timeout=5)
        except subprocess.TimeoutExpired:
            target.kill()
            target.wait(timeout=5)


def cpu_sample_command(xprobe: pathlib.Path, seconds: int) -> list[str]:
    return [
        str(xprobe),
        "measure",
        "--pid",
        "{pid}",
        "--cpu-sample",
        "--duration-ms",
        str(seconds * 1000),
        "--frequency-hz",
        str(FREQUENCY_HZ),
        "--max-samples",
        str(seconds * FREQUENCY_HZ * 4),
        "--max-groups",
        "512",
        "--json",
        "--non-interactive",
        "--no-color",
    ]


def syscall_command(xprobe: pathlib.Path, seconds: int) -> list[str]:
    return [
        str(xprobe),
        "measure",
        "--pid",
        "{pid}",
        "--syscall-aggregate",
        "--duration-ms",
        str(seconds * 1000),
        "--max-groups",
        "256",
        "--json",
        "--non-interactive",
        "--no-color",
    ]


def exact_command(
    xprobe: pathlib.Path, start: str, end: str, policy: str, seconds: int
) -> list[str]:
    return [
        str(xprobe),
        "measure",
        "--pid",
        "{pid}",
        "--from",
        start,
        "--to",
        end,
        "--match",
        policy,
        "--duration-ms",
        str(seconds * 1000),
        "--max-events",
        "50000",
        "--json",
        "--non-interactive",
        "--no-color",
    ]


def validate_cpu(xprobe: pathlib.Path, pid: int) -> dict:
    return run_json(
        [str(xprobe), "validate", "--pid", str(pid), "--cpu-sample", *json_flags()]
    )


def validate_syscalls(xprobe: pathlib.Path, pid: int) -> dict:
    return run_json(
        [
            str(xprobe),
            "validate",
            "--pid",
            str(pid),
            "--syscall-aggregate",
            *json_flags(),
        ]
    )


def validate_pair(
    xprobe: pathlib.Path, pid: int, start: str, end: str, policy: str
) -> dict:
    return run_json(
        [
            str(xprobe),
            "validate",
            "--pid",
            str(pid),
            "--from",
            start,
            "--to",
            end,
            "--match",
            policy,
            *json_flags(),
        ]
    )


def json_flags() -> list[str]:
    return ["--json", "--non-interactive", "--no-color"]


def run_json(command: list[str]) -> dict:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed with {completed.returncode}: {' '.join(command)}\n"
            f"stdout={completed.stdout}\nstderr={completed.stderr}"
        )
    return json.loads(completed.stdout)


def native_selector_hints(inventory: dict) -> tuple[str, str]:
    for hotspot in inventory["inventory"]["hotspots"]:
        if hotspot["frame"]["symbol"] == "xprobe_native_hot_loop":
            entry = hotspot.get("entry_selector_hint")
            returned = hotspot.get("return_selector_hint")
            if entry and returned:
                return entry, returned
    raise AssertionError("CPU inventory did not produce selectors for xprobe_native_hot_loop")


def cpu_quality(result: dict) -> dict:
    collection = result["collection"]
    symbols = result["symbolization"]
    observed = collection["observed_samples"]
    total_frames = symbols["total_frames"]
    resolved = symbols["resolved_native_frames"] + symbols["resolved_python_frames"]
    return {
        "completeness": collection["completeness"],
        "observed_samples": observed,
        "grouped_samples": collection["grouped_samples"],
        "lost_samples": collection["lost_samples"],
        "sample_capacity": collection["sample_capacity"],
        "group_capacity": collection["group_capacity"],
        "groups": collection["groups"],
        "stack_coverage": collection["grouped_samples"] / observed if observed else 0.0,
        "symbol_coverage": resolved / total_frames if total_frames else 0.0,
        "python_status": symbols["python_status"],
        "truncated_stacks": collection["truncated_stacks"],
    }


def syscall_quality(result: dict) -> dict:
    collection = result["collection"]
    return {
        "completeness": collection["completeness"],
        "observed_entries": collection["observed_entries"],
        "matched_exits": collection["matched_exits"],
        "unmatched_exits": collection["unmatched_exits"],
        "inflight_at_end": collection["inflight_at_end"],
        "dropped_aggregates": collection["dropped_aggregates"],
        "groups": collection["groups"],
        "group_capacity": collection["group_capacity"],
    }


def exact_quality(result: dict) -> dict:
    samples = result["measurement"]["samples"]
    return {
        "completeness": result["collection"]["completeness"],
        "matched_samples": samples["matched"],
        "unmatched_start_samples": samples["unmatched_start"],
        "unmatched_end_samples": samples["unmatched_end"],
        "ambiguous_samples": samples["ambiguous"],
        "dropped_events": result["collection"]["dropped_events"],
        "correlation_confidence": result["correlation"]["confidence"],
    }


def perf_quality(perf: pathlib.Path, data: pathlib.Path) -> dict:
    completed = subprocess.run(
        [str(perf), "script", "--input", str(data)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(f"perf script failed:\n{completed.stderr}")
    samples = sum(1 for line in completed.stdout.splitlines() if line and not line[0].isspace())
    return {"decoded_samples": samples, "lost_samples": None}


def py_spy_quality(path: pathlib.Path) -> dict:
    samples = 0
    stacks = 0
    for line in path.read_text().splitlines():
        stack, separator, count = line.rpartition(" ")
        if not separator or not stack:
            raise AssertionError(f"malformed py-spy raw record: {line}")
        samples += int(count)
        stacks += 1
    return {"decoded_samples": samples, "stack_groups": stacks, "lost_samples": None}


def assert_cpu_inventory(result: dict, require_python: bool) -> None:
    assert result["ok"] is True, result
    assert result["status"] == "completed", result
    assert result["collection"]["completeness"] == "complete", result
    assert result["collection"]["observed_samples"] > 0, result
    assert result["collection"]["lost_samples"] == 0, result
    assert result["collection"]["grouped_samples"] > 0, result
    assert result["symbolization"]["resolved_native_frames"] > 0, result
    if require_python:
        assert result["symbolization"]["python_status"] == "active", result
        assert result["symbolization"]["resolved_python_frames"] > 0, result


def summarize_cases(cases: dict[str, dict]) -> dict:
    baseline = cases["baseline"]["throughput_iterations_per_second"]
    for case in cases.values():
        observed = case["throughput_iterations_per_second"]
        case["overhead_ratio"] = baseline / observed
    return cases


def read_metrics(path: pathlib.Path) -> dict[str, int]:
    return {key: int(value) for key, value in json.loads(path.read_text()).items()}


def read_resource_metrics(path: pathlib.Path) -> dict[str, int]:
    return {
        key: int(value)
        for key, value in (line.split() for line in path.read_text().splitlines())
    }


def wait_for_metrics(path: pathlib.Path) -> None:
    deadline = time.monotonic() + 10
    while not path.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for {path}")
        time.sleep(0.01)


def compile_fixture(source: pathlib.Path, output: pathlib.Path) -> None:
    subprocess.run(
        [
            "cc",
            "-std=c11",
            "-O2",
            "-g",
            "-fno-omit-frame-pointer",
            "-no-pie",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            str(source),
            "-o",
            str(output),
        ],
        check=True,
    )


def require_executable(path: pathlib.Path) -> pathlib.Path:
    resolved = path.resolve()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise SystemExit(f"required executable is unavailable: {path}")
    return resolved


def require_command(command: str) -> pathlib.Path:
    resolved = shutil.which(command)
    if resolved is None:
        raise SystemExit(f"required benchmark tool is unavailable: {command}")
    return pathlib.Path(resolved).resolve()


def require_cpython_perf(python: pathlib.Path) -> None:
    completed = subprocess.run(
        [
            str(python),
            "-X",
            "perf",
            "-c",
            "import sys; assert sys._xoptions.get('perf') is True",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"Python benchmark requires CPython -X perf support: {completed.stderr}"
        )


def tool_version(tool: pathlib.Path, arguments: list[str]) -> str:
    return subprocess.check_output(
        [str(tool), *arguments], text=True, stderr=subprocess.STDOUT
    ).strip()


if __name__ == "__main__":
    main()
