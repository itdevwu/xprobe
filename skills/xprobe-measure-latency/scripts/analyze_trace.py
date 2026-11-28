#!/usr/bin/env python3
"""Summarize bounded xprobe Event JSONL artifacts.

For one artifact the report gives each GPU's time budget (busy, idle, compute,
communication, transfers), ranks device idle gaps and stream gaps, optionally
ranks the slowest pairs of a measurement result, and can list every event
inside a time window ("vertical slice") around a gap, an outlier, or explicit
timestamps. For several artifacts of one host, such as the ranks of a data- or
tensor-parallel job, it compares those budgets over the window they share.
Everything is descriptive: events inside a window are concurrent with it, and
ranks that overlap in time are compared, not shown to cause each other.
"""

import argparse
import collections
import json
import math
import pathlib
import re
import sys


ACTIVITY_TYPES = {
    "gpu_kernel_start": ("kernel", "start"),
    "gpu_kernel_end": ("kernel", "end"),
    "gpu_memcpy_start": ("memcpy", "start"),
    "gpu_memcpy_end": ("memcpy", "end"),
    "gpu_memset_start": ("memset", "start"),
    "gpu_memset_end": ("memset", "end"),
}


def percentile(values: list[int], percent: int) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(percent * len(ordered) / 100))
    return ordered[rank - 1]


def duration_summary(values: list[int]) -> dict:
    if not values:
        return {
            "count": 0,
            "total_ns": 0,
            "min_ns": None,
            "p50_ns": None,
            "p95_ns": None,
            "max_ns": None,
        }
    return {
        "count": len(values),
        "total_ns": sum(values),
        "min_ns": min(values),
        "p50_ns": percentile(values, 50),
        "p95_ns": percentile(values, 95),
        "max_ns": max(values),
    }


def interval_union_ns(intervals: list[tuple[int, int]]) -> int:
    if not intervals:
        return 0
    ordered = sorted(intervals)
    union = 0
    current_start, current_end = ordered[0]
    for start, end in ordered[1:]:
        if start <= current_end:
            current_end = max(current_end, end)
        else:
            union += current_end - current_start
            current_start, current_end = start, end
    return union + current_end - current_start


def dimensions(cuda: dict, field: str) -> tuple[int, int, int] | None:
    value = cuda.get(field)
    if value is None:
        return None
    return (value["x"], value["y"], value["z"])


def activity_name(kind: str, cuda: dict) -> str:
    if kind == "kernel":
        return cuda.get("kernel_name") or "<unknown>"
    if kind == "memcpy":
        return cuda.get("memcpy_kind") or "unknown"
    return "memset"


def activity_key(kind: str, event: dict) -> tuple:
    cuda = event.get("cuda") or {}
    return (
        kind,
        event.get("pid"),
        cuda.get("device_id"),
        cuda.get("context_id"),
        cuda.get("stream_id"),
        cuda.get("correlation_id"),
        activity_name(kind, cuda),
    )


# Communication kernels are recognized by name; a heuristic that holds for
# NCCL builds and can be overridden with --comm-kernel.
DEFAULT_COMM_KERNEL = r"^nccl"


def pair_activities(events: list[dict]) -> tuple[list[dict], int, int]:
    boundaries = []
    for event in events:
        activity = ACTIVITY_TYPES.get(event.get("event_type"))
        if activity is not None:
            kind, boundary = activity
            boundaries.append((event["timestamp_ns"], boundary != "start", kind, boundary, event))
    boundaries.sort(key=lambda item: (item[0], item[1]))

    starts: dict[tuple, collections.deque] = collections.defaultdict(collections.deque)
    intervals = []
    unmatched_ends = 0
    for _, _, kind, boundary, event in boundaries:
        key = activity_key(kind, event)
        if boundary == "start":
            starts[key].append(event)
            continue
        if not starts[key]:
            unmatched_ends += 1
            continue
        start = starts[key].popleft()
        if start["clock_domain"] != event["clock_domain"]:
            raise ValueError(
                f"activity pair {start.get('event_id')} / {event.get('event_id')} "
                "uses different clock domains"
            )
        start_ns = start["timestamp_ns"]
        end_ns = event["timestamp_ns"]
        if end_ns < start_ns:
            raise ValueError(
                f"activity pair {start.get('event_id')} / {event.get('event_id')} "
                "has a negative duration"
            )
        cuda = start.get("cuda") or {}
        intervals.append(
            {
                "kind": kind,
                "name": activity_name(kind, cuda),
                "pid": start.get("pid"),
                "clock_domain": start["clock_domain"],
                "device_id": cuda.get("device_id"),
                "context_id": cuda.get("context_id"),
                "stream_id": cuda.get("stream_id"),
                "start_ns": start_ns,
                "end_ns": end_ns,
                "duration_ns": end_ns - start_ns,
                "grid": dimensions(cuda, "grid"),
                "block": dimensions(cuda, "block"),
                "bytes": cuda.get("bytes"),
            }
        )
    unmatched_starts = sum(len(queue) for queue in starts.values())
    return intervals, unmatched_starts, unmatched_ends


def boundary_intervals(events: list[dict], intervals: list[dict]) -> list[dict]:
    """Activity the capture saw only one boundary of, stretched to the edge
    of the capture: it ran before the first event or past the last one."""
    paired = collections.Counter()
    for interval in intervals:
        paired[(interval["pid"], interval["device_id"], interval["start_ns"], "start")] += 1
        paired[(interval["pid"], interval["device_id"], interval["end_ns"], "end")] += 1
    clocks = collections.defaultdict(list)
    for event in events:
        clocks[event.get("clock_domain")].append(event["timestamp_ns"])
    edges = {clock: (min(times), max(times)) for clock, times in clocks.items()}
    partial = []
    for event in events:
        activity = ACTIVITY_TYPES.get(event.get("event_type"))
        if activity is None:
            continue
        kind, boundary = activity
        cuda = event.get("cuda") or {}
        key = (event.get("pid"), cuda.get("device_id"), event["timestamp_ns"], boundary)
        if paired[key]:
            paired[key] -= 1
            continue
        first, last = edges[event.get("clock_domain")]
        start, end = (event["timestamp_ns"], last) if boundary == "start" else (first, event["timestamp_ns"])
        partial.append(
            {
                "kind": kind,
                "name": activity_name(kind, cuda),
                "pid": event.get("pid"),
                "clock_domain": event.get("clock_domain"),
                "device_id": cuda.get("device_id"),
                "start_ns": start,
                "end_ns": end,
                "partial": True,
            }
        )
    return partial


def union(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merged, sorted intervals."""
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def covered_ns(intervals: list[tuple[int, int]]) -> int:
    return sum(end - start for start, end in intervals)


def subtract(base: list[tuple[int, int]], cut: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Parts of merged `base` intervals not covered by merged `cut`."""
    remaining = []
    for start, end in base:
        cursor = start
        for cut_start, cut_end in cut:
            if cut_end <= cursor or cut_start >= end:
                continue
            if cut_start > cursor:
                remaining.append((cursor, cut_start))
            cursor = max(cursor, cut_end)
        if cursor < end:
            remaining.append((cursor, end))
    return remaining


def clip(intervals: list[tuple[int, int]], window: tuple[int, int] | None) -> list[tuple[int, int]]:
    if window is None:
        return intervals
    return [
        (max(start, window[0]), min(end, window[1]))
        for start, end in intervals
        if end > window[0] and start < window[1]
    ]


def gaps_between(busy: list[tuple[int, int]], limit: int) -> list[dict]:
    gaps = [
        {"start_ns": previous[1], "end_ns": current[0], "gap_ns": current[0] - previous[1]}
        for previous, current in zip(busy, busy[1:])
    ]
    return top(gaps, "gap_ns", limit)


def device_budgets(
    intervals: list[dict],
    uuids: dict,
    comm_kernel: re.Pattern,
    limit: int,
    window: tuple[int, int] | None = None,
) -> list[dict]:
    """Each GPU's time budget per process and clock domain.

    `busy` is the union of every kernel, copy, and memset; `compute` of
    kernels that are not communication; `communication_only` is time when
    only communication kernels ran, which on a collective is often a rank
    waiting for its peers. Inside `window` the budgets are clipped to it.
    """
    grouped = collections.defaultdict(list)
    for interval in intervals:
        if interval["device_id"] is None:
            continue
        grouped[(interval["pid"], interval["device_id"], interval["clock_domain"])].append(interval)
    rows = []
    for (pid, device, clock), group in sorted(grouped.items(), key=lambda item: str(item[0])):
        def merged(predicate):
            return union(clip([(item["start_ns"], item["end_ns"]) for item in group if predicate(item)], window))

        busy = merged(lambda item: True)
        compute = merged(lambda item: item["kind"] == "kernel" and not comm_kernel.search(item["name"]))
        communication = merged(lambda item: item["kind"] == "kernel" and comm_kernel.search(item["name"]))
        transfer = merged(lambda item: item["kind"] != "kernel")
        if window is not None:
            span = window
        elif busy:
            span = (busy[0][0], busy[-1][1])
        else:
            continue
        span_ns = span[1] - span[0]
        rows.append(
            {
                "pid": pid,
                "device_id": device,
                "uuid": uuids.get((pid, device)),
                "clock_domain": clock,
                "span": {"start_ns": span[0], "end_ns": span[1], "ns": span_ns},
                "busy_ns": covered_ns(busy),
                "idle_ns": span_ns - covered_ns(busy),
                "compute_ns": covered_ns(compute),
                "communication_ns": covered_ns(communication),
                "communication_only_ns": covered_ns(subtract(communication, compute)),
                "summed_activity_ns": sum(
                    item["end_ns"] - item["start_ns"] for item in group if not item.get("partial")
                ),
                "transfer_ns": covered_ns(transfer),
                "partial_activities": sum(1 for item in group if item.get("partial")),
                "top_idle_gaps": gaps_between(busy, limit),
                "top_compute_gaps": gaps_between(compute, limit),
            }
        )
    return rows


def selector_hint(name: str, names: list[str]) -> dict | None:
    if name == "<unknown>":
        return None
    escaped = re.escape(name)
    if len(name) < 128:
        regex = f"^{escaped}$"
        scope = "exact_name"
    else:
        alternatives = [candidate for candidate in names if candidate != name]
        candidates = []
        for length in range(min(16, len(name)), min(127, len(name)) + 1):
            prefix = name[:length]
            if all(not candidate.startswith(prefix) for candidate in alternatives):
                candidates.append((length, f"^{re.escape(prefix)}.*", "prefix"))
                break
            suffix = name[-length:]
            if all(not candidate.endswith(suffix) for candidate in alternatives):
                candidates.append((length, f".*{re.escape(suffix)}$", "suffix"))
                break
        if not candidates:
            return None
        _, regex, filter_kind = min(candidates)
        scope = f"{filter_kind}_unique_in_capture"
    return {
        "name_regex": regex,
        "scope": scope,
        "start_selector": f"cuda:kernel_start:name~{regex}",
        "end_selector": f"cuda:kernel_end:name~{regex}",
    }


def dimensions_object(value: tuple[int, int, int] | None) -> dict | None:
    if value is None:
        return None
    return {"x": value[0], "y": value[1], "z": value[2]}


def kernel_report(intervals: list[dict]) -> dict:
    kernels = [interval for interval in intervals if interval["kind"] == "kernel"]
    names = sorted({interval["name"] for interval in kernels})
    total = sum(interval["duration_ns"] for interval in kernels)
    grouped = collections.defaultdict(list)
    for interval in kernels:
        grouped[interval["name"]].append(interval)

    reports = []
    for name, group in grouped.items():
        variants = collections.defaultdict(list)
        for interval in group:
            variants[(interval["grid"], interval["block"])].append(interval["duration_ns"])
        reports.append(
            {
                "name": name,
                "duration": duration_summary([item["duration_ns"] for item in group]),
                "summed_kernel_time_share": round(
                    sum(item["duration_ns"] for item in group) / total, 6
                )
                if total
                else None,
                "selector_hint": selector_hint(name, names),
                "launch_variants": [
                    {
                        "grid": dimensions_object(grid),
                        "block": dimensions_object(block),
                        "duration": duration_summary(durations),
                    }
                    for (grid, block), durations in sorted(
                        variants.items(), key=lambda item: repr(item[0])
                    )
                ],
            }
        )
    reports.sort(key=lambda item: (-item["duration"]["total_ns"], item["name"]))
    kernel_intervals = [(item["start_ns"], item["end_ns"]) for item in kernels]
    busy = interval_union_ns(kernel_intervals)
    return {
        "duration": duration_summary([item["duration_ns"] for item in kernels]),
        "busy_union_ns": busy,
        "overlap_factor": round(total / busy, 6) if busy else None,
        "by_name": reports,
    }


def bandwidth(group: list[dict]) -> dict:
    """Achieved copy bandwidth over the summed copy time (bytes per ns = GB/s)."""
    total_bytes = sum(item["bytes"] or 0 for item in group)
    total_ns = sum(item["duration_ns"] for item in group)
    return {
        "total_bytes": total_bytes,
        "avg_bytes": round(total_bytes / len(group), 1) if group else None,
        "bandwidth_gbps": round(total_bytes / total_ns, 3) if total_ns else None,
    }


def memcpy_report(intervals: list[dict]) -> dict:
    copies = [interval for interval in intervals if interval["kind"] == "memcpy"]
    grouped = collections.defaultdict(list)
    for interval in copies:
        grouped[interval["name"]].append(interval)
    return {
        "duration": duration_summary([item["duration_ns"] for item in copies]),
        **bandwidth(copies),
        "by_kind": [
            {
                "kind": kind,
                "duration": duration_summary([item["duration_ns"] for item in group]),
                **bandwidth(group),
            }
            for kind, group in sorted(grouped.items())
        ],
    }


def gap_entry(previous: dict, current: dict) -> dict:
    return {
        "start_ns": previous["end_ns"],
        "end_ns": current["start_ns"],
        "gap_ns": current["start_ns"] - previous["end_ns"],
        "after": previous["name"],
        "before": current["name"],
    }


def top(entries: list[dict], key: str, limit: int) -> list[dict]:
    return sorted(entries, key=lambda item: (-item[key], item["start_ns"]))[:limit]


def device_idle_gaps(intervals: list[dict], limit: int) -> list[dict]:
    """Largest spans with no captured activity on a device: GPU bubbles.

    Activity is compared only within one process and clock domain."""
    grouped = collections.defaultdict(list)
    for interval in intervals:
        grouped[(interval["pid"], interval["device_id"], interval["clock_domain"])].append(interval)
    gaps = []
    for (pid, device, clock), group in grouped.items():
        ordered = sorted(group, key=lambda item: (item["start_ns"], item["end_ns"]))
        busy_until = ordered[0]
        for current in ordered[1:]:
            if current["start_ns"] > busy_until["end_ns"]:
                gaps.append(
                    {
                        "pid": pid,
                        "device_id": device,
                        "clock_domain": clock,
                        **gap_entry(busy_until, current),
                    }
                )
            if current["end_ns"] > busy_until["end_ns"]:
                busy_until = current
    return top(gaps, "gap_ns", limit)


def stream_report(intervals: list[dict], top_gaps: int) -> list[dict]:
    grouped = collections.defaultdict(list)
    for interval in intervals:
        key = (
            interval["pid"],
            interval["device_id"],
            interval["context_id"],
            interval["stream_id"],
            interval["clock_domain"],
        )
        grouped[key].append(interval)

    reports = []
    for (pid, device, context, stream, clock), group in grouped.items():
        kernels = sorted(
            (item for item in group if item["kind"] == "kernel"),
            key=lambda item: (item["start_ns"], item["end_ns"]),
        )
        gaps = []
        gap_entries = []
        overlaps = []
        for previous, current in zip(kernels, kernels[1:]):
            delta = current["start_ns"] - previous["end_ns"]
            if delta >= 0:
                gaps.append(delta)
                gap_entries.append(gap_entry(previous, current))
            else:
                overlaps.append(-delta)
        reports.append(
            {
                "pid": pid,
                "device_id": device,
                "context_id": context,
                "stream_id": stream,
                "clock_domain": clock,
                "event_counts": dict(
                    sorted(collections.Counter(item["kind"] for item in group).items())
                ),
                "summed_activity_ns": sum(item["duration_ns"] for item in group),
                "busy_union_ns": interval_union_ns(
                    [(item["start_ns"], item["end_ns"]) for item in group]
                ),
                "adjacent_kernel_gaps": duration_summary(gaps),
                "adjacent_kernel_overlaps": duration_summary(overlaps),
                "top_gaps": top(gap_entries, "gap_ns", top_gaps),
            }
        )
    reports.sort(
        key=lambda item: (
            item["pid"] if item["pid"] is not None else -1,
            item["device_id"] if item["device_id"] is not None else -1,
            item["context_id"] if item["context_id"] is not None else -1,
            item["stream_id"] if item["stream_id"] is not None else -1,
            item["clock_domain"],
        )
    )
    return reports


def load_events(path: pathlib.Path) -> list[dict]:
    events = []
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get("schema_version") != "2.0":
                raise ValueError(
                    f"{path}:{line_number}: expected schema_version 2.0"
                )
            events.append(event)
    if not events:
        raise ValueError(f"{path}: trace contains no events")
    return events


def event_label(event: dict) -> str | None:
    cuda = event.get("cuda") or {}
    host = event.get("host") or {}
    nvtx = event.get("nvtx") or {}
    attributes = event.get("attributes") or {}
    return (
        cuda.get("kernel_name")
        or attributes.get("cuda_api_name")
        or nvtx.get("name")
        or host.get("symbol_demangled")
        or host.get("symbol")
        or cuda.get("memcpy_kind")
    )


def comparable_clocks(domains: set) -> set:
    """Clock domains whose timestamps compare with these."""
    return HOST_CLOCKS if domains <= HOST_CLOCKS else domains


def slice_events(
    events: list[dict],
    start_ns: int,
    end_ns: int,
    limit: int,
    pid: object = None,
    clocks: set | None = None,
) -> dict:
    """Events inside [start_ns, end_ns], in time order, bounded by limit; a
    gap or outlier keeps only its own process and comparable clocks."""
    inside = sorted(
        (
            event
            for event in events
            if start_ns <= event["timestamp_ns"] <= end_ns
            and (pid is None or event.get("pid") == pid)
            and (clocks is None or event.get("clock_domain") in clocks)
        ),
        key=lambda event: (event["timestamp_ns"], event.get("sequence", 0)),
    )
    rows = []
    for event in inside[:limit]:
        cuda = event.get("cuda") or {}
        rows.append(
            {
                "timestamp_ns": event["timestamp_ns"],
                "offset_ns": event["timestamp_ns"] - start_ns,
                "event_type": event["event_type"],
                "name": event_label(event),
                "pid": event.get("pid"),
                "tid": event.get("tid"),
                "stream_id": cuda.get("stream_id"),
                "correlation_id": cuda.get("correlation_id"),
                "event_id": event.get("event_id"),
            }
        )
    return {
        "start_ns": start_ns,
        "end_ns": end_ns,
        "events": rows,
        "total_events": len(inside),
        "truncated": len(inside) > limit,
        "counts_by_type": dict(
            sorted(collections.Counter(event["event_type"] for event in inside).items())
        ),
    }


HOST_CLOCKS = {"host_monotonic", "cupti_normalized_to_host_monotonic"}


def load_python_samples(path: pathlib.Path) -> list[dict]:
    """Records written by `measure --python-sample`."""
    samples = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict) or "timestamp_ns" not in record or "frames" not in record:
            raise ValueError(f"{path}:{number}: not a Python sample record")
        samples.append(record)
    return samples


def frame_label(frame: dict) -> str:
    return f"{frame['function']} ({frame['file']}:{frame['first_line']})"


def python_slice(samples: list[dict], start_ns: int, end_ns: int, limit: int = 10) -> dict:
    """Python stacks sampled inside [start_ns, end_ns]."""
    inside = [sample for sample in samples if start_ns <= sample["timestamp_ns"] <= end_ns]
    gil = [sample for sample in inside if sample["gil"]]
    stacks = collections.Counter(
        tuple(frame_label(frame) for frame in sample["frames"]) for sample in gil
    )
    waits = collections.Counter(
        (
            sample["native"].get("syscall"),
            sample["native"].get("module"),
            sample["native"].get("symbol"),
        )
        for sample in inside
        if not sample["gil"] and sample.get("native")
    )
    return {
        "samples": len(inside),
        "gil_samples": len(gil),
        "gil_stacks": [
            {"frames": list(frames), "samples": count, "proportion": round(count / len(gil), 6)}
            for frames, count in sorted(stacks.items(), key=lambda item: (-item[1], item[0]))[:limit]
        ],
        "threads": dict(
            sorted(collections.Counter(str(sample.get("tid")) for sample in inside).items())
        ),
        "native_waits": [
            {"syscall": syscall, "module": module, "symbol": symbol, "samples": count}
            for (syscall, module, symbol), count in sorted(
                waits.items(), key=lambda item: (-item[1], tuple(map(str, item[0])))
            )[:limit]
        ],
    }


def measurement_outliers(path: pathlib.Path, limit: int) -> dict:
    """Slowest pairs from a measure result; full evidence when available."""
    result = json.loads(path.read_text())
    if result.get("ok") is not True:
        raise ValueError(f"{path}: not a successful measurement result")
    edges = result.get("edges")
    evidences = (
        [(edge["name"], edge["evidence"]) for edge in edges]
        if edges is not None
        else [(None, result["evidence"])]
    )
    outliers = []
    sources = set()
    for edge, evidence in evidences:
        if evidence.get("pairs") is not None:
            pairs = evidence["pairs"]
            sources.add("full_evidence")
        else:
            pairs = [exemplar["pair"] for exemplar in evidence.get("exemplars", [])]
            sources.add("rank_exemplars")
        for pair in pairs:
            start, end = pair["start"], pair["end"]
            outliers.append(
                {
                    "edge": edge,
                    "latency_ns": pair["latency_ns"],
                    "start_ns": start["timestamp_ns"],
                    "end_ns": end["timestamp_ns"],
                    "start_event": start.get("event_id"),
                    "end_event": end.get("event_id"),
                    "pid": start.get("pid"),
                    "tid": start.get("tid"),
                    "stream_id": (start.get("cuda") or {}).get("stream_id"),
                    "correlation_id": (start.get("cuda") or {}).get("correlation_id"),
                    "clock_domains": sorted(
                        {str(start.get("clock_domain")), str(end.get("clock_domain"))}
                    ),
                }
            )
    outliers.sort(key=lambda item: (-item["latency_ns"], item["start_ns"]))
    return {
        "input": str(path),
        "source": sorted(sources),
        "slowest": outliers[:limit],
    }


def load_manifest(path: pathlib.Path) -> dict | None:
    """The capture manifest written beside an artifact, if any."""
    manifest = path.with_name(path.name + ".manifest.json")
    if not manifest.exists():
        return None
    return json.loads(manifest.read_text())


def device_uuids(manifest: dict | None) -> dict:
    if manifest is None:
        return {}
    pid = manifest["target"]["pid"]
    return {(pid, device["device_id"]): device["uuid"] for device in manifest.get("cuda_devices", [])}


def analyze(
    path: pathlib.Path,
    *,
    top_gaps: int = 5,
    comm_kernel: re.Pattern = re.compile(DEFAULT_COMM_KERNEL),
    measurement: pathlib.Path | None = None,
    outliers: int = 10,
    window: tuple[str, object] | None = None,
    window_ns: int = 0,
    max_slice_events: int = 200,
    python_samples: pathlib.Path | None = None,
) -> dict:
    events = load_events(path)
    intervals, unmatched_starts, unmatched_ends = pair_activities(events)
    # Activity seen at one boundary only ran to the edge of the capture; it
    # keeps the device busy rather than leaving a false idle gap.
    partial = boundary_intervals(events, intervals)
    summed = sum(item["duration_ns"] for item in intervals)
    manifest = load_manifest(path)
    warnings = []
    if manifest is None or not manifest.get("all_gpu_activity"):
        warnings.append(
            {
                "code": "GPU_ACTIVITY_COVERAGE_UNKNOWN",
                "message": "no manifest records that every kernel, copy, and memset was captured; device idle time may include activity the capture filtered out",
            }
        )
    if unmatched_starts or unmatched_ends:
        warnings.append(
            {
                "code": "UNPAIRED_ACTIVITY_BOUNDARIES",
                "message": "durations exclude unpaired start or end records; device budgets stretch them to the capture edge",
            }
        )
    idle_gaps = device_idle_gaps(intervals + partial, top_gaps)
    outlier_report = measurement_outliers(measurement, outliers) if measurement else None
    window_report = None
    if window is not None:
        kind, value = window
        if kind == "gap":
            if not 1 <= value <= len(idle_gaps):
                raise ValueError(f"--slice-gap {value}: only {len(idle_gaps)} idle gaps")
            target = idle_gaps[value - 1]
        elif kind == "outlier":
            if outlier_report is None:
                raise ValueError("--slice-outlier requires --measurement")
            if not 1 <= value <= len(outlier_report["slowest"]):
                raise ValueError(
                    f"--slice-outlier {value}: only {len(outlier_report['slowest'])} outliers"
                )
            target = outlier_report["slowest"][value - 1]
        else:
            target = {"start_ns": value[0], "end_ns": value[1]}
        start_ns = target["start_ns"] - window_ns
        end_ns = target["end_ns"] + window_ns
        if kind == "gap":
            scope = {"pid": target["pid"], "clocks": comparable_clocks({target["clock_domain"]})}
        elif kind == "outlier":
            scope = {"pid": target["pid"], "clocks": comparable_clocks(set(target["clock_domains"]))}
        else:
            scope = {}
        window_report = {
            "around": {"kind": kind, "start_ns": target["start_ns"], "end_ns": target["end_ns"]},
            "window_ns": window_ns,
            **slice_events(events, start_ns, end_ns, max_slice_events, **scope),
        }
        if python_samples is not None:
            window_report["python"] = None
            # Python samples use CLOCK_MONOTONIC; only host-clock slices line
            # up with them. A gap or outlier carries its own clock and
            # process; a time range uses the events inside it, or the whole
            # trace when it holds none.
            evidence = [
                event for event in events if start_ns <= event["timestamp_ns"] <= end_ns
            ] or events
            if kind == "gap":
                domains = {target["clock_domain"]}
                pids = {target["pid"]}
            elif kind == "outlier":
                domains = set(target["clock_domains"])
                pids = {target["pid"]}
            else:
                domains = {event.get("clock_domain") for event in evidence}
                pids = {event.get("pid") for event in evidence}
            if not domains or not domains <= HOST_CLOCKS:
                warnings.append(
                    {
                        "code": "PYTHON_CLOCK_UNALIGNED",
                        "message": "the slice's timestamps are not all CLOCK_MONOTONIC; Python samples were not placed in it",
                    }
                )
            else:
                samples = load_python_samples(python_samples)
                matching = [sample for sample in samples if sample.get("pid") in pids]
                if len(matching) != len(samples):
                    warnings.append(
                        {
                            "code": "PYTHON_SAMPLES_OTHER_PROCESS",
                            "message": f"{len(samples) - len(matching)} Python samples come from processes other than the slice's and were left out",
                        }
                    )
                window_report["python"] = python_slice(matching, start_ns, end_ns)
    if outlier_report and outlier_report["source"] == ["rank_exemplars"]:
        warnings.append(
            {
                "code": "OUTLIERS_FROM_EXEMPLARS",
                "message": "measurement has summary evidence; rerun with --evidence full to rank every pair",
            }
        )
    return {
        "analysis_version": "1.4",
        "input": str(path),
        "events": {
            "total": len(events),
            "by_type": dict(
                sorted(collections.Counter(event["event_type"] for event in events).items())
            ),
            "paired_activities": len(intervals),
            "unmatched_activity_starts": unmatched_starts,
            "unmatched_activity_ends": unmatched_ends,
        },
        "capture": {
            "manifest": manifest is not None,
            "all_gpu_activity": bool(manifest and manifest.get("all_gpu_activity")),
            "window": manifest["window"] if manifest else None,
            "communication_kernels": comm_kernel.pattern,
        },
        "devices": device_budgets(intervals + partial, device_uuids(manifest), comm_kernel, top_gaps),
        "gpu": {
            "summed_activity_ns": summed,
            "top_idle_gaps": idle_gaps,
        },
        "kernels": kernel_report(intervals),
        "memcpy": memcpy_report(intervals),
        "memset": {
            "duration": duration_summary(
                [
                    item["duration_ns"]
                    for item in intervals
                    if item["kind"] == "memset"
                ]
            )
        },
        "streams": stream_report(intervals, top_gaps),
        "outliers": outlier_report,
        "slice": window_report,
        "warnings": warnings,
    }


def compare(paths: list[pathlib.Path], *, top_gaps: int, comm_kernel: re.Pattern) -> dict:
    """GPU budgets of several artifacts of one host, over the window they
    share. Each artifact is one process, so its events are never paired with
    another's; only their time budgets are compared."""
    inputs = []
    warnings = []
    for path in paths:
        events = load_events(path)
        intervals, _, _ = pair_activities(events)
        intervals += boundary_intervals(events, intervals)
        manifest = load_manifest(path)
        clocks = {item["clock_domain"] for item in intervals}
        if manifest is None:
            warnings.append(
                {
                    "code": "NO_MANIFEST",
                    "message": f"{path} has no manifest: its window is its activity span and its GPUs have no UUIDs",
                }
            )
        if manifest is not None and not manifest.get("all_gpu_activity"):
            warnings.append(
                {
                    "code": "GPU_ACTIVITY_COVERAGE_UNKNOWN",
                    "message": f"{path} did not record every GPU activity; its idle time may hide filtered work",
                }
            )
        if manifest is not None:
            window = (manifest["window"]["start_ns"], manifest["window"]["end_ns"])
        elif intervals:
            window = (
                min(item["start_ns"] for item in intervals),
                max(item["end_ns"] for item in intervals),
            )
        else:
            window = None
        inputs.append((path, intervals, manifest, clocks, window))
    host = all(clocks and clocks <= HOST_CLOCKS for _, _, _, clocks, _ in inputs)
    windows = [window for *_, window in inputs if window is not None]
    common = None
    if host and len(windows) == len(inputs):
        start = max(window[0] for window in windows)
        end = min(window[1] for window in windows)
        common = (start, end) if start < end else None
    if not host:
        warnings.append(
            {
                "code": "CLOCKS_NOT_COMPARABLE",
                "message": "not every artifact is on CLOCK_MONOTONIC; each is budgeted over its own span",
            }
        )
    elif common is None:
        warnings.append(
            {
                "code": "NO_COMMON_WINDOW",
                "message": "the artifacts share no instant; each is budgeted over its own span, so compare shares, not totals",
            }
        )
    rows = []
    for path, intervals, manifest, _, _ in inputs:
        for row in device_budgets(intervals, device_uuids(manifest), comm_kernel, top_gaps, common):
            span = row["span"]["ns"]
            row["input"] = str(path)
            row["shares"] = {
                name: round(row[f"{name}_ns"] / span, 6) if span else None
                for name in ("busy", "idle", "compute", "communication_only")
            }
            rows.append(row)
    def extreme(key, pick):
        candidates = [row for row in rows if row["shares"][key] is not None]
        if not candidates:
            return None
        row = pick(candidates, key=lambda row: row["shares"][key])
        return {"input": row["input"], "pid": row["pid"], "device_id": row["device_id"],
                "uuid": row["uuid"], "share": row["shares"][key]}
    computes = [row["shares"]["compute"] for row in rows if row["shares"]["compute"] is not None]
    return {
        "analysis_version": "1.4",
        "inputs": [str(path) for path in paths],
        "window": {"start_ns": common[0], "end_ns": common[1]} if common else None,
        "communication_kernels": comm_kernel.pattern,
        "devices": rows,
        "spread": {
            "compute_share": round(max(computes) - min(computes), 6) if computes else None,
            # On a collective, the rank that computes longest is the one its
            # peers wait for; the one waiting longest computes least.
            "most_compute": extreme("compute", max),
            "most_communication_only": extreme("communication_only", max),
            "most_idle": extreme("idle", max),
        },
        "warnings": warnings,
    }


def parse_around(value: str) -> tuple[int, int]:
    start, _, end = value.partition(":")
    start_ns = int(start)
    end_ns = int(end) if end else start_ns
    if end_ns < start_ns:
        raise argparse.ArgumentTypeError("--around END_NS must not precede START_NS")
    return (start_ns, end_ns)


def positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize kernels, copies, overlap, streams, gaps, outliers, "
        "and time slices in xprobe Event JSONL"
    )
    parser.add_argument("trace", type=pathlib.Path, nargs="+",
                        help="Event JSONL artifacts; several compare per-GPU budgets across processes")
    parser.add_argument("--comm-kernel", default=DEFAULT_COMM_KERNEL, metavar="REGEX",
                        help="kernel names counted as communication (default: ^nccl)")
    parser.add_argument("--top-gaps", type=positive, default=5,
                        help="idle gaps to rank per device and per stream")
    parser.add_argument("--measurement", type=pathlib.Path,
                        help="measure result JSON whose slowest pairs to rank")
    parser.add_argument("--outliers", type=positive, default=10,
                        help="slowest pairs to list from --measurement")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--slice-gap", type=positive, metavar="RANK",
                        help="list events around the RANK-th largest device idle gap")
    target.add_argument("--slice-outlier", type=positive, metavar="RANK",
                        help="list events around the RANK-th slowest measured pair")
    target.add_argument("--around", type=parse_around, metavar="START_NS[:END_NS]",
                        help="list events around explicit timestamps")
    parser.add_argument("--window-ms", type=float, default=0.0,
                        help="padding before and after the slice target")
    parser.add_argument("--max-slice-events", type=positive, default=200)
    parser.add_argument("--python-samples", type=pathlib.Path,
                        help="measure --python-sample artifact whose stacks to add to the slice")
    args = parser.parse_args()
    try:
        comm_kernel = re.compile(args.comm_kernel)
    except re.error as error:
        parser.error(f"--comm-kernel is not a regular expression: {error}")
    if len(args.trace) > 1:
        if args.measurement or args.slice_gap or args.slice_outlier or args.around or args.python_samples:
            parser.error("--measurement, slices, and --python-samples take one trace")
        report = compare(args.trace, top_gaps=args.top_gaps, comm_kernel=comm_kernel)
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return
    if args.python_samples is not None and not (
        args.slice_gap or args.slice_outlier or args.around
    ):
        parser.error("--python-samples requires --slice-gap, --slice-outlier, or --around")
    if args.window_ms < 0:
        parser.error("--window-ms must not be negative")
    window = None
    if args.slice_gap is not None:
        window = ("gap", args.slice_gap)
    elif args.slice_outlier is not None:
        window = ("outlier", args.slice_outlier)
    elif args.around is not None:
        window = ("timestamps", args.around)
    report = analyze(
        args.trace[0],
        top_gaps=args.top_gaps,
        comm_kernel=comm_kernel,
        measurement=args.measurement,
        outliers=args.outliers,
        window=window,
        window_ns=round(args.window_ms * 1_000_000),
        max_slice_events=args.max_slice_events,
        python_samples=args.python_samples,
    )
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
