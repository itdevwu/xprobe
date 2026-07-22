#!/usr/bin/env python3
"""Summarize a bounded xprobe Event JSONL artifact."""

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


def memcpy_report(intervals: list[dict]) -> dict:
    copies = [interval for interval in intervals if interval["kind"] == "memcpy"]
    grouped = collections.defaultdict(list)
    for interval in copies:
        grouped[interval["name"]].append(interval)
    return {
        "duration": duration_summary([item["duration_ns"] for item in copies]),
        "total_bytes": sum(item["bytes"] or 0 for item in copies),
        "by_kind": [
            {
                "kind": kind,
                "duration": duration_summary([item["duration_ns"] for item in group]),
                "total_bytes": sum(item["bytes"] or 0 for item in group),
            }
            for kind, group in sorted(grouped.items())
        ],
    }


def stream_report(intervals: list[dict]) -> list[dict]:
    grouped = collections.defaultdict(list)
    for interval in intervals:
        key = (
            interval["pid"],
            interval["device_id"],
            interval["context_id"],
            interval["stream_id"],
        )
        grouped[key].append(interval)

    reports = []
    for (pid, device, context, stream), group in grouped.items():
        kernels = sorted(
            (item for item in group if item["kind"] == "kernel"),
            key=lambda item: (item["start_ns"], item["end_ns"]),
        )
        gaps = []
        overlaps = []
        for previous, current in zip(kernels, kernels[1:]):
            delta = current["start_ns"] - previous["end_ns"]
            if delta >= 0:
                gaps.append(delta)
            else:
                overlaps.append(-delta)
        reports.append(
            {
                "pid": pid,
                "device_id": device,
                "context_id": context,
                "stream_id": stream,
                "event_counts": dict(
                    sorted(collections.Counter(item["kind"] for item in group).items())
                ),
                "summed_activity_ns": sum(item["duration_ns"] for item in group),
                "busy_union_ns": interval_union_ns(
                    [(item["start_ns"], item["end_ns"]) for item in group]
                ),
                "adjacent_kernel_gaps": duration_summary(gaps),
                "adjacent_kernel_overlaps": duration_summary(overlaps),
            }
        )
    reports.sort(
        key=lambda item: (
            item["pid"] if item["pid"] is not None else -1,
            item["device_id"] if item["device_id"] is not None else -1,
            item["context_id"] if item["context_id"] is not None else -1,
            item["stream_id"] if item["stream_id"] is not None else -1,
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


def analyze(path: pathlib.Path) -> dict:
    events = load_events(path)
    intervals, unmatched_starts, unmatched_ends = pair_activities(events)
    activity_ranges = [(item["start_ns"], item["end_ns"]) for item in intervals]
    busy = interval_union_ns(activity_ranges)
    summed = sum(item["duration_ns"] for item in intervals)
    span = (
        max(item["end_ns"] for item in intervals)
        - min(item["start_ns"] for item in intervals)
        if intervals
        else 0
    )
    warnings = []
    if unmatched_starts or unmatched_ends:
        warnings.append(
            {
                "code": "UNPAIRED_ACTIVITY_BOUNDARIES",
                "message": "activity metrics exclude unpaired start or end records",
            }
        )
    return {
        "analysis_version": "1.0",
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
        "gpu": {
            "span_ns": span,
            "busy_union_ns": busy,
            "summed_activity_ns": summed,
            "overlap_factor": round(summed / busy, 6) if busy else None,
            "busy_fraction_of_span": round(busy / span, 6) if span else None,
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
        "streams": stream_report(intervals),
        "warnings": warnings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize kernels, copies, overlap, streams, and gaps in xprobe Event JSONL"
    )
    parser.add_argument("trace", type=pathlib.Path)
    args = parser.parse_args()
    json.dump(analyze(args.trace), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
