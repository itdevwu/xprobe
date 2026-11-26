#!/usr/bin/env python3
"""Summarize a bounded xprobe Event JSONL artifact.

Beyond aggregate GPU timing, the report ranks idle gaps, optionally ranks the
slowest pairs of a measurement result, and can list every event inside a time
window ("vertical slice") around a gap, an outlier, or explicit timestamps.
Everything is descriptive: events inside a window are concurrent with it, not
proven causes.
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


def slice_events(events: list[dict], start_ns: int, end_ns: int, limit: int) -> dict:
    """Every event inside [start_ns, end_ns], in time order, bounded by limit."""
    inside = sorted(
        (event for event in events if start_ns <= event["timestamp_ns"] <= end_ns),
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


def analyze(
    path: pathlib.Path,
    *,
    top_gaps: int = 5,
    measurement: pathlib.Path | None = None,
    outliers: int = 10,
    window: tuple[str, object] | None = None,
    window_ns: int = 0,
    max_slice_events: int = 200,
    python_samples: pathlib.Path | None = None,
) -> dict:
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
    idle_gaps = device_idle_gaps(intervals, top_gaps)
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
        window_report = {
            "around": {"kind": kind, "start_ns": target["start_ns"], "end_ns": target["end_ns"]},
            "window_ns": window_ns,
            **slice_events(events, start_ns, end_ns, max_slice_events),
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
        "analysis_version": "1.3",
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
    parser.add_argument("trace", type=pathlib.Path)
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
        args.trace,
        top_gaps=args.top_gaps,
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
