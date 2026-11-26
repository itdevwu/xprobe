//! CPython stack samples and their aggregation.
//!
//! The collector reads samples from a live interpreter; this module holds
//! their data and turns a finished capture into a `PythonSampleResult`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use xprobe_protocol::{
    CpuStackFrame, PythonFrame, PythonHotspot, PythonNativeLeaf, PythonNativeWait,
    PythonSampleCollection, PythonSampleInventory, PythonSampleRecord, PythonSampleResult,
    PythonStackGroup, PythonTidSource, ReadLatency, SchemaVersion3, SessionStatus, TargetIdentity,
    Warning,
};

/// A function in a sampled stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    /// `co_qualname` (3.11+) or `co_name`.
    pub function: String,
    pub file: String,
    /// `co_firstlineno`: the line where the function starts.
    pub first_line: u32,
}

/// One stack, innermost frame first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stack {
    pub frames: Vec<u32>,
    pub truncated: bool,
}

/// One stack read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonSample {
    /// `CLOCK_MONOTONIC` time just before the read.
    pub timestamp_ns: u64,
    pub tid: Option<u32>,
    /// Taken as the GIL holder rather than in an all-thread sweep.
    pub gil: bool,
    pub stack: Stack,
    /// Where a blocked thread waits in native code (sweep samples only).
    pub native: Option<NativeLeaf>,
}

/// A blocked thread's system call and user-space program counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeLeaf {
    pub syscall: Option<u32>,
    pub pc: u64,
}

/// Parse `/proc/<pid>/task/<tid>/syscall`: `running`, `-1 sp pc` for a
/// thread blocked outside a system call, or `nr args... sp pc`.
#[must_use]
pub fn parse_task_syscall(text: &str) -> Option<NativeLeaf> {
    let fields = text.split_whitespace().collect::<Vec<_>>();
    let first = *fields.first()?;
    if first == "running" || fields.len() < 3 {
        return None;
    }
    let pc = u64::from_str_radix(fields.last()?.trim_start_matches("0x"), 16).ok()?;
    let syscall = if first == "-1" {
        None
    } else {
        Some(first.parse().ok()?)
    };
    Some(NativeLeaf { syscall, pc })
}

/// How many reads of each kind happened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SamplerCounters {
    pub gil_ticks: u64,
    /// GIL ticks on which no thread held the GIL.
    pub gil_idle: u64,
    pub thread_sweeps: u64,
    /// Stacks that changed while they were read.
    pub inconsistent: u64,
    /// Samples not kept because `max_samples` was reached.
    pub over_capacity: u64,
    /// Ticks that started after their deadline had passed.
    pub late_ticks: u64,
}

/// How thread states were mapped to Linux TIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TidSource {
    /// `PyThreadState.native_thread_id` (3.11+).
    Native,
    /// A TID found in `struct pthread` at this offset.
    Pthread(u64),
    Unmapped,
}

/// A finished sampling run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonCapture {
    pub samples: Vec<PythonSample>,
    pub codes: Vec<Code>,
    pub counters: SamplerCounters,
    /// Wall time of each kept stack read, in nanoseconds.
    pub read_ns: Vec<u64>,
    pub elapsed: Duration,
    pub tid_source: TidSource,
    /// Every TID seen in the interpreter's thread list.
    pub threads: BTreeSet<u32>,
}

/// Stack groups and hotspots kept per list.
const LIST_LIMIT: usize = 50;
/// Share of discarded reads above which the result warns.
const INCONSISTENT_WARNING_SHARE: f64 = 0.05;
/// Share of the requested rate below which the result warns.
const RATE_WARNING_SHARE: f64 = 0.9;

/// What the sampler was asked to do and where it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamplingRequest {
    pub session_id: String,
    pub name: Option<String>,
    pub target: TargetIdentity,
    pub python_minor: u8,
    pub python_binary: String,
    pub duration: Duration,
    pub gil_hz: u32,
    pub threads_hz: u32,
    pub sample_capacity: u64,
    pub stack_depth: u32,
}

fn frame(codes: &[Code], index: u32) -> PythonFrame {
    codes.get(index as usize).map_or_else(
        || PythonFrame {
            function: "<unknown>".to_owned(),
            file: String::new(),
            first_line: 0,
        },
        |code| PythonFrame {
            function: code.function.clone(),
            file: code.file.clone(),
            first_line: code.first_line,
        },
    )
}

#[allow(
    clippy::cast_precision_loss,
    reason = "sample counts stay far below 2^52"
)]
fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn groups<'a>(
    samples: impl Iterator<Item = &'a PythonSample>,
    codes: &[Code],
    total: u64,
) -> Vec<PythonStackGroup> {
    let mut counts = BTreeMap::<&[u32], u64>::new();
    for sample in samples {
        *counts.entry(sample.stack.frames.as_slice()).or_default() += 1;
    }
    let mut groups = counts
        .into_iter()
        .map(|(frames, samples)| PythonStackGroup {
            frames: frames.iter().map(|index| frame(codes, *index)).collect(),
            samples,
            proportion: ratio(samples, total),
        })
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| {
        right
            .samples
            .cmp(&left.samples)
            .then_with(|| left.frames.cmp(&right.frames))
    });
    groups.truncate(LIST_LIMIT);
    groups
}

fn hotspots<'a>(
    samples: impl Iterator<Item = &'a PythonSample>,
    codes: &[Code],
    total: u64,
) -> Vec<PythonHotspot> {
    let mut inclusive = BTreeMap::<u32, u64>::new();
    let mut exclusive = BTreeMap::<u32, u64>::new();
    for sample in samples {
        // A recursive function counts once per sample.
        for index in sample.stack.frames.iter().collect::<BTreeSet<_>>() {
            *inclusive.entry(*index).or_default() += 1;
        }
        if let Some(leaf) = sample.stack.frames.first() {
            *exclusive.entry(*leaf).or_default() += 1;
        }
    }
    let mut hotspots = inclusive
        .into_iter()
        .map(|(index, inclusive_samples)| {
            let exclusive_samples = exclusive.get(&index).copied().unwrap_or(0);
            PythonHotspot {
                frame: frame(codes, index),
                inclusive_samples,
                exclusive_samples,
                inclusive_proportion: ratio(inclusive_samples, total),
                exclusive_proportion: ratio(exclusive_samples, total),
            }
        })
        .collect::<Vec<_>>();
    hotspots.sort_by(|left, right| {
        right
            .exclusive_samples
            .cmp(&left.exclusive_samples)
            .then(right.inclusive_samples.cmp(&left.inclusive_samples))
            .then_with(|| left.frame.cmp(&right.frame))
    });
    hotspots.truncate(LIST_LIMIT);
    hotspots
}

fn latency(read_ns: &[u64]) -> Option<ReadLatency> {
    let mut sorted = read_ns.to_vec();
    sorted.sort_unstable();
    let rank =
        |percentile: usize| sorted[(percentile * sorted.len()).div_ceil(100).saturating_sub(1)];
    (!sorted.is_empty()).then(|| ReadLatency {
        p50_ns: rank(50),
        p99_ns: rank(99),
        max_ns: sorted[sorted.len() - 1],
    })
}

fn warning(code: &str, message: String) -> Warning {
    Warning {
        code: code.to_owned(),
        message,
        details: BTreeMap::new(),
    }
}

/// Warnings for discarded reads, missed rates, unmapped TIDs, and samples
/// over capacity.
fn quality_warnings(
    request: &SamplingRequest,
    capture: &PythonCapture,
    gil_hz_achieved: f64,
    threads_hz_achieved: f64,
) -> Vec<Warning> {
    let counters = capture.counters;
    let mut warnings = Vec::new();
    let attempted = capture.samples.len() as u64 + counters.inconsistent;
    if ratio(counters.inconsistent, attempted) > INCONSISTENT_WARNING_SHARE {
        warnings.push(warning(
            "PYTHON_READS_INCONSISTENT",
            format!(
                "{} of {attempted} stack reads changed while they were read and were discarded",
                counters.inconsistent
            ),
        ));
    }
    for (what, requested, achieved) in [
        ("GIL", request.gil_hz, gil_hz_achieved),
        ("thread", request.threads_hz, threads_hz_achieved),
    ] {
        if requested != 0 && achieved < f64::from(requested) * RATE_WARNING_SHARE {
            warnings.push(warning(
                "PYTHON_RATE_BELOW_REQUEST",
                format!("{what} sampling reached {achieved:.0} Hz of the requested {requested} Hz"),
            ));
        }
    }
    if capture.tid_source == TidSource::Unmapped {
        warnings.push(warning(
            "PYTHON_TIDS_UNMAPPED",
            "thread states could not be mapped to Linux TIDs; samples carry no TID".to_owned(),
        ));
    }
    if counters.over_capacity != 0 {
        warnings.push(warning(
            "PYTHON_SAMPLES_OVER_CAPACITY",
            format!(
                "{} samples were not kept after the capacity of {} was reached",
                counters.over_capacity, request.sample_capacity
            ),
        ));
    }
    warnings
}

/// Aggregate a finished capture.
#[must_use]
pub fn analyze(
    request: &SamplingRequest,
    capture: &PythonCapture,
    native: &BTreeMap<u64, CpuStackFrame>,
) -> PythonSampleResult {
    let counters = capture.counters;
    let gil = || capture.samples.iter().filter(|sample| sample.gil);
    let threads = || capture.samples.iter().filter(|sample| !sample.gil);
    let gil_samples = gil().count() as u64;
    let thread_samples = threads().count() as u64;
    let seconds = capture.elapsed.as_secs_f64();
    #[allow(
        clippy::cast_precision_loss,
        reason = "tick counts stay far below 2^52"
    )]
    let per_second = |count: u64| {
        if seconds > 0.0 {
            count as f64 / seconds
        } else {
            0.0
        }
    };
    let gil_hz_achieved = per_second(counters.gil_ticks);
    let threads_hz_achieved = per_second(counters.thread_sweeps);

    let warnings = quality_warnings(request, capture, gil_hz_achieved, threads_hz_achieved);
    let truncated_stacks = capture
        .samples
        .iter()
        .filter(|sample| sample.stack.truncated)
        .count() as u64;
    PythonSampleResult {
        schema_version: SchemaVersion3::current(),
        ok: true,
        session_id: request.session_id.clone(),
        status: SessionStatus::Completed,
        target: request.target.clone(),
        inventory: PythonSampleInventory {
            name: request.name.clone(),
            duration_ms: u64::try_from(request.duration.as_millis()).unwrap_or(u64::MAX),
            gil_stack_groups: groups(gil(), &capture.codes, counters.gil_ticks),
            gil_hotspots: hotspots(gil(), &capture.codes, counters.gil_ticks),
            gil_released_proportion: ratio(counters.gil_idle, counters.gil_ticks),
            thread_stack_groups: groups(threads(), &capture.codes, thread_samples),
            native_waits: native_waits(threads(), native, thread_samples),
        },
        collection: PythonSampleCollection {
            python_version: format!("3.{}", request.python_minor),
            python_binary: request.python_binary.clone(),
            tid_source: match capture.tid_source {
                TidSource::Native => PythonTidSource::Native,
                TidSource::Pthread(_) => PythonTidSource::Pthread,
                TidSource::Unmapped => PythonTidSource::Unmapped,
            },
            elapsed_ns: u64::try_from(capture.elapsed.as_nanos()).unwrap_or(u64::MAX),
            gil_hz_requested: request.gil_hz,
            gil_hz_achieved,
            threads_hz_requested: request.threads_hz,
            threads_hz_achieved,
            gil_ticks: counters.gil_ticks,
            gil_samples,
            gil_released_ticks: counters.gil_idle,
            thread_sweeps: counters.thread_sweeps,
            thread_samples,
            threads: u32::try_from(capture.threads.len()).unwrap_or(u32::MAX),
            inconsistent_reads: counters.inconsistent,
            late_ticks: counters.late_ticks,
            sample_capacity: request.sample_capacity,
            over_capacity: counters.over_capacity,
            stack_depth: request.stack_depth,
            truncated_stacks,
            read_latency: latency(&capture.read_ns),
        },
        artifact: None,
        warnings,
    }
}

/// The program counters of every native leaf, to symbolize while the
/// target's mappings are still live.
#[must_use]
pub fn native_addresses(capture: &PythonCapture) -> BTreeSet<u64> {
    capture
        .samples
        .iter()
        .filter_map(|sample| sample.native.map(|leaf| leaf.pc))
        .collect()
}

fn native_leaf(leaf: NativeLeaf, native: &BTreeMap<u64, CpuStackFrame>) -> PythonNativeLeaf {
    let frame = native.get(&leaf.pc);
    PythonNativeLeaf {
        syscall: leaf.syscall.map(|number| {
            crate::syscall_aggregate::syscall_name(number)
                .map_or_else(|| format!("syscall {number}"), str::to_owned)
        }),
        module: frame.and_then(|frame| frame.module_path.clone()),
        symbol: frame.and_then(|frame| frame.symbol.clone()),
    }
}

fn native_waits<'a>(
    samples: impl Iterator<Item = &'a PythonSample>,
    native: &BTreeMap<u64, CpuStackFrame>,
    total: u64,
) -> Vec<PythonNativeWait> {
    let mut counts = BTreeMap::<PythonNativeLeaf, u64>::new();
    for leaf in samples.filter_map(|sample| sample.native) {
        *counts.entry(native_leaf(leaf, native)).or_default() += 1;
    }
    let mut waits = counts
        .into_iter()
        .map(|(leaf, samples)| PythonNativeWait {
            leaf,
            samples,
            proportion: ratio(samples, total),
        })
        .collect::<Vec<_>>();
    waits.sort_by(|left, right| {
        right
            .samples
            .cmp(&left.samples)
            .then_with(|| left.leaf.cmp(&right.leaf))
    });
    waits.truncate(LIST_LIMIT);
    waits
}

/// Every sample as an artifact record.
#[must_use]
pub fn records(
    capture: &PythonCapture,
    pid: u32,
    native: &BTreeMap<u64, CpuStackFrame>,
) -> Vec<PythonSampleRecord> {
    capture
        .samples
        .iter()
        .map(|sample| PythonSampleRecord {
            timestamp_ns: sample.timestamp_ns,
            pid,
            tid: sample.tid,
            gil: sample.gil,
            truncated: sample.stack.truncated,
            frames: sample
                .stack
                .frames
                .iter()
                .map(|index| frame(&capture.codes, *index))
                .collect(),
            native: sample.native.map(|leaf| native_leaf(leaf, native)),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use xprobe_protocol::TargetIdentity;

    use super::{
        Code, NativeLeaf, PythonCapture, PythonSample, SamplerCounters, SamplingRequest, Stack,
        TidSource, analyze, parse_task_syscall, records,
    };

    fn sample(gil: bool, frames: &[u32]) -> PythonSample {
        PythonSample {
            timestamp_ns: 1,
            tid: Some(7),
            gil,
            stack: Stack {
                frames: frames.to_vec(),
                truncated: false,
            },
            native: None,
        }
    }

    #[test]
    fn parses_task_syscall_states() {
        assert_eq!(parse_task_syscall("running\n"), None);
        assert_eq!(
            parse_task_syscall("-1 0x7ffc1234 0x7f00aa\n"),
            Some(NativeLeaf {
                syscall: None,
                pc: 0x7f_00aa
            })
        );
        assert_eq!(
            parse_task_syscall("202 0x1 0x80 0x0 0x0 0x0 0x0 0x7ffc1234 0x7f00bb\n"),
            Some(NativeLeaf {
                syscall: Some(202),
                pc: 0x7f_00bb
            })
        );
    }

    #[test]
    fn aggregates_gil_and_thread_samples_separately() {
        let code = |function: &str| Code {
            function: function.to_owned(),
            file: "app.py".to_owned(),
            first_line: 1,
        };
        let capture = PythonCapture {
            // Three GIL samples in `step` under `main`, one in `load`; the
            // fifth GIL tick found the GIL released.
            samples: vec![
                sample(true, &[0, 2]),
                sample(true, &[0, 2]),
                sample(true, &[0, 2]),
                sample(true, &[1, 2]),
                sample(false, &[1, 2]),
            ],
            codes: vec![code("step"), code("load"), code("main")],
            counters: SamplerCounters {
                gil_ticks: 5,
                gil_idle: 1,
                thread_sweeps: 1,
                ..SamplerCounters::default()
            },
            read_ns: vec![10, 20, 30, 40, 1000],
            elapsed: Duration::from_millis(2),
            tid_source: TidSource::Native,
            threads: BTreeSet::from([7]),
        };
        let request = SamplingRequest {
            session_id: "xp".to_owned(),
            name: None,
            target: TargetIdentity {
                pid: 1,
                process_start_time: 2,
            },
            python_minor: 12,
            python_binary: "/usr/bin/python3.12".to_owned(),
            duration: Duration::from_millis(2),
            gil_hz: 2500,
            threads_hz: 500,
            sample_capacity: 100,
            stack_depth: 128,
        };
        let result = analyze(&request, &capture, &std::collections::BTreeMap::new());
        let inventory = &result.inventory;
        assert_eq!(inventory.gil_stack_groups[0].samples, 3);
        assert!((inventory.gil_stack_groups[0].proportion - 0.6).abs() < 1e-9);
        assert!((inventory.gil_released_proportion - 0.2).abs() < 1e-9);
        let step = &inventory.gil_hotspots[0];
        assert_eq!(step.frame.function, "step");
        assert_eq!((step.exclusive_samples, step.inclusive_samples), (3, 3));
        let main = inventory
            .gil_hotspots
            .iter()
            .find(|hotspot| hotspot.frame.function == "main")
            .unwrap();
        assert_eq!((main.exclusive_samples, main.inclusive_samples), (0, 4));
        assert_eq!(inventory.thread_stack_groups[0].frames[0].function, "load");
        let collection = &result.collection;
        assert_eq!((collection.gil_samples, collection.thread_samples), (4, 1));
        assert!((collection.gil_hz_achieved - 2500.0).abs() < 1e-6);
        let latency = collection.read_latency.unwrap();
        assert_eq!(
            (latency.p50_ns, latency.p99_ns, latency.max_ns),
            (30, 1000, 1000)
        );
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);

        let lines = records(&capture, 1, &std::collections::BTreeMap::new());
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0].frames[0].function, "step");
        assert_eq!(lines[0].frames[1].function, "main");
    }
}
