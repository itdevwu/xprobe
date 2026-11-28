//! External CPython stack sampling results.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{EvidenceArtifact, SchemaVersion3, SessionStatus, TargetIdentity, Warning};

/// One Python function in a sampled stack.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PythonFrame {
    /// `co_qualname` (3.11+) or `co_name`.
    pub function: String,
    pub file: String,
    /// The line where the function starts, not the line that was running.
    pub first_line: u32,
}

/// Where a blocked thread waits in native code, from
/// `/proc/<pid>/task/<tid>/syscall`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PythonNativeLeaf {
    /// The system call it is blocked in, if any.
    pub syscall: Option<String>,
    /// The mapped object and symbol of its user-space program counter.
    pub module: Option<String>,
    pub symbol: Option<String>,
}

/// Thread samples blocked at one native leaf.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PythonNativeWait {
    pub leaf: PythonNativeLeaf,
    pub samples: u64,
    /// Share of thread samples.
    pub proportion: f64,
}

/// Identical stacks, innermost frame first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PythonStackGroup {
    pub frames: Vec<PythonFrame>,
    pub samples: u64,
    /// Share of the samples this group was drawn from.
    pub proportion: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PythonHotspot {
    pub frame: PythonFrame,
    pub inclusive_samples: u64,
    pub exclusive_samples: u64,
    pub inclusive_proportion: f64,
    pub exclusive_proportion: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PythonSampleInventory {
    pub name: Option<String>,
    pub duration_ms: u64,
    /// Stacks of the GIL holder; proportions are of GIL ticks, so they sum
    /// with `gil_released_proportion` to one.
    pub gil_stack_groups: Vec<PythonStackGroup>,
    pub gil_hotspots: Vec<PythonHotspot>,
    /// Share of GIL ticks on which no thread held the GIL: native code that
    /// released it, I/O, or idle waiting.
    pub gil_released_proportion: f64,
    /// Stacks of every thread from the slower sweeps; proportions are of
    /// thread samples.
    pub thread_stack_groups: Vec<PythonStackGroup>,
    /// Native leaves of blocked threads in the sweeps; a running thread has
    /// none.
    pub native_waits: Vec<PythonNativeWait>,
}

/// How a sample's thread was mapped to a Linux TID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PythonTidSource {
    /// `PyThreadState.native_thread_id` (3.11+).
    Native,
    /// The TID glibc stores in `struct pthread` (before 3.11).
    Pthread,
    /// No consistent TID mapping; samples carry no TID.
    Unmapped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadLatency {
    pub p50_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PythonSampleCollection {
    /// Maps sample timestamps to wall time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock: Option<crate::WallClock>,
    /// `3.N` of the target interpreter.
    pub python_version: String,
    pub python_binary: String,
    pub tid_source: PythonTidSource,
    pub elapsed_ns: u64,
    pub gil_hz_requested: u32,
    /// GIL ticks per second actually reached.
    pub gil_hz_achieved: f64,
    pub threads_hz_requested: u32,
    pub threads_hz_achieved: f64,
    pub gil_ticks: u64,
    pub gil_samples: u64,
    pub gil_released_ticks: u64,
    pub thread_sweeps: u64,
    pub thread_samples: u64,
    pub threads: u32,
    /// Reads discarded because the innermost frame, a code object, a frame
    /// mapping, or the GIL holder changed while they were read.
    pub inconsistent_reads: u64,
    /// Swept threads whose `/proc/<pid>/task/<tid>/syscall` could not be
    /// read or parsed.
    pub native_unreadable: u64,
    /// Ticks that started after their deadline.
    pub late_ticks: u64,
    pub sample_capacity: u64,
    /// Samples not kept because the capacity was reached.
    pub over_capacity: u64,
    pub stack_depth: u32,
    pub truncated_stacks: u64,
    /// Wall time of one kept stack read.
    pub read_latency: Option<ReadLatency>,
}

/// Result of `measure --python-sample`, schema `3.0`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PythonSampleResult {
    pub schema_version: SchemaVersion3,
    pub ok: bool,
    pub session_id: String,
    pub status: SessionStatus,
    pub target: TargetIdentity,
    pub inventory: PythonSampleInventory,
    pub collection: PythonSampleCollection,
    /// Every sample with its timestamp, one `PythonSampleRecord` per line.
    pub artifact: Option<EvidenceArtifact>,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}

/// One line of a Python sample artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PythonSampleRecord {
    /// `CLOCK_MONOTONIC` time just before the stack was read.
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: Option<u32>,
    /// Taken as the GIL holder rather than in a sweep of every thread.
    pub gil: bool,
    pub truncated: bool,
    /// Innermost frame first.
    pub frames: Vec<PythonFrame>,
    /// Where the thread was blocked in native code, for sweep samples of a
    /// thread that was not running.
    pub native: Option<PythonNativeLeaf>,
}
