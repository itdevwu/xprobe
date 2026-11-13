use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Per-thread time split over the triage window from procfs `schedstat`.
///
/// `blocked_ns` is window time neither running nor runnable. It includes
/// voluntary sleep and idle waiting, so read it per thread rather than as a
/// process total.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadTimeBreakdown {
    pub window_ns: u64,
    /// Threads alive for the whole window; totals cover only these threads.
    pub threads_observed: u64,
    pub threads_started: u64,
    pub threads_exited: u64,
    pub on_cpu_ns: u64,
    pub runqueue_ns: u64,
    pub blocked_ns: u64,
    /// Busiest whole-window threads by on-CPU plus runqueue time.
    pub top_threads: Vec<ThreadTime>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadTime {
    pub tid: u32,
    pub name: String,
    pub on_cpu_ns: u64,
    pub runqueue_ns: u64,
    pub blocked_ns: u64,
    pub on_cpu_share: f64,
    pub runqueue_share: f64,
    pub blocked_share: f64,
}

/// CFS bandwidth throttling of the target's cgroup over the triage window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CgroupCpuThrottling {
    pub version: CgroupVersion,
    pub cgroup_path: String,
    /// CPU quota divided by period; `null` means no CPU limit.
    pub quota_cpus: Option<f64>,
    pub periods: u64,
    pub throttled_periods: u64,
    pub throttled_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CgroupVersion {
    V1,
    V2,
}

/// NVML device health sampled through the triage window.
///
/// Utilization is the driver's sampled share of time with at least one kernel
/// running; it is an estimate, not an exact busy-interval union.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GpuDeviceHealth {
    pub index: u32,
    pub uuid: String,
    pub samples: u64,
    pub utilization_mean_pct: Option<f64>,
    pub utilization_max_pct: Option<u32>,
    pub memory_utilization_mean_pct: Option<f64>,
    /// Union of active NVML clock event reasons across samples.
    pub clock_event_reasons: Vec<String>,
    pub temperature_max_c: Option<u32>,
    pub power_max_w: Option<f64>,
    pub pcie: Option<PcieLink>,
}

/// Narrowest `PCIe` link observed against the link maximum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PcieLink {
    pub generation_min: u32,
    pub generation_max: u32,
    pub width_min: u32,
    pub width_max: u32,
}

/// One bounded triage window over a live process: where time went, and the
/// next exact measurement to run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriageResult {
    pub schema_version: crate::SchemaVersion3,
    pub ok: bool,
    pub session_id: String,
    pub status: crate::SessionStatus,
    pub target: crate::TargetIdentity,
    pub window_ms: u64,
    /// Ranked by estimated share of the window each finding accounts for.
    pub findings: Vec<TriageFinding>,
    pub threads: ThreadTimeBreakdown,
    pub cgroup: Option<CgroupCpuThrottling>,
    pub cpu_hotspots: Vec<crate::CpuHotspot>,
    pub syscalls: Vec<crate::SyscallAggregateGroup>,
    pub gpu_devices: Vec<GpuDeviceHealth>,
    pub gpu_activity: Vec<crate::AggregateGroup>,
    pub sources: Vec<TriageSource>,
    /// Questions this triage cannot answer; do not infer them from silence.
    pub not_covered: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<crate::Warning>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriageFinding {
    pub rank: u32,
    pub code: String,
    /// Estimated share of the window this finding accounts for, in [0, 1].
    pub impact_share: f64,
    pub summary: String,
    pub next: Option<TriageNextStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriageNextStep {
    pub kind: TriageNextKind,
    pub description: String,
    /// Ready to write to a file and run with `measure --spec`.
    pub spec: Option<crate::MeasurementSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TriageNextKind {
    Measure,
    Environment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriageSource {
    pub source: TriageSourceKind,
    pub status: TriageSourceStatus,
    pub reason: Option<String>,
    /// Full inventory result for this source, when one was written.
    pub artifact: Option<String>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TriageSourceKind {
    ThreadTime,
    Cgroup,
    CpuSample,
    SyscallAggregate,
    GpuHealth,
    GpuActivity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TriageSourceStatus {
    Collected,
    /// The capability is absent or not permitted on this host or target.
    Unavailable,
    /// Not applicable to this target, such as GPU activity without CUDA.
    Skipped,
}
