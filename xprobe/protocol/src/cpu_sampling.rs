use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    CaptureCompleteness, CheckResult, SchemaVersion, SessionStatus, TargetIdentity,
    ValidationIssue, Warning,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CpuSampleEvent {
    CpuClock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CpuSamplingSpec {
    pub schema_version: SchemaVersion,
    pub name: Option<String>,
    pub target: TargetIdentity,
    pub sample_event: CpuSampleEvent,
    pub frequency_hz: u64,
    pub duration_ms: u64,
    pub timeout_ms: u64,
    pub max_samples: u64,
    pub max_groups: u64,
    pub stack_depth: u32,
    pub max_threads: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CpuFrameLanguage {
    Native,
    Python,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CpuStackFrame {
    pub address: u64,
    pub module_path: Option<String>,
    pub build_id: Option<String>,
    pub file_offset: Option<u64>,
    pub symbol: Option<String>,
    pub symbol_offset: Option<u64>,
    pub language: CpuFrameLanguage,
    pub source_path: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CpuStackGroup {
    pub frames: Vec<CpuStackFrame>,
    pub samples: u64,
    pub proportion: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CpuHotspot {
    pub frame: CpuStackFrame,
    pub inclusive_samples: u64,
    pub exclusive_samples: u64,
    pub inclusive_proportion: f64,
    pub exclusive_proportion: f64,
    pub entry_selector_hint: Option<String>,
    pub return_selector_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CpuSampleInventory {
    pub name: Option<String>,
    pub sample_event: CpuSampleEvent,
    pub frequency_hz: u64,
    pub duration_ms: u64,
    pub stack_groups: Vec<CpuStackGroup>,
    pub hotspots: Vec<CpuHotspot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PythonSymbolizationStatus {
    NotDetected,
    Inactive,
    Active,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CpuSampleCollectionSummary {
    pub completeness: CaptureCompleteness,
    pub observed_samples: u64,
    pub grouped_samples: u64,
    pub lost_samples: u64,
    pub sample_capacity: u64,
    pub group_capacity: u64,
    pub groups: u64,
    pub table_utilization: f64,
    pub stack_depth: u32,
    pub truncated_stacks: u64,
    pub threads_observed: u32,
    pub threads_attached: u32,
    pub thread_capacity: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CpuSymbolizationSummary {
    pub total_frames: u64,
    pub resolved_native_frames: u64,
    pub resolved_python_frames: u64,
    pub unresolved_frames: u64,
    pub python_status: PythonSymbolizationStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CpuSampleInventoryResult {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub session_id: String,
    pub status: SessionStatus,
    pub target: TargetIdentity,
    pub inventory: CpuSampleInventory,
    pub collection: CpuSampleCollectionSummary,
    pub symbolization: CpuSymbolizationSummary,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CpuSamplingRequirements {
    pub needs_perf_event: bool,
    pub target_mutation: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CpuSamplingValidationResult {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub valid: bool,
    pub target: TargetIdentity,
    pub target_threads: u32,
    pub requirements: CpuSamplingRequirements,
    pub perf_event: CheckResult,
    pub python_status: PythonSymbolizationStatus,
    #[serde(default)]
    pub issues: Vec<ValidationIssue>,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}
