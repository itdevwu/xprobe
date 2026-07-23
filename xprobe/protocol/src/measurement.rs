use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Event, SchemaVersion, Warning};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetIdentity {
    pub pid: u32,
    pub process_start_time: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MatchPolicy {
    Exact,
    FirstAfter,
    Nearest,
    StackNested,
    StreamOrder,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementMode {
    #[default]
    Exact,
    Aggregate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeasurementSpec {
    pub schema_version: SchemaVersion,
    pub name: Option<String>,
    pub target: TargetIdentity,
    pub start_selector: String,
    pub end_selector: String,
    pub match_policy: MatchPolicy,
    pub samples: Option<u64>,
    pub duration_ms: Option<u64>,
    pub timeout_ms: u64,
    #[serde(default)]
    pub max_events: Option<u64>,
    #[serde(default)]
    pub measurement_mode: MeasurementMode,
    #[serde(default)]
    pub max_groups: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Completed,
    TimedOut,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeasurementResult {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub session_id: String,
    pub status: SessionStatus,
    pub measurement: Measurement,
    pub correlation: CorrelationSummary,
    pub clock: ClockQuality,
    pub collection: CollectionSummary,
    pub evidence: Vec<MatchedEventPair>,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatchedEventPair {
    pub start: Event,
    pub end: Event,
    pub latency_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Measurement {
    pub name: Option<String>,
    pub samples: SampleSummary,
    pub latency_ns: LatencyStatistics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SampleSummary {
    pub matched: u64,
    pub unmatched_start: u64,
    pub unmatched_end: u64,
    pub ambiguous: u64,
    pub dropped: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LatencyStatistics {
    pub min: u64,
    pub mean: f64,
    pub p50: u64,
    pub p90: u64,
    pub p95: u64,
    pub p99: u64,
    pub max: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationConfidence {
    Exact,
    High,
    Heuristic,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorrelationSummary {
    pub method: String,
    pub confidence: CorrelationConfidence,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClockQuality {
    pub alignment: String,
    pub estimated_error_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectionSummary {
    pub completeness: CaptureCompleteness,
    pub host_events: u64,
    pub cuda_events: u64,
    pub dropped_events: u64,
    pub cupti: Option<CuptiCollectionSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaptureCompleteness {
    Complete,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CuptiCollectionSummary {
    pub record_capacity: u64,
    pub observed_records: u64,
    pub retained_records: u64,
    pub dropped_records: u64,
    pub buffer_utilization: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AggregateInventoryResult {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub session_id: String,
    pub status: SessionStatus,
    pub inventory: AggregateInventory,
    pub collection: AggregateCollectionSummary,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AggregateInventory {
    pub name: Option<String>,
    pub start_selector: String,
    pub end_selector: String,
    pub groups: Vec<AggregateGroup>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AggregateGroup {
    pub activity: AggregateActivity,
    pub name: Option<String>,
    pub device_id: Option<u32>,
    pub memcpy_kind: Option<crate::MemcpyKind>,
    pub start_selector_hint: String,
    pub end_selector_hint: String,
    pub count: u64,
    pub duration_ns: AggregateDuration,
    pub total_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AggregateActivity {
    Kernel,
    Memcpy,
    Memset,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AggregateDuration {
    pub min: u64,
    pub mean: f64,
    pub max: u64,
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AggregateCollectionSummary {
    pub completeness: CaptureCompleteness,
    pub observed_activities: u64,
    pub grouped_activities: u64,
    pub dropped_activities: u64,
    pub group_capacity: u64,
    pub groups: u64,
    pub occupied_slots: u64,
    pub table_utilization: f64,
}
