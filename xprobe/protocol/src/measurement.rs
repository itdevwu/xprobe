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
    pub max_events: u64,
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
