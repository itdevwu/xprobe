use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ClockQuality, CollectionSummary, CorrelationSummary, ErrorCode, Evidence, EvidenceArtifact,
    MatchPolicy, Measurement, PolicyRecommendation, ResultQuality, SchemaVersion3, SessionStatus,
    TargetIdentity, ValidatedEndpoint, ValidationRequirements, Warning,
};

/// Endpoints and edges allowed in one bounded graph capture.
pub const GRAPH_MAX_ENDPOINTS: usize = 8;
pub const GRAPH_MAX_EDGES: usize = 8;
/// Linux syscall, tracepoint, and USDT endpoints share two collector slots.
pub const GRAPH_MAX_LINUX_ENDPOINTS: usize = 2;

/// Several start/end edges measured from one bounded capture of one process.
///
/// Endpoints are named once and shared by edges. Each edge is correlated
/// independently; a graph never joins edges into per-request paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeasurementGraphSpec {
    pub schema_version: SchemaVersion3,
    pub name: Option<String>,
    pub target: TargetIdentity,
    /// Endpoint name to event selector.
    pub endpoints: BTreeMap<String, String>,
    pub edges: Vec<GraphEdgeSpec>,
    /// Stop collection after this window; required unless every edge sets
    /// `samples`.
    pub duration_ms: Option<u64>,
    pub timeout_ms: u64,
    /// Record capacity of the whole shared capture.
    pub max_events: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphEdgeSpec {
    pub name: String,
    pub from: String,
    pub to: String,
    pub match_policy: MatchPolicy,
    pub samples: Option<u64>,
}

/// Read-only validation of every endpoint and edge in a graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeasurementGraphValidationResult {
    pub schema_version: SchemaVersion3,
    pub ok: bool,
    /// True only when every endpoint and edge is valid.
    pub valid: bool,
    pub target: TargetIdentity,
    pub endpoints: Vec<GraphEndpointValidation>,
    pub edges: Vec<GraphEdgeValidation>,
    /// Requirements merged across every edge.
    pub requirements: ValidationRequirements,
    pub issues: Vec<GraphValidationIssue>,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphEndpointValidation {
    pub name: String,
    pub endpoint: ValidatedEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphEdgeValidation {
    pub name: String,
    pub from: String,
    pub to: String,
    pub match_policy: MatchPolicy,
    pub policy_recommendation: PolicyRecommendation,
}

/// An issue attached to the graph, one endpoint, or one edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphValidationIssue {
    pub scope: GraphIssueScope,
    /// Endpoint or edge name; `null` for graph-level issues.
    pub name: Option<String>,
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GraphIssueScope {
    Graph,
    Endpoint,
    Edge,
}

/// Per-edge results from one shared bounded capture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeasurementGraphResult {
    pub schema_version: SchemaVersion3,
    pub ok: bool,
    pub session_id: String,
    pub status: SessionStatus,
    pub name: Option<String>,
    pub target: TargetIdentity,
    pub edges: Vec<GraphEdgeResult>,
    /// The shared capture every edge was correlated from.
    pub collection: CollectionSummary,
    pub artifact: Option<EvidenceArtifact>,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphEdgeResult {
    pub name: String,
    pub from: String,
    pub to: String,
    pub start_selector: String,
    pub end_selector: String,
    pub measurement: Measurement,
    pub quality: ResultQuality,
    pub correlation: CorrelationSummary,
    pub clock: ClockQuality,
    /// Exemplars and optional full pairs; the artifact is graph-level.
    pub evidence: Evidence,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}
