use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ErrorCode, EventType, MatchPolicy, MemcpyKind, ResolvedProbe, SchemaVersion, TargetIdentity,
    Warning,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EndpointSource {
    Host,
    Cuda,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentActivation {
    NotRequired,
    AlreadyLoaded,
    InjectionRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolvedCudaSelector {
    pub event_type: EventType,
    pub api_domain: Option<String>,
    pub api_name: Option<String>,
    pub kernel_name_regex: Option<String>,
    pub memcpy_kind: Option<MemcpyKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidatedEndpoint {
    pub selector: String,
    pub source: EndpointSource,
    pub event_type: EventType,
    pub collectable: bool,
    pub host: Option<ResolvedProbe>,
    pub cuda: Option<ResolvedCudaSelector>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ValidationRequirements {
    pub needs_ebpf: bool,
    pub needs_cupti: bool,
    pub needs_cupti_callback: bool,
    pub needs_cupti_activity: bool,
    pub needs_clock_alignment: bool,
    pub agent_activation: AgentActivation,
    pub target_mutation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidationIssue {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRecommendationReason {
    DeterministicCorrelationKey,
    HostCallFrame,
    CudaStreamOrder,
    TemporalOrderOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyRecommendation {
    pub policy: MatchPolicy,
    pub reason: PolicyRecommendationReason,
    pub compatible_policies: Vec<MatchPolicy>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidationResult {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub valid: bool,
    pub target: TargetIdentity,
    pub start: ValidatedEndpoint,
    pub end: ValidatedEndpoint,
    pub match_policy: MatchPolicy,
    pub policy_recommendation: PolicyRecommendation,
    pub requirements: ValidationRequirements,
    #[serde(default)]
    pub issues: Vec<ValidationIssue>,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}
