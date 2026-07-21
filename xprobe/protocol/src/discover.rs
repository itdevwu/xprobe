use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{EndpointSource, EventType, SchemaVersion, TargetIdentity, Warning};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryOrigin {
    ElfSymbol,
    CudaApiSymbol,
    CuptiActivity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredEvent {
    pub selector: String,
    pub source: EndpointSource,
    pub event_type: EventType,
    pub origin: DiscoveryOrigin,
    pub binary_path: Option<String>,
    pub symbol: Option<String>,
    pub requires_observation: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryResult {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub target: TargetIdentity,
    pub query: Option<String>,
    pub limit: u64,
    pub total_matches: u64,
    pub truncated: bool,
    pub events: Vec<DiscoveredEvent>,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}
