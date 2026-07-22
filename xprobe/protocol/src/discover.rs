use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{TargetIdentity, Warning};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum DiscoverySchemaVersion {
    #[serde(rename = "2.0")]
    V2,
}

impl DiscoverySchemaVersion {
    #[must_use]
    pub const fn current() -> Self {
        Self::V2
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CudaProcessCandidate {
    pub target: TargetIdentity,
    pub parent_pid: u32,
    pub executable: String,
    pub command_line: Vec<String>,
    pub gpu_uuids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryResult {
    pub schema_version: DiscoverySchemaVersion,
    pub ok: bool,
    pub root: TargetIdentity,
    pub limit: u64,
    pub total_candidates: u64,
    pub truncated: bool,
    pub candidates: Vec<CudaProcessCandidate>,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}
