use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{SchemaVersion, TargetIdentity, Warning};

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
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub root: TargetIdentity,
    pub limit: u64,
    pub total_candidates: u64,
    pub truncated: bool,
    pub candidates: Vec<CudaProcessCandidate>,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}
