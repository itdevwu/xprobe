use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Capabilities, CheckResult, SchemaVersion, TargetIdentity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessCredentials {
    pub real_uid: u32,
    pub effective_uid: u32,
    pub saved_uid: u32,
    pub filesystem_uid: u32,
    pub real_gid: u32,
    pub effective_gid: u32,
    pub saved_gid: u32,
    pub filesystem_gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CgroupEntry {
    pub hierarchy_id: u32,
    pub controllers: Vec<String>,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessCudaState {
    pub libcuda_loaded: bool,
    pub libcudart_loaded: bool,
    pub xprobe_cupti_loaded: bool,
    pub context: CheckResult,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessReport {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub target: TargetIdentity,
    pub executable: String,
    pub command_line: Vec<String>,
    pub credentials: ProcessCredentials,
    pub namespace_pids: Vec<u32>,
    pub mount_namespace: String,
    pub cgroups: Vec<CgroupEntry>,
    pub loaded_libraries: Vec<String>,
    pub cuda: ProcessCudaState,
    pub capabilities: Capabilities,
}
