use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{HostProbeKind, SchemaVersion, TargetIdentity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ElfObjectKind {
    Executable,
    PositionIndependentExecutable,
    SharedLibrary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessMapping {
    pub start_address: u64,
    pub end_address: u64,
    pub file_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolvedProbe {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub target: TargetIdentity,
    pub selector: String,
    pub binary_path: String,
    pub build_id: Option<String>,
    pub object_kind: ElfObjectKind,
    pub probe_kind: HostProbeKind,
    pub symbol: Option<String>,
    pub symbol_virtual_address: Option<u64>,
    pub symbol_size: Option<u64>,
    pub file_offset: u64,
    pub runtime_address: u64,
    pub mapping: ProcessMapping,
}
