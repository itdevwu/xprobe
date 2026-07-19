use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Event, SchemaVersion, TargetIdentity};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostCaptureResult {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub session_id: String,
    pub target: TargetIdentity,
    pub probe_id: u32,
    pub captured: u64,
    pub dropped: u64,
    pub timed_out: bool,
    pub events: Vec<Event>,
}
