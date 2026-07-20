use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::SchemaVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Jsonl,
    Chrome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceExportResult {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub format: ExportFormat,
    pub output: String,
    pub event_count: u64,
}
