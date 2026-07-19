use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::SchemaVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    PermissionDenied,
    TargetNotFound,
    TargetExited,
    TargetReused,
    AmbiguousTarget,
    SymbolNotFound,
    BinaryNotMapped,
    InvalidEventSelector,
    InvalidCorrelationPolicy,
    CuptiNotAvailable,
    CuptiAgentNotLoaded,
    CudaContextNotFound,
    UnsupportedCudaVersion,
    EventRateTooHigh,
    SessionLimitExceeded,
    NoMatchedSamples,
    HighUnmatchedRate,
    EventsDropped,
    ClockAlignmentFailed,
    TraceExportFailed,
    CleanupFailed,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XprobeError {
    pub code: ErrorCode,
    pub message: String,
    pub recoverable: bool,
    #[serde(default)]
    pub details: BTreeMap<String, Value>,
    #[serde(default)]
    pub hints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub error: XprobeError,
}

impl ErrorResponse {
    #[must_use]
    pub fn new(error: XprobeError) -> Self {
        Self {
            schema_version: SchemaVersion::V1,
            ok: false,
            error,
        }
    }
}
