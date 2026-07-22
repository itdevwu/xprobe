use std::{collections::BTreeMap, fmt};

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

impl ErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::TargetNotFound => "TARGET_NOT_FOUND",
            Self::TargetExited => "TARGET_EXITED",
            Self::TargetReused => "TARGET_REUSED",
            Self::AmbiguousTarget => "AMBIGUOUS_TARGET",
            Self::SymbolNotFound => "SYMBOL_NOT_FOUND",
            Self::BinaryNotMapped => "BINARY_NOT_MAPPED",
            Self::InvalidEventSelector => "INVALID_EVENT_SELECTOR",
            Self::InvalidCorrelationPolicy => "INVALID_CORRELATION_POLICY",
            Self::CuptiNotAvailable => "CUPTI_NOT_AVAILABLE",
            Self::CuptiAgentNotLoaded => "CUPTI_AGENT_NOT_LOADED",
            Self::CudaContextNotFound => "CUDA_CONTEXT_NOT_FOUND",
            Self::UnsupportedCudaVersion => "UNSUPPORTED_CUDA_VERSION",
            Self::EventRateTooHigh => "EVENT_RATE_TOO_HIGH",
            Self::SessionLimitExceeded => "SESSION_LIMIT_EXCEEDED",
            Self::NoMatchedSamples => "NO_MATCHED_SAMPLES",
            Self::HighUnmatchedRate => "HIGH_UNMATCHED_RATE",
            Self::EventsDropped => "EVENTS_DROPPED",
            Self::ClockAlignmentFailed => "CLOCK_ALIGNMENT_FAILED",
            Self::TraceExportFailed => "TRACE_EXPORT_FAILED",
            Self::CleanupFailed => "CLEANUP_FAILED",
            Self::Internal => "INTERNAL",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
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
            schema_version: SchemaVersion::V2,
            ok: false,
            error,
        }
    }
}
