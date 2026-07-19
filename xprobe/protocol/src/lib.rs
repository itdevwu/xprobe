//! Versioned public data contracts shared by all xprobe components.

mod capability;
mod error;
mod event;
mod measurement;
pub mod schema;
mod version;

pub use capability::{
    Capabilities, CapabilityReport, CheckResult, CheckStatus, Environment, SystemChecks, Warning,
};
pub use error::{ErrorCode, ErrorResponse, XprobeError};
pub use event::{
    ArgumentValue, ClockDomain, CudaEvent, Dim3, Event, EventSource, EventType, HostEvent,
    HostProbeKind, MemcpyKind,
};
pub use measurement::{
    ClockQuality, CollectionSummary, CorrelationConfidence, CorrelationSummary, LatencyStatistics,
    MatchPolicy, Measurement, MeasurementResult, MeasurementSpec, SampleSummary, SessionStatus,
    TargetIdentity,
};
pub use version::SchemaVersion;

pub const SCHEMA_VERSION: &str = "1.0";
