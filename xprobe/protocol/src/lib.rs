//! Versioned public data contracts shared by all xprobe components.

mod capability;
mod capture;
mod discover;
mod error;
mod event;
mod export;
mod measurement;
mod process;
mod resolve;
pub mod schema;
mod validate;
mod version;

pub use capability::{
    Capabilities, CapabilityReport, CheckResult, CheckStatus, Environment, SystemChecks, Warning,
};
pub use capture::HostCaptureResult;
pub use discover::{DiscoveredEvent, DiscoveryOrigin, DiscoveryResult};
pub use error::{ErrorCode, ErrorResponse, XprobeError};
pub use event::{
    ArgumentValue, ClockDomain, CudaEvent, Dim3, Event, EventSource, EventType, HostEvent,
    HostProbeKind, MemcpyKind,
};
pub use export::{ExportFormat, TraceExportResult};
pub use measurement::{
    ClockQuality, CollectionSummary, CorrelationConfidence, CorrelationSummary, LatencyStatistics,
    MatchPolicy, Measurement, MeasurementResult, MeasurementSpec, SampleSummary, SessionStatus,
    TargetIdentity,
};
pub use process::{CgroupEntry, ProcessCredentials, ProcessCudaState, ProcessReport};
pub use resolve::{ElfObjectKind, ProcessMapping, ResolvedProbe};
pub use validate::{
    AgentActivation, EndpointSource, ResolvedCudaSelector, ValidatedEndpoint, ValidationIssue,
    ValidationRequirements, ValidationResult,
};
pub use version::SchemaVersion;

pub const SCHEMA_VERSION: &str = "1.0";
