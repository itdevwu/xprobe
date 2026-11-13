//! Versioned public data contracts shared by all xprobe components.

mod capability;
mod capture;
mod cpu_sampling;
mod discover;
mod error;
mod event;
mod export;
mod measurement;
mod process;
mod resolve;
pub mod schema;
mod syscall_aggregate;
mod triage;
mod validate;
mod version;

pub use capability::{
    Capabilities, CapabilityReport, CheckResult, CheckStatus, Environment, SystemChecks, Warning,
};
pub use capture::HostCaptureResult;
pub use cpu_sampling::{
    CpuCaptureCompleteness, CpuFrameLanguage, CpuHotspot, CpuSampleCollectionSummary,
    CpuSampleEvent, CpuSampleInventory, CpuSampleInventoryResult, CpuSamplingRequirements,
    CpuSamplingSpec, CpuSamplingValidationResult, CpuStackFrame, CpuStackGroup,
    CpuSymbolizationSummary, PythonSymbolizationStatus,
};
pub use discover::{CudaProcessCandidate, DiscoveryResult};
pub use error::{ErrorCode, ErrorResponse, XprobeError};
pub use event::{
    ArgumentValue, ClockDomain, CudaEvent, Dim3, Event, EventSource, EventType, HostEvent,
    HostProbeKind, MemcpyKind, NvtxEvent, NvtxRangeKind,
};
pub use export::{ExportFormat, TraceExportResult};
pub use measurement::{
    AggregateActivity, AggregateCollectionSummary, AggregateDuration, AggregateGroup,
    AggregateInventory, AggregateInventoryResult, CaptureCompleteness, ClockQuality,
    CollectionSummary, CorrelationConfidence, CorrelationSummary, CuptiCollectionSummary, Evidence,
    EvidenceArtifact, EvidenceExemplar, EvidenceMode, LatencyRank, LatencyStatistics, MatchPolicy,
    MatchedEventPair, Measurement, MeasurementMode, MeasurementResult, MeasurementSpec,
    QualityIssue, QualitySeverity, QualityVerdict, ResultQuality, SampleSummary, SessionStatus,
    TargetIdentity,
};
pub use process::{CgroupEntry, ProcessCredentials, ProcessCudaState, ProcessReport};
pub use resolve::{ElfObjectKind, ProcessMapping, ResolvedProbe};
pub use syscall_aggregate::{
    SyscallAggregateCollectionSummary, SyscallAggregateCompleteness, SyscallAggregateGroup,
    SyscallAggregateInventory, SyscallAggregateRequirements, SyscallAggregateResult,
    SyscallAggregateSpec, SyscallAggregateValidationResult,
};
pub use triage::{
    CgroupCpuThrottling, CgroupVersion, GpuDeviceHealth, PcieLink, ThreadTime, ThreadTimeBreakdown,
    TriageFinding, TriageNextKind, TriageNextStep, TriageResult, TriageSource, TriageSourceKind,
    TriageSourceStatus,
};
pub use validate::{
    AgentActivation, EndpointSource, PolicyRecommendation, PolicyRecommendationReason,
    ResolvedCudaSelector, ResolvedLinuxSelector, ValidatedEndpoint, ValidationIssue,
    ValidationRequirements, ValidationResult,
};
pub use version::{SchemaVersion, SchemaVersion3};

pub const SCHEMA_VERSION: &str = "2.0";
