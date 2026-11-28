//! Versioned public data contracts shared by all xprobe components.

mod capability;
mod capture;
mod cpu_sampling;
mod discover;
mod error;
mod event;
mod export;
mod graph;
mod manifest;
mod measurement;
mod process;
mod python_sampling;
mod resolve;
pub mod schema;
mod syscall_aggregate;
mod triage;
mod trigger;
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
    ActivityBoundary, ArgumentValue, CUDA_LAUNCH_APIS, CUDA_RECORD_NAME_MAX_BYTES, ClockDomain,
    CudaEvent, Dim3, Event, EventSource, EventType, HostEvent, HostProbeKind, MemcpyKind,
    MemoryKind, NvtxEvent, NvtxRangeKind, activity_boundary, is_cuda_launch_api,
};
pub use export::{ExportFormat, TraceExportResult};
pub use graph::{
    GRAPH_MAX_CUDA_FILTERS, GRAPH_MAX_EDGES, GRAPH_MAX_ENDPOINTS, GRAPH_MAX_LINUX_ENDPOINTS,
    GraphEdgeResult, GraphEdgeSpec, GraphEdgeValidation, GraphEndpointValidation, GraphIssueScope,
    GraphTarget, GraphValidationIssue, MeasurementGraphResult, MeasurementGraphSpec,
    MeasurementGraphValidationResult,
};
pub use manifest::{
    CaptureManifest, CaptureWindow, ManifestArtifact, ManifestVersion, manifest_path,
};
pub use measurement::{
    AggregateActivity, AggregateCollectionSummary, AggregateDuration, AggregateGroup,
    AggregateInventory, AggregateInventoryResult, CaptureCompleteness, CaptureCoverage,
    ClockAnchor, ClockQuality, CollectionSummary, CorrelationConfidence, CorrelationSummary,
    CoverageSource, CudaDevice, CuptiCollectionSummary, Evidence, EvidenceArtifact,
    EvidenceExemplar, EvidenceMode, LatencyRank, LatencyStatistics, MatchPolicy, MatchedEventPair,
    Measurement, MeasurementMode, MeasurementResult, MeasurementSpec, QualityIssue,
    QualitySeverity, QualityVerdict, ResultQuality, SampleSummary, SessionStatus, TargetIdentity,
    WallClock,
};
pub use process::{CgroupEntry, ProcessCredentials, ProcessCudaState, ProcessReport};
pub use python_sampling::{
    PythonFrame, PythonHotspot, PythonNativeLeaf, PythonNativeWait, PythonSampleCollection,
    PythonSampleInventory, PythonSampleRecord, PythonSampleResult, PythonStackGroup,
    PythonTidSource, ReadLatency,
};
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
pub use trigger::{
    TriggerCollection, TriggerCondition, TriggerKind, TriggerObservation, TriggerResult,
    TriggerWindow,
};
pub use validate::{
    AgentActivation, EndpointSource, PolicyRecommendation, PolicyRecommendationReason,
    ResolvedCudaSelector, ResolvedLinuxSelector, ValidatedEndpoint, ValidationIssue,
    ValidationRequirements, ValidationResult,
};
pub use version::{SchemaVersion, SchemaVersion3};

pub const SCHEMA_VERSION: &str = "2.0";
