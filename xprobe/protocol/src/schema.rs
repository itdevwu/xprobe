use schemars::{Schema, schema_for};

use crate::{
    AggregateInventoryResult, CapabilityReport, CpuSampleInventoryResult, CpuSamplingSpec,
    CpuSamplingValidationResult, DiscoveryResult, ErrorResponse, Event, HostCaptureResult,
    MeasurementGraphResult, MeasurementGraphSpec, MeasurementGraphValidationResult,
    MeasurementResult, MeasurementSpec, ProcessReport, ResolvedProbe, SyscallAggregateResult,
    SyscallAggregateSpec, SyscallAggregateValidationResult, TraceExportResult, TriageResult,
    ValidationResult,
};

#[must_use]
pub fn generated_schemas() -> [(&'static str, Schema); 22] {
    [
        ("event.schema.json", schema_for!(Event)),
        ("error.schema.json", schema_for!(ErrorResponse)),
        ("measurement-spec.schema.json", schema_for!(MeasurementSpec)),
        (
            "measurement-result.schema.json",
            schema_for!(MeasurementResult),
        ),
        (
            "aggregate-inventory-result.schema.json",
            schema_for!(AggregateInventoryResult),
        ),
        (
            "cpu-sampling-spec.schema.json",
            schema_for!(CpuSamplingSpec),
        ),
        (
            "cpu-sample-inventory-result.schema.json",
            schema_for!(CpuSampleInventoryResult),
        ),
        (
            "cpu-sampling-validate.schema.json",
            schema_for!(CpuSamplingValidationResult),
        ),
        (
            "syscall-aggregate-spec.schema.json",
            schema_for!(SyscallAggregateSpec),
        ),
        (
            "syscall-aggregate-result.schema.json",
            schema_for!(SyscallAggregateResult),
        ),
        (
            "syscall-aggregate-validate.schema.json",
            schema_for!(SyscallAggregateValidationResult),
        ),
        ("capability.schema.json", schema_for!(CapabilityReport)),
        ("discover.schema.json", schema_for!(DiscoveryResult)),
        ("inspect.schema.json", schema_for!(ProcessReport)),
        ("host-capture.schema.json", schema_for!(HostCaptureResult)),
        ("resolve.schema.json", schema_for!(ResolvedProbe)),
        ("validate.schema.json", schema_for!(ValidationResult)),
        ("trace-export.schema.json", schema_for!(TraceExportResult)),
        ("triage-result.schema.json", schema_for!(TriageResult)),
        (
            "measurement-graph-spec.schema.json",
            schema_for!(MeasurementGraphSpec),
        ),
        (
            "measurement-graph-validate.schema.json",
            schema_for!(MeasurementGraphValidationResult),
        ),
        (
            "measurement-graph-result.schema.json",
            schema_for!(MeasurementGraphResult),
        ),
    ]
}
