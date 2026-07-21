use schemars::{Schema, schema_for};

use crate::{
    CapabilityReport, DiscoveryResult, ErrorResponse, Event, HostCaptureResult, MeasurementResult,
    MeasurementSpec, ProcessReport, ResolvedProbe, TraceExportResult, ValidationResult,
};

#[must_use]
pub fn generated_schemas() -> [(&'static str, Schema); 11] {
    [
        ("event.schema.json", schema_for!(Event)),
        ("error.schema.json", schema_for!(ErrorResponse)),
        ("measurement-spec.schema.json", schema_for!(MeasurementSpec)),
        (
            "measurement-result.schema.json",
            schema_for!(MeasurementResult),
        ),
        ("capability.schema.json", schema_for!(CapabilityReport)),
        ("discover.schema.json", schema_for!(DiscoveryResult)),
        ("inspect.schema.json", schema_for!(ProcessReport)),
        ("host-capture.schema.json", schema_for!(HostCaptureResult)),
        ("resolve.schema.json", schema_for!(ResolvedProbe)),
        ("validate.schema.json", schema_for!(ValidationResult)),
        ("trace-export.schema.json", schema_for!(TraceExportResult)),
    ]
}
