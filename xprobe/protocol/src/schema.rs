use schemars::{Schema, schema_for};

use crate::{
    CapabilityReport, ErrorResponse, Event, HostCaptureResult, MeasurementResult, MeasurementSpec,
    ProcessReport, ResolvedProbe,
};

#[must_use]
pub fn generated_schemas() -> [(&'static str, Schema); 8] {
    [
        ("event.schema.json", schema_for!(Event)),
        ("error.schema.json", schema_for!(ErrorResponse)),
        ("measurement-spec.schema.json", schema_for!(MeasurementSpec)),
        (
            "measurement-result.schema.json",
            schema_for!(MeasurementResult),
        ),
        ("capability.schema.json", schema_for!(CapabilityReport)),
        ("inspect.schema.json", schema_for!(ProcessReport)),
        ("host-capture.schema.json", schema_for!(HostCaptureResult)),
        ("resolve.schema.json", schema_for!(ResolvedProbe)),
    ]
}
