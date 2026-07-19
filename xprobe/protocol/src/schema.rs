use schemars::{Schema, schema_for};

use crate::{CapabilityReport, ErrorResponse, Event, MeasurementResult, MeasurementSpec};

#[must_use]
pub fn generated_schemas() -> [(&'static str, Schema); 5] {
    [
        ("event.schema.json", schema_for!(Event)),
        ("error.schema.json", schema_for!(ErrorResponse)),
        ("measurement-spec.schema.json", schema_for!(MeasurementSpec)),
        (
            "measurement-result.schema.json",
            schema_for!(MeasurementResult),
        ),
        ("capability.schema.json", schema_for!(CapabilityReport)),
    ]
}
