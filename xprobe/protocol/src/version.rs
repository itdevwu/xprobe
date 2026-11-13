use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SchemaVersion {
    #[serde(rename = "2.0")]
    V2,
}

impl SchemaVersion {
    #[must_use]
    pub const fn current() -> Self {
        Self::V2
    }
}

/// Version of records whose shape changed in xprobe 0.6.
///
/// Records keep their own version so unchanged contracts, such as Event JSONL
/// artifacts, remain readable at `2.0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SchemaVersion3 {
    #[serde(rename = "3.0")]
    V3,
}

impl SchemaVersion3 {
    #[must_use]
    pub const fn current() -> Self {
        Self::V3
    }
}
