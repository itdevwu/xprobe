use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SchemaVersion {
    #[serde(rename = "1.0")]
    V1,
}

impl SchemaVersion {
    #[must_use]
    pub const fn current() -> Self {
        Self::V1
    }
}
