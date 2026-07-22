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
