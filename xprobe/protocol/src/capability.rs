use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::SchemaVersion;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct Capabilities {
    pub uprobe: bool,
    pub uretprobe: bool,
    pub tracepoint: bool,
    pub cuda_callback: bool,
    pub cuda_activity: bool,
    pub runtime_injection: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Available,
    Restricted,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    pub status: CheckStatus,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SystemChecks {
    pub btf: CheckResult,
    pub ebpf_permissions: CheckResult,
    pub kernel_lockdown: CheckResult,
    pub perf_event_paranoid: CheckResult,
    pub ptrace_scope: CheckResult,
    pub nvidia_driver: CheckResult,
    pub cuda_driver: CheckResult,
    pub cuda_toolkit: CheckResult,
    pub cupti: CheckResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub operating_system: String,
    pub architecture: String,
    pub kernel_release: String,
    pub effective_uid: u32,
    pub container: Option<String>,
    pub pid_namespace: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Warning {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub details: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityReport {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub capabilities: Capabilities,
    pub environment: Environment,
    pub checks: SystemChecks,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}
