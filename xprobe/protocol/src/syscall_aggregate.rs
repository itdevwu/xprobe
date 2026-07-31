use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AggregateDuration, CheckResult, SchemaVersion, SessionStatus, TargetIdentity, ValidationIssue,
    Warning,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SyscallAggregateSpec {
    pub schema_version: SchemaVersion,
    pub name: Option<String>,
    pub target: TargetIdentity,
    pub duration_ms: u64,
    pub timeout_ms: u64,
    pub max_groups: u64,
    pub max_inflight: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SyscallAggregateGroup {
    pub syscall_number: u32,
    pub syscall_name: Option<String>,
    pub count: u64,
    pub errors: u64,
    pub duration_ns: AggregateDuration,
    pub entry_selector_hint: Option<String>,
    pub exit_selector_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SyscallAggregateInventory {
    pub name: Option<String>,
    pub duration_ms: u64,
    pub groups: Vec<SyscallAggregateGroup>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SyscallAggregateCompleteness {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SyscallAggregateCollectionSummary {
    pub completeness: SyscallAggregateCompleteness,
    pub observed_entries: u64,
    pub matched_exits: u64,
    pub unmatched_exits: u64,
    pub inflight_at_end: u64,
    pub dropped_aggregates: u64,
    pub group_capacity: u64,
    pub groups: u64,
    pub table_utilization: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SyscallAggregateResult {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub session_id: String,
    pub status: SessionStatus,
    pub target: TargetIdentity,
    pub inventory: SyscallAggregateInventory,
    pub collection: SyscallAggregateCollectionSummary,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SyscallAggregateRequirements {
    pub needs_ebpf: bool,
    pub target_mutation: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SyscallAggregateValidationResult {
    pub schema_version: SchemaVersion,
    pub ok: bool,
    pub valid: bool,
    pub target: TargetIdentity,
    pub requirements: SyscallAggregateRequirements,
    pub ebpf: CheckResult,
    #[serde(default)]
    pub issues: Vec<ValidationIssue>,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}
