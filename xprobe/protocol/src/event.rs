use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::SchemaVersion;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Ebpf,
    CuptiCallback,
    CuptiActivity,
    Marker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    HostFunctionEntry,
    HostFunctionExit,
    KernelFunctionEntry,
    KernelFunctionExit,
    Tracepoint,
    SyscallEntry,
    SyscallExit,
    CudaApiEntry,
    CudaApiExit,
    GpuKernelStart,
    GpuKernelEnd,
    GpuMemcpyStart,
    GpuMemcpyEnd,
    GpuMemsetStart,
    GpuMemsetEnd,
    NvtxRangeStart,
    NvtxRangeEnd,
    Marker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClockDomain {
    HostMonotonic,
    Cupti,
    CuptiNormalizedToHostMonotonic,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema_version: SchemaVersion,
    pub session_id: String,
    pub event_id: String,
    pub sequence: u64,
    pub source: EventSource,
    pub event_type: EventType,
    pub pid: u32,
    pub tid: u32,
    pub cpu: Option<u32>,
    pub timestamp_raw: u64,
    pub timestamp_ns: u64,
    pub clock_domain: ClockDomain,
    pub timestamp_error_ns: Option<u64>,
    pub process_start_time: Option<u64>,
    pub host: Option<HostEvent>,
    pub cuda: Option<CudaEvent>,
    #[serde(default)]
    pub nvtx: Option<NvtxEvent>,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostProbeKind {
    Uprobe,
    Uretprobe,
    Kprobe,
    Kretprobe,
    Tracepoint,
    Syscall,
    Usdt,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostEvent {
    pub probe_kind: HostProbeKind,
    pub binary_path: Option<String>,
    pub build_id: Option<String>,
    pub symbol: Option<String>,
    #[serde(default)]
    pub symbol_demangled: Option<String>,
    pub offset: Option<u64>,
    pub return_value: Option<i64>,
    #[serde(default)]
    pub arguments: Vec<ArgumentValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArgumentValue {
    pub index: u16,
    pub abi_type: String,
    pub value: Option<Value>,
    pub read_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CudaEvent {
    pub device_id: Option<u32>,
    pub context_id: Option<u32>,
    pub stream_id: Option<u64>,
    pub correlation_id: Option<u32>,
    pub runtime_correlation_id: Option<u32>,
    pub callback_domain: Option<u32>,
    pub callback_id: Option<u32>,
    pub kernel_name: Option<String>,
    pub kernel_name_mangled: Option<String>,
    pub start_ns: Option<u64>,
    pub end_ns: Option<u64>,
    pub grid: Option<Dim3>,
    pub block: Option<Dim3>,
    pub bytes: Option<u64>,
    pub memcpy_kind: Option<MemcpyKind>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NvtxRangeKind {
    Thread,
    Process,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NvtxEvent {
    pub name: String,
    pub name_complete: bool,
    pub range_kind: NvtxRangeKind,
    pub range_id: u64,
    pub start_tid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Dim3 {
    pub x: u32,
    pub y: u32,
    pub z: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum MemcpyKind {
    #[serde(rename = "HtoD")]
    HostToDevice,
    #[serde(rename = "DtoH")]
    DeviceToHost,
    #[serde(rename = "DtoD")]
    DeviceToDevice,
    #[serde(rename = "HtoH")]
    HostToHost,
    #[serde(rename = "PtoP")]
    PeerToPeer,
    #[serde(rename = "unknown")]
    Unknown,
}
