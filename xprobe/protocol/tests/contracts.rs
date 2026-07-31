use std::{fs, path::PathBuf};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use xprobe_protocol::{
    AggregateInventoryResult, CapabilityReport, CpuSampleInventoryResult, CpuSamplingSpec,
    CpuSamplingValidationResult, DiscoveryResult, ErrorResponse, Event, HostCaptureResult,
    MeasurementResult, MeasurementSpec, ProcessReport, ResolvedLinuxSelector, ResolvedProbe,
    SyscallAggregateResult, SyscallAggregateSpec, SyscallAggregateValidationResult,
    TraceExportResult, ValidationResult, schema::generated_schemas,
};

fn assert_round_trip<T>(fixture: &Value)
where
    T: DeserializeOwned + Serialize,
{
    let parsed: T = serde_json::from_value(fixture.clone()).expect("fixture must deserialize");
    let serialized = serde_json::to_value(parsed).expect("contract must serialize");
    assert_eq!(&serialized, fixture);
}

#[test]
fn event_contract_round_trips() {
    assert_round_trip::<Event>(&json!({
        "schema_version": "2.0",
        "session_id": "xp_test",
        "event_id": "evt_1",
        "sequence": 1,
        "source": "ebpf",
        "event_type": "host_function_entry",
        "pid": 1234,
        "tid": 1234,
        "cpu": 3,
        "timestamp_raw": 1000,
        "timestamp_ns": 1000,
        "clock_domain": "host_monotonic",
        "timestamp_error_ns": 50,
        "process_start_time": 42,
        "host": {
            "probe_kind": "uprobe",
            "binary_path": "/srv/app",
            "build_id": null,
            "symbol": "handle_request",
            "symbol_demangled": null,
            "offset": 4096,
            "return_value": null,
            "arguments": []
        },
        "cuda": null,
        "nvtx": null,
        "attributes": {}
    }));
}

#[test]
fn host_capture_contract_round_trips() {
    assert_round_trip::<HostCaptureResult>(&json!({
        "schema_version": "2.0",
        "ok": true,
        "session_id": "xp_uprobe_1234_1000",
        "target": {"pid": 1234, "process_start_time": 42},
        "probe_id": 7,
        "captured": 1,
        "dropped": 0,
        "timed_out": false,
        "record_limit_reached": false,
        "events": [{
            "schema_version": "2.0",
            "session_id": "xp_uprobe_1234_1000",
            "event_id": "evt_1",
            "sequence": 1,
            "source": "ebpf",
            "event_type": "host_function_entry",
            "pid": 1234,
            "tid": 1234,
            "cpu": 3,
            "timestamp_raw": 1000,
            "timestamp_ns": 1000,
            "clock_domain": "host_monotonic",
            "timestamp_error_ns": null,
            "process_start_time": 42,
            "host": {
                "probe_kind": "uprobe",
                "binary_path": "/srv/app",
                "build_id": null,
                "symbol": "handle_request",
                "symbol_demangled": null,
                "offset": null,
                "return_value": null,
                "arguments": []
            },
            "cuda": null,
            "nvtx": null,
            "attributes": {}
        }]
    }));
}

#[test]
fn discovery_contract_round_trips() {
    assert_round_trip::<DiscoveryResult>(&json!({
        "schema_version": "2.0",
        "ok": true,
        "root": {"pid": 1234, "process_start_time": 42},
        "limit": 10,
        "total_candidates": 1,
        "truncated": false,
        "candidates": [{
            "target": {"pid": 1240, "process_start_time": 44},
            "parent_pid": 1234,
            "executable": "/srv/worker",
            "command_line": ["/srv/worker", "--rank", "0"],
            "gpu_uuids": ["GPU-test"]
        }],
        "warnings": []
    }));
}

#[test]
fn error_contract_round_trips() {
    assert_round_trip::<ErrorResponse>(&json!({
        "schema_version": "2.0",
        "ok": false,
        "error": {
            "code": "SYMBOL_NOT_FOUND",
            "message": "The requested symbol was not found.",
            "recoverable": true,
            "details": {"symbol": "handle_request"},
            "hints": ["Run xprobe discover symbols."]
        }
    }));
}

#[test]
fn capability_contract_round_trips() {
    assert_round_trip::<CapabilityReport>(&json!({
        "schema_version": "2.0",
        "ok": true,
        "capabilities": {
            "uprobe": true,
            "uretprobe": true,
            "tracepoint": true,
            "cuda_callback": false,
            "cuda_activity": false,
            "runtime_injection": false
        },
        "environment": {
            "operating_system": "linux",
            "architecture": "x86_64",
            "kernel_release": "6.8.0",
            "effective_uid": 1000,
            "container": null,
            "pid_namespace": "4026531836"
        },
        "checks": {
            "btf": {"status": "available", "detail": "/sys/kernel/btf/vmlinux"},
            "ebpf_permissions": {"status": "restricted", "detail": "missing CAP_BPF"},
            "kernel_lockdown": {"status": "unknown", "detail": null},
            "perf_event_paranoid": {"status": "restricted", "detail": "4"},
            "ptrace_scope": {"status": "restricted", "detail": "1"},
            "nvidia_driver": {"status": "unavailable", "detail": null},
            "cuda_driver": {"status": "unavailable", "detail": null},
            "cuda_toolkit": {"status": "unavailable", "detail": null},
            "cupti": {"status": "unavailable", "detail": null}
        },
        "warnings": []
    }));
}

#[test]
fn measurement_spec_contract_round_trips() {
    assert_round_trip::<MeasurementSpec>(&json!({
        "schema_version": "2.0",
        "name": "request_to_kernel",
        "target": {"pid": 1234, "process_start_time": 42},
        "start_selector": "uprobe:/srv/app:handle_request:entry",
        "end_selector": "cuda:kernel_start:name~flash.*",
        "match_policy": "first_after",
        "samples": 100,
        "duration_ms": null,
        "timeout_ms": 30_000,
        "max_events": 100_000,
        "measurement_mode": "exact",
        "max_groups": null
    }));
}

#[test]
fn aggregate_inventory_contract_round_trips() {
    assert_round_trip::<AggregateInventoryResult>(&json!({
        "schema_version": "2.0",
        "ok": true,
        "session_id": "xp_inventory",
        "status": "completed",
        "inventory": {
            "name": "kernel_inventory",
            "start_selector": "cuda:kernel_start",
            "end_selector": "cuda:kernel_end",
            "groups": [{
                "activity": "kernel",
                "name": "vector_add",
                "name_complete": true,
                "device_id": 0,
                "memcpy_kind": null,
                "start_selector_hint": "cuda:kernel_start:name~^vector_add$",
                "end_selector_hint": "cuda:kernel_end:name~^vector_add$",
                "count": 10,
                "duration_ns": {
                    "min": 1000,
                    "mean": 1500.0,
                    "max": 2000,
                    "total": 15000
                },
                "total_bytes": null
            }]
        },
        "collection": {
            "completeness": "complete",
            "observed_activities": 10,
            "grouped_activities": 10,
            "dropped_activities": 0,
            "group_capacity": 4096,
            "groups": 1,
            "occupied_slots": 1,
            "table_utilization": 0.000_244_140_625
        },
        "warnings": []
    }));
}

#[test]
fn cpu_sampling_spec_contract_round_trips() {
    assert_round_trip::<CpuSamplingSpec>(&json!({
        "schema_version": "2.0",
        "name": "cpu_inventory",
        "target": {"pid": 1234, "process_start_time": 42},
        "sample_event": "cpu_clock",
        "frequency_hz": 99,
        "duration_ms": 1000,
        "timeout_ms": 30000,
        "max_samples": 10000,
        "max_groups": 4096,
        "stack_depth": 64,
        "max_threads": 1024
    }));
}

#[test]
fn cpu_sample_inventory_contract_round_trips() {
    let frame = json!({
        "address": 4_198_400,
        "module_path": "/srv/app",
        "build_id": "abcd",
        "file_offset": 4096,
        "symbol": "handle_request",
        "symbol_offset": 0,
        "language": "native",
        "source_path": null,
        "line": null
    });
    assert_round_trip::<CpuSampleInventoryResult>(&json!({
        "schema_version": "2.0",
        "ok": true,
        "session_id": "xp_cpu_inventory",
        "status": "completed",
        "target": {"pid": 1234, "process_start_time": 42},
        "inventory": {
            "name": "cpu_inventory",
            "sample_event": "cpu_clock",
            "frequency_hz": 99,
            "duration_ms": 1000,
            "stack_groups": [{
                "frames": [frame.clone()],
                "samples": 80,
                "proportion": 0.8
            }],
            "hotspots": [{
                "frame": frame,
                "inclusive_samples": 80,
                "exclusive_samples": 60,
                "inclusive_proportion": 0.8,
                "exclusive_proportion": 0.6,
                "entry_selector_hint": "uprobe:/srv/app:handle_request:entry",
                "return_selector_hint": "uprobe:/srv/app:handle_request:return"
            }]
        },
        "collection": {
            "completeness": "complete",
            "observed_samples": 100,
            "grouped_samples": 100,
            "lost_samples": 0,
            "sample_capacity": 10000,
            "group_capacity": 4096,
            "groups": 4,
            "table_utilization": 0.000_976_562_5,
            "stack_depth": 64,
            "truncated_stacks": 0,
            "threads_observed": 8,
            "threads_attached": 8,
            "thread_capacity": 1024
        },
        "symbolization": {
            "total_frames": 20,
            "resolved_native_frames": 18,
            "resolved_python_frames": 0,
            "unresolved_frames": 2,
            "python_status": "not_detected"
        },
        "warnings": []
    }));
}

#[test]
fn cpu_sampling_validation_contract_round_trips() {
    assert_round_trip::<CpuSamplingValidationResult>(&json!({
        "schema_version": "2.0",
        "ok": true,
        "valid": true,
        "target": {"pid": 1234, "process_start_time": 42},
        "target_threads": 8,
        "requirements": {
            "needs_perf_event": true,
            "target_mutation": false
        },
        "perf_event": {"status": "available", "detail": "perf_event_paranoid=1"},
        "python_status": "inactive",
        "issues": [],
        "warnings": []
    }));
}

#[test]
fn syscall_aggregate_spec_contract_round_trips() {
    assert_round_trip::<SyscallAggregateSpec>(&json!({
        "schema_version": "2.0",
        "name": "syscalls",
        "target": {"pid": 1234, "process_start_time": 42},
        "duration_ms": 1000,
        "timeout_ms": 30000,
        "max_groups": 256,
        "max_inflight": 1024
    }));
}

#[test]
fn syscall_aggregate_result_contract_round_trips() {
    assert_round_trip::<SyscallAggregateResult>(&json!({
        "schema_version": "2.0",
        "ok": true,
        "session_id": "xp_syscalls",
        "status": "completed",
        "target": {"pid": 1234, "process_start_time": 42},
        "inventory": {
            "name": "syscalls",
            "duration_ms": 1000,
            "groups": [{
                "syscall_number": 202,
                "syscall_name": "futex",
                "count": 80,
                "errors": 2,
                "duration_ns": {"min": 100, "mean": 250.0, "max": 1000, "total": 20000},
                "entry_selector_hint": "syscall:futex:entry",
                "exit_selector_hint": "syscall:futex:exit"
            }]
        },
        "collection": {
            "completeness": "complete",
            "observed_entries": 100,
            "matched_exits": 100,
            "unmatched_exits": 0,
            "inflight_at_end": 0,
            "dropped_aggregates": 0,
            "group_capacity": 256,
            "groups": 8,
            "table_utilization": 0.03125
        },
        "warnings": []
    }));
}

#[test]
fn syscall_aggregate_validation_contract_round_trips() {
    assert_round_trip::<SyscallAggregateValidationResult>(&json!({
        "schema_version": "2.0",
        "ok": true,
        "valid": true,
        "target": {"pid": 1234, "process_start_time": 42},
        "requirements": {"needs_ebpf": true, "target_mutation": false},
        "ebpf": {"status": "available", "detail": "CAP_BPF and CAP_PERFMON"},
        "issues": [],
        "warnings": []
    }));
}

#[test]
fn trace_export_contract_round_trips() {
    assert_round_trip::<TraceExportResult>(&json!({
        "schema_version": "2.0",
        "ok": true,
        "format": "chrome",
        "output": "/tmp/xprobe-trace.json",
        "event_count": 42
    }));
}

#[test]
fn measurement_result_contract_round_trips() {
    assert_round_trip::<MeasurementResult>(&json!({
        "schema_version": "2.0",
        "ok": true,
        "session_id": "xp_test",
        "status": "completed",
        "measurement": {
            "name": "request_to_kernel",
            "samples": {
                "matched": 1,
                "unmatched_start": 0,
                "unmatched_end": 0,
                "ambiguous": 0,
                "dropped": 0
            },
            "latency_ns": {
                "min": 13_000,
                "mean": 13_000.0,
                "p50": 13_000,
                "p90": 13_000,
                "p95": 13_000,
                "p99": 13_000,
                "max": 13_000
            }
        },
        "correlation": {
            "method": "first_after",
            "confidence": "heuristic",
            "score": 0.7
        },
        "clock": {
            "alignment": "cupti_normalized_to_host_monotonic",
            "estimated_error_ns": 2500
        },
        "collection": {
            "completeness": "complete",
            "host_events": 1,
            "cuda_events": 1,
            "dropped_events": 0,
            "cupti": null
        },
        "evidence": [],
        "warnings": []
    }));
}

#[test]
fn process_report_contract_round_trips() {
    assert_round_trip::<ProcessReport>(&json!({
        "schema_version": "2.0",
        "ok": true,
        "target": {"pid": 1234, "process_start_time": 42},
        "executable": "/srv/app/server",
        "command_line": ["/srv/app/server", "--port", "8080"],
        "credentials": {
            "real_uid": 1000,
            "effective_uid": 1000,
            "saved_uid": 1000,
            "filesystem_uid": 1000,
            "real_gid": 1000,
            "effective_gid": 1000,
            "saved_gid": 1000,
            "filesystem_gid": 1000
        },
        "namespace_pids": [1234, 17],
        "mount_namespace": "mnt:[4026531841]",
        "cgroups": [{
            "hierarchy_id": 0,
            "controllers": [],
            "path": "/user.slice/user-1000.slice/session-1.scope"
        }],
        "loaded_libraries": ["/usr/lib/libcuda.so.1"],
        "cuda": {
            "libcuda_loaded": true,
            "libcudart_loaded": false,
            "xprobe_cupti_loaded": false,
            "context": {
                "status": "unknown",
                "detail": "CUDA context state is not externally observable"
            }
        },
        "capabilities": {
            "uprobe": true,
            "uretprobe": true,
            "tracepoint": true,
            "cuda_callback": false,
            "cuda_activity": false,
            "runtime_injection": false
        }
    }));
}

#[test]
fn resolved_probe_contract_round_trips() {
    assert_round_trip::<ResolvedProbe>(&json!({
        "schema_version": "2.0",
        "ok": true,
        "target": {"pid": 1234, "process_start_time": 42},
        "selector": "uprobe:/srv/app/libserver.so:handle_request:entry",
        "binary_path": "/srv/app/libserver.so",
        "build_id": "0123456789abcdef",
        "object_kind": "shared_library",
        "probe_kind": "uprobe",
        "symbol": "handle_request",
        "symbol_demangled": null,
        "symbol_virtual_address": 8192,
        "symbol_size": 32,
        "file_offset": 8192,
        "runtime_address": 140_737_488_363_520_u64,
        "mapping": {
            "start_address": 140_737_488_355_328_u64,
            "end_address": 140_737_488_420_864_u64,
            "file_offset": 0
        }
    }));
}

#[test]
fn resolved_python_usdt_contract_round_trips() {
    assert_round_trip::<ResolvedLinuxSelector>(&json!({
        "event_type": "python_gc_start",
        "probe_kind": "usdt",
        "category": "python",
        "name": "gc__start",
        "syscall_number": null,
        "binary_path": "/usr/bin/python3.12",
        "provider": "python"
    }));
}

#[test]
fn validation_result_contract_round_trips() {
    assert_round_trip::<ValidationResult>(&json!({
        "schema_version": "2.0",
        "ok": true,
        "valid": false,
        "target": {"pid": 1234, "process_start_time": 42},
        "start": {
            "selector": "cuda:runtime_api:cudaLaunchKernel:exit",
            "source": "cuda",
            "event_type": "cuda_api_exit",
            "collectable": true,
            "host": null,
            "linux": null,
            "cuda": {
                "event_type": "cuda_api_exit",
                "api_domain": "runtime_api",
                "api_name": "cudaLaunchKernel",
                "kernel_name_regex": null,
                "nvtx_name_regex": null,
                "memcpy_kind": null
            }
        },
        "end": {
            "selector": "cuda:kernel_start:name~flash.*",
            "source": "cuda",
            "event_type": "gpu_kernel_start",
            "collectable": true,
            "host": null,
            "linux": null,
            "cuda": {
                "event_type": "gpu_kernel_start",
                "api_domain": null,
                "api_name": null,
                "kernel_name_regex": "flash.*",
                "nvtx_name_regex": null,
                "memcpy_kind": null
            }
        },
        "match_policy": "exact",
        "policy_recommendation": {
            "policy": "exact",
            "reason": "deterministic_correlation_key",
            "compatible_policies": ["exact", "first_after", "nearest"]
        },
        "requirements": {
            "needs_ebpf": false,
            "needs_cupti": true,
            "needs_cupti_callback": true,
            "needs_cupti_activity": true,
            "needs_nvtx": false,
            "needs_clock_alignment": true,
            "agent_activation": "injection_required",
            "target_mutation": true
        },
        "issues": [{
            "code": "CLOCK_ALIGNMENT_FAILED",
            "message": "the capture does not declare host-monotonic CUPTI activity timestamps"
        }],
        "warnings": [{
            "code": "TARGET_PROCESS_WILL_BE_MODIFIED",
            "message": "measure must inject the xprobe CUPTI agent into the target process",
            "details": {}
        }]
    }));
}

#[test]
fn checked_in_schemas_are_current() {
    let schema_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas");

    for (file_name, schema) in generated_schemas() {
        let expected = format!(
            "{}\n",
            serde_json::to_string_pretty(&schema).expect("schema must serialize")
        );
        let actual = fs::read_to_string(schema_dir.join(file_name))
            .unwrap_or_else(|error| panic!("failed to read {file_name}: {error}"));
        assert_eq!(actual, expected, "regenerate {file_name}");
    }
}

#[test]
fn unknown_contract_fields_are_rejected() {
    let result = serde_json::from_value::<CapabilityReport>(json!({
        "schema_version": "2.0",
        "ok": true,
        "capabilities": {
            "uprobe": true,
            "uretprobe": true,
            "tracepoint": true,
            "cuda_callback": false,
            "cuda_activity": false,
            "runtime_injection": false,
            "unexpected": true
        },
        "environment": {
            "operating_system": "linux",
            "architecture": "x86_64",
            "kernel_release": "6.8.0",
            "effective_uid": 1000,
            "container": null,
            "pid_namespace": "4026531836"
        },
        "checks": {
            "btf": {"status": "available", "detail": "/sys/kernel/btf/vmlinux"},
            "ebpf_permissions": {"status": "restricted", "detail": "missing CAP_BPF"},
            "kernel_lockdown": {"status": "unknown", "detail": null},
            "perf_event_paranoid": {"status": "restricted", "detail": "4"},
            "ptrace_scope": {"status": "restricted", "detail": "1"},
            "nvidia_driver": {"status": "unavailable", "detail": null},
            "cuda_driver": {"status": "unavailable", "detail": null},
            "cuda_toolkit": {"status": "unavailable", "detail": null},
            "cupti": {"status": "unavailable", "detail": null}
        },
        "warnings": []
    }));

    assert!(result.is_err());
}

#[test]
fn unsupported_schema_versions_are_rejected() {
    let result = serde_json::from_value::<ErrorResponse>(json!({
        "schema_version": "9.9",
        "ok": false,
        "error": {
            "code": "INTERNAL",
            "message": "unsupported test fixture",
            "recoverable": false,
            "details": {},
            "hints": []
        }
    }));

    assert!(result.is_err());
}
