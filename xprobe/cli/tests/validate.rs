use std::process::Command;

use xprobe_protocol::{
    AgentActivation, CheckStatus, CpuSamplingValidationResult, ErrorCode, ErrorResponse,
    MatchPolicy, PythonSymbolizationStatus, SyscallAggregateValidationResult, ValidationResult,
};

#[test]
fn validate_reports_environment_requirements_without_attaching() {
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "validate",
            "--pid",
            &std::process::id().to_string(),
            "--from",
            "cuda:runtime_api:cudaLaunchKernel:exit",
            "--to",
            "cuda:kernel_start:name~test.*",
            "--match",
            "exact",
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .output()
        .expect("xprobe validate must run");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
    let result: ValidationResult =
        serde_json::from_slice(&output.stdout).expect("stdout must contain validation JSON");
    assert_eq!(result.match_policy, MatchPolicy::Exact);
    assert_eq!(result.policy_recommendation.policy, MatchPolicy::Exact);
    assert!(
        result
            .policy_recommendation
            .compatible_policies
            .contains(&MatchPolicy::FirstAfter)
    );
    assert!(result.requirements.needs_cupti);
    assert!(result.requirements.needs_cupti_callback);
    assert!(result.requirements.needs_cupti_activity);
    assert!(result.requirements.needs_clock_alignment);
    assert_eq!(
        result.requirements.agent_activation,
        AgentActivation::InjectionRequired
    );
    assert!(result.requirements.target_mutation);
    assert_eq!(
        result.issues,
        Vec::<xprobe_protocol::ValidationIssue>::new()
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.code == "TARGET_PROCESS_WILL_BE_MODIFIED")
    );
}

#[test]
fn validate_rejects_an_invalid_kernel_regex() {
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "validate",
            "--pid",
            &std::process::id().to_string(),
            "--from",
            "cuda:runtime_api:cudaLaunchKernel:exit",
            "--to",
            "cuda:kernel_start:name~[",
            "--match",
            "exact",
            "--json",
        ])
        .output()
        .expect("xprobe validate must run");

    assert_eq!(output.status.code(), Some(1));
    let error: ErrorResponse =
        serde_json::from_slice(&output.stdout).expect("stdout must contain error JSON");
    assert_eq!(error.error.code, ErrorCode::InvalidEventSelector);
}

#[test]
fn validate_accepts_pid_scoped_cpu_sampling_without_ebpf() {
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "validate",
            "--pid",
            &std::process::id().to_string(),
            "--cpu-sample",
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .output()
        .expect("xprobe validate must run");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
    let result: CpuSamplingValidationResult =
        serde_json::from_slice(&output.stdout).expect("stdout must contain validation JSON");
    assert_eq!(result.valid, result.issues.is_empty());
    if result.perf_event.status == CheckStatus::Available {
        assert!(result.valid);
    } else {
        assert!(!result.valid);
        assert_eq!(result.issues.len(), 1);
        assert_eq!(result.issues[0].code, ErrorCode::PermissionDenied);
    }
    assert!(result.requirements.needs_perf_event);
    assert!(!result.requirements.target_mutation);
    assert!(result.target_threads >= 1);
    assert_eq!(result.python_status, PythonSymbolizationStatus::NotDetected);
}

#[test]
fn validate_reports_syscall_aggregate_ebpf_requirements() {
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "validate",
            "--pid",
            &std::process::id().to_string(),
            "--syscall-aggregate",
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .output()
        .expect("xprobe validate must run");

    assert!(output.status.success());
    let result: SyscallAggregateValidationResult =
        serde_json::from_slice(&output.stdout).expect("stdout must contain validation JSON");
    assert!(result.requirements.needs_ebpf);
    assert!(!result.requirements.target_mutation);
    assert_eq!(result.valid, result.issues.is_empty());
}

fn own_start_time() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").expect("own stat is readable");
    stat[stat.rfind(')').expect("stat has a command") + 1..]
        .split_whitespace()
        .nth(19)
        .expect("stat has a start time")
        .parse()
        .expect("start time is an integer")
}

fn validate_graph(graph: &serde_json::Value) -> std::process::Output {
    let path = std::env::temp_dir().join(format!(
        "xprobe-graph-{}-{}.json",
        std::process::id(),
        graph["name"].as_str().unwrap_or("graph")
    ));
    std::fs::write(&path, serde_json::to_vec(graph).unwrap()).expect("graph fixture is written");
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args(["validate", "--spec", path.to_str().unwrap()])
        .output()
        .expect("xprobe validate must run");
    std::fs::remove_file(path).expect("graph fixture is removed");
    output
}

fn graph(name: &str, edges: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schema_version": "3.0",
        "name": name,
        "target": {"pid": std::process::id(), "process_start_time": own_start_time()},
        "endpoints": {
            "launch_exit": "cuda:runtime_api:cudaLaunchKernel:exit",
            "kernel_start": "cuda:kernel_start",
            "kernel_end": "cuda:kernel_end"
        },
        "edges": edges,
        "duration_ms": null,
        "timeout_ms": 1000,
        "max_events": null
    })
}

#[test]
fn validates_a_cuda_graph_with_merged_requirements() {
    let output = validate_graph(&graph(
        "valid",
        &serde_json::json!([
            {"name": "launch", "from": "launch_exit", "to": "kernel_start", "match_policy": "exact", "samples": 5},
            {"name": "kernel", "from": "kernel_start", "to": "kernel_end", "match_policy": "exact", "samples": 5}
        ]),
    ));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: xprobe_protocol::MeasurementGraphValidationResult =
        serde_json::from_slice(&output.stdout).expect("stdout is graph validation JSON");
    assert_eq!(result.issues, Vec::new());
    assert!(result.valid);
    assert_eq!(
        result
            .endpoints
            .iter()
            .map(|endpoint| endpoint.name.as_str())
            .collect::<Vec<_>>(),
        ["kernel_end", "kernel_start", "launch_exit"]
    );
    assert!(result.requirements.needs_cupti_callback);
    assert!(result.requirements.needs_cupti_activity);
    assert_eq!(
        result.requirements.agent_activation,
        AgentActivation::InjectionRequired
    );
}

#[test]
fn reports_scoped_graph_issues_without_failing() {
    let output = validate_graph(&graph(
        "invalid",
        &serde_json::json!([
            {"name": "launch", "from": "launch_exit", "to": "missing", "match_policy": "exact", "samples": null}
        ]),
    ));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: xprobe_protocol::MeasurementGraphValidationResult =
        serde_json::from_slice(&output.stdout).expect("stdout is graph validation JSON");
    assert!(!result.valid);
    let issues = result
        .issues
        .iter()
        .map(|issue| (issue.scope, issue.name.as_deref(), issue.message.as_str()))
        .collect::<Vec<_>>();
    assert!(issues.contains(&(
        xprobe_protocol::GraphIssueScope::Edge,
        Some("launch"),
        "edge references unknown endpoint \"missing\""
    )));
    assert!(issues.iter().any(|(scope, name, _)| {
        *scope == xprobe_protocol::GraphIssueScope::Endpoint && *name == Some("kernel_end")
    }));
    assert!(
        issues
            .iter()
            .any(|(_, _, message)| message.contains("bounded"))
    );
}
