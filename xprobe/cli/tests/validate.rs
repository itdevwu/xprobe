use std::process::Command;

use xprobe_protocol::{ErrorCode, ErrorResponse, MatchPolicy, ValidationResult};

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
    assert!(output.stderr.is_empty());
    let result: ValidationResult =
        serde_json::from_slice(&output.stdout).expect("stdout must contain validation JSON");
    assert_eq!(result.match_policy, MatchPolicy::Exact);
    assert!(result.requirements.needs_cupti);
    assert!(result.requirements.needs_cupti_callback);
    assert!(result.requirements.needs_cupti_activity);
    assert!(!result.requirements.target_mutation);
    assert!(!result.valid);
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.code == ErrorCode::CuptiAgentNotLoaded)
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
