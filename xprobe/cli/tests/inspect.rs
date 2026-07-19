use std::process::Command;

use xprobe_protocol::{ErrorCode, ErrorResponse, ProcessReport, SchemaVersion};

#[test]
fn inspect_json_describes_the_target_process() {
    let pid = std::process::id();
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "inspect",
            "--pid",
            &pid.to_string(),
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .output()
        .expect("xprobe inspect must run");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());

    let report: ProcessReport =
        serde_json::from_slice(&output.stdout).expect("stdout must contain only process JSON");
    assert_eq!(report.schema_version, SchemaVersion::current());
    assert_eq!(report.target.pid, pid);
    assert!(!report.executable.is_empty());
    assert!(!report.namespace_pids.is_empty());
}

#[test]
fn inspect_missing_target_returns_a_structured_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args(["inspect", "--pid", &u32::MAX.to_string(), "--json"])
        .output()
        .expect("xprobe inspect must run");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());

    let response: ErrorResponse =
        serde_json::from_slice(&output.stdout).expect("stdout must contain only error JSON");
    assert_eq!(response.error.code, ErrorCode::TargetNotFound);
    assert!(response.error.recoverable);
}
