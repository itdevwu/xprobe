use std::process::Command;

use xprobe_protocol::{DiscoveryResult, ErrorCode, ErrorResponse, EventType};

#[test]
fn discovers_bounded_cuda_activity_selectors() {
    let pid = std::process::id();
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "discover",
            "--pid",
            &pid.to_string(),
            "--query",
            "kernel_start",
            "--limit",
            "10",
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .output()
        .expect("xprobe discover must run");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let result: DiscoveryResult =
        serde_json::from_slice(&output.stdout).expect("stdout must contain discovery JSON");
    assert_eq!(result.target.pid, pid);
    assert_eq!(result.total_matches, 1);
    assert_eq!(result.events[0].event_type, EventType::GpuKernelStart);
    assert!(result.events[0].requires_observation);
}

#[test]
fn rejects_zero_discovery_limit() {
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "discover",
            "--pid",
            &std::process::id().to_string(),
            "--limit",
            "0",
            "--json",
        ])
        .output()
        .expect("xprobe discover must run");

    assert_eq!(output.status.code(), Some(1));
    let error: ErrorResponse =
        serde_json::from_slice(&output.stdout).expect("stdout must contain error JSON");
    assert_eq!(error.error.code, ErrorCode::SessionLimitExceeded);
}
