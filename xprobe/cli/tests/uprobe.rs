use std::{env, process::Command};

use xprobe_protocol::{ErrorCode, ErrorResponse};

#[test]
fn uprobe_rejects_a_binary_not_mapped_by_the_target() {
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "dev",
            "uprobe",
            "--pid",
            &std::process::id().to_string(),
            "--binary",
            "/bin/sh",
            "--symbol",
            "main",
            "--json",
        ])
        .output()
        .expect("xprobe dev uprobe must run");

    assert_eq!(output.status.code(), Some(1));
    let response: ErrorResponse =
        serde_json::from_slice(&output.stdout).expect("stdout must contain only error JSON");
    assert_eq!(response.error.code, ErrorCode::BinaryNotMapped);
}

#[test]
fn uprobe_rejects_a_zero_sample_limit_before_loading_bpf() {
    let binary = env::current_exe().expect("test executable path must be available");
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "dev",
            "uprobe",
            "--pid",
            &std::process::id().to_string(),
            "--binary",
            binary.to_str().expect("test executable path must be UTF-8"),
            "--symbol",
            "main",
            "--samples",
            "0",
            "--json",
        ])
        .output()
        .expect("xprobe dev uprobe must run");

    assert_eq!(output.status.code(), Some(1));
    let response: ErrorResponse =
        serde_json::from_slice(&output.stdout).expect("stdout must contain only error JSON");
    assert_eq!(response.error.code, ErrorCode::InvalidEventSelector);
}

#[test]
fn uretprobe_rejects_a_zero_sample_limit_before_loading_bpf() {
    let binary = env::current_exe().expect("test executable path must be available");
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "dev",
            "uprobe",
            "--pid",
            &std::process::id().to_string(),
            "--binary",
            binary.to_str().expect("test executable path must be UTF-8"),
            "--symbol",
            "main",
            "--return",
            "--samples",
            "0",
            "--json",
        ])
        .output()
        .expect("xprobe dev uprobe --return must run");

    assert_eq!(output.status.code(), Some(1));
    let response: ErrorResponse =
        serde_json::from_slice(&output.stdout).expect("stdout must contain only error JSON");
    assert_eq!(response.error.code, ErrorCode::InvalidEventSelector);
}

#[test]
fn uprobe_jsonl_failure_is_machine_readable() {
    let binary = env::current_exe().expect("test executable path must be available");
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "dev",
            "uprobe",
            "--pid",
            &std::process::id().to_string(),
            "--binary",
            binary.to_str().expect("test executable path must be UTF-8"),
            "--symbol",
            "main",
            "--samples",
            "0",
            "--jsonl",
        ])
        .output()
        .expect("xprobe dev uprobe must run");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let response: ErrorResponse =
        serde_json::from_slice(&output.stdout).expect("stdout must contain only error JSON");
    assert_eq!(response.error.code, ErrorCode::InvalidEventSelector);
}
