use std::{fs, path::PathBuf, process::Command};

use xprobe_protocol::{
    ErrorCode, ErrorResponse, MatchPolicy, MeasurementMode, MeasurementSpec, SchemaVersion,
    TargetIdentity,
};

fn spec_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "xprobe-trace-spec-{name}-{}.json",
        std::process::id()
    ))
}

#[test]
fn trace_rejects_a_reused_target_from_the_spec() {
    let path = spec_path("trace");
    let spec = MeasurementSpec {
        schema_version: SchemaVersion::current(),
        name: Some("stale_target".to_owned()),
        target: TargetIdentity {
            pid: std::process::id(),
            process_start_time: 0,
        },
        start_selector: "cuda:kernel_start".to_owned(),
        end_selector: "cuda:kernel_end".to_owned(),
        match_policy: MatchPolicy::Exact,
        samples: Some(1),
        duration_ms: None,
        timeout_ms: 1_000,
        max_events: Some(100),
        measurement_mode: MeasurementMode::Exact,
        max_groups: None,
    };
    fs::write(&path, serde_json::to_vec_pretty(&spec).unwrap())
        .expect("trace spec must be written");

    let completed = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "trace",
            "--spec",
            path.to_str().expect("temporary path must be UTF-8"),
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .output()
        .expect("xprobe trace must run");
    fs::remove_file(path).expect("trace spec must be removed");

    assert_eq!(completed.status.code(), Some(3));
    let error: ErrorResponse =
        serde_json::from_slice(&completed.stdout).expect("structured error JSON");
    assert_eq!(error.error.code, ErrorCode::TargetReused);
}

#[test]
fn measure_accepts_a_versioned_live_spec() {
    let path = spec_path("measure");
    let spec = MeasurementSpec {
        schema_version: SchemaVersion::current(),
        name: Some("stale_target".to_owned()),
        target: TargetIdentity {
            pid: std::process::id(),
            process_start_time: 0,
        },
        start_selector: "cuda:kernel_start".to_owned(),
        end_selector: "cuda:kernel_end".to_owned(),
        match_policy: MatchPolicy::Exact,
        samples: Some(1),
        duration_ms: None,
        timeout_ms: 1_000,
        max_events: Some(100),
        measurement_mode: MeasurementMode::Exact,
        max_groups: None,
    };
    fs::write(&path, serde_json::to_vec_pretty(&spec).unwrap())
        .expect("measurement spec must be written");

    let completed = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "measure",
            "--spec",
            path.to_str().expect("temporary path must be UTF-8"),
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .output()
        .expect("xprobe measure must run");
    fs::remove_file(path).expect("measurement spec must be removed");

    assert_eq!(completed.status.code(), Some(3));
    let error: ErrorResponse =
        serde_json::from_slice(&completed.stdout).expect("structured error JSON");
    assert_eq!(error.error.code, ErrorCode::TargetReused);
}
