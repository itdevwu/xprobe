use std::{fs, path::PathBuf, process::Command};

use xprobe_protocol::{
    CorrelationConfidence, ErrorCode, ErrorResponse, MeasurementResult, SessionStatus,
};

const HEADER_SIZE: usize = 48;
const RECORD_SIZE: usize = 200;

fn capture_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("xprobe-measure-{name}-{}.bin", std::process::id()))
}

fn record(kind: u32, timestamp: u64, correlation_id: u32, name: &str) -> [u8; RECORD_SIZE] {
    let mut record = [0_u8; RECORD_SIZE];
    record[0..8].copy_from_slice(&timestamp.to_le_bytes());
    record[8..12].copy_from_slice(&kind.to_le_bytes());
    record[12..16].copy_from_slice(&1234_u32.to_le_bytes());
    record[16..20].copy_from_slice(&1235_u32.to_le_bytes());
    record[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    record[24..28].copy_from_slice(&7_u32.to_le_bytes());
    record[28..32].copy_from_slice(&9_u32.to_le_bytes());
    record[32..36].copy_from_slice(&correlation_id.to_le_bytes());
    record[72..72 + name.len()].copy_from_slice(name.as_bytes());
    record
}

fn write_capture(path: &PathBuf, records: &[[u8; RECORD_SIZE]]) {
    let mut bytes = vec![0_u8; HEADER_SIZE + records.len() * RECORD_SIZE];
    bytes[0..8].copy_from_slice(b"XPCUPTI\0");
    bytes[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&48_u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&200_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(
        &u64::try_from(records.len())
            .expect("record count must fit u64")
            .to_le_bytes(),
    );
    for (index, record) in records.iter().enumerate() {
        let offset = HEADER_SIZE + index * RECORD_SIZE;
        bytes[offset..offset + RECORD_SIZE].copy_from_slice(record);
    }
    fs::write(path, bytes).expect("capture fixture must be written");
}

#[test]
fn measures_exact_kernel_durations_from_a_completed_capture() {
    let path = capture_path("exact");
    write_capture(
        &path,
        &[
            record(3, 100, 11, "test_kernel"),
            record(4, 150, 11, "test_kernel"),
            record(3, 200, 12, "test_kernel"),
            record(4, 280, 12, "test_kernel"),
        ],
    );
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "measure",
            "--input",
            path.to_str().expect("temporary path must be UTF-8"),
            "--from",
            "cuda:kernel_start:name~test.*",
            "--to",
            "cuda:kernel_end:name~test.*",
            "--match",
            "exact",
            "--samples",
            "2",
            "--name",
            "kernel_duration",
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .output()
        .expect("xprobe measure must run");
    fs::remove_file(path).expect("capture fixture must be removed");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let result: MeasurementResult =
        serde_json::from_slice(&output.stdout).expect("stdout must contain measurement JSON");
    assert_eq!(result.status, SessionStatus::Completed);
    assert_eq!(result.measurement.samples.matched, 2);
    assert_eq!(result.measurement.latency_ns.min, 50);
    assert!((result.measurement.latency_ns.mean - 65.0).abs() < f64::EPSILON);
    assert_eq!(result.measurement.latency_ns.max, 80);
    assert_eq!(result.correlation.confidence, CorrelationConfidence::Exact);
    assert_eq!(result.clock.alignment, "cupti_same_domain");
}

#[test]
fn rejects_unaligned_api_to_kernel_latency() {
    let path = capture_path("unaligned");
    write_capture(
        &path,
        &[
            record(2, 100, 11, "cudaLaunchKernel"),
            record(3, 200, 11, "test_kernel"),
        ],
    );
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "measure",
            "--input",
            path.to_str().expect("temporary path must be UTF-8"),
            "--from",
            "cuda:runtime_api:cudaLaunchKernel:exit",
            "--to",
            "cuda:kernel_start",
            "--match",
            "exact",
            "--samples",
            "1",
            "--json",
        ])
        .output()
        .expect("xprobe measure must run");
    fs::remove_file(path).expect("capture fixture must be removed");

    assert_eq!(output.status.code(), Some(1));
    let error: ErrorResponse =
        serde_json::from_slice(&output.stdout).expect("stdout must contain error JSON");
    assert_eq!(error.error.code, ErrorCode::ClockAlignmentFailed);
}

#[test]
fn requires_a_sample_or_duration_limit() {
    let path = capture_path("unbounded");
    write_capture(
        &path,
        &[
            record(3, 100, 11, "test_kernel"),
            record(4, 150, 11, "test_kernel"),
        ],
    );
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "measure",
            "--input",
            path.to_str().expect("temporary path must be UTF-8"),
            "--from",
            "cuda:kernel_start",
            "--to",
            "cuda:kernel_end",
            "--match",
            "exact",
            "--json",
        ])
        .output()
        .expect("xprobe measure must run");
    fs::remove_file(path).expect("capture fixture must be removed");

    assert_eq!(output.status.code(), Some(1));
    let error: ErrorResponse =
        serde_json::from_slice(&output.stdout).expect("stdout must contain error JSON");
    assert_eq!(error.error.code, ErrorCode::SessionLimitExceeded);
}
