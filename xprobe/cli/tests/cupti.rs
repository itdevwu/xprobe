use std::{fs, path::PathBuf, process::Command};

use xprobe_protocol::{ErrorCode, ErrorResponse, Event, EventSource, EventType};

const HEADER_SIZE: usize = 80;
const RECORD_SIZE: usize = 200;

fn capture_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("xprobe-{name}-{}.bin", std::process::id()))
}

fn write_capture(path: &PathBuf) {
    let mut bytes = vec![0_u8; HEADER_SIZE + RECORD_SIZE];
    bytes[0..8].copy_from_slice(b"XPCUPTI\0");
    bytes[8..12].copy_from_slice(&2_u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&80_u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&200_u32.to_le_bytes());
    bytes[24..28].copy_from_slice(&3_u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&1_u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&1_u64.to_le_bytes());
    bytes[40..48].copy_from_slice(&1_u64.to_le_bytes());
    bytes[48..56].copy_from_slice(&1_u64.to_le_bytes());

    let record = &mut bytes[HEADER_SIZE..];
    record[0..8].copy_from_slice(&100_u64.to_le_bytes());
    record[8..12].copy_from_slice(&1_u32.to_le_bytes());
    record[12..16].copy_from_slice(&1234_u32.to_le_bytes());
    record[16..20].copy_from_slice(&1235_u32.to_le_bytes());
    record[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    record[24..28].copy_from_slice(&7_u32.to_le_bytes());
    record[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
    record[32..36].copy_from_slice(&42_u32.to_le_bytes());
    record[36..40].copy_from_slice(&2_u32.to_le_bytes());
    record[40..44].copy_from_slice(&211_u32.to_le_bytes());
    record[68..72].copy_from_slice(&42_u32.to_le_bytes());
    record[72..88].copy_from_slice(b"cudaLaunchKernel");
    fs::write(path, bytes).expect("capture fixture must be written");
}

#[test]
fn cupti_capture_is_emitted_as_event_jsonl() {
    let path = capture_path("cupti-valid");
    write_capture(&path);

    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "capture",
            "cupti",
            "--input",
            path.to_str().expect("temporary path must be UTF-8"),
            "--session-id",
            "xp_test",
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .output()
        .expect("xprobe capture cupti must run");
    fs::remove_file(path).expect("capture fixture must be removed");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("JSONL must be UTF-8");
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1);
    let event: Event = serde_json::from_str(lines[0]).expect("line must be an Event");
    assert_eq!(event.session_id, "xp_test");
    assert_eq!(event.source, EventSource::CuptiCallback);
    assert_eq!(event.event_type, EventType::CudaApiEntry);
    assert_eq!(event.cuda.expect("CUDA payload").correlation_id, Some(42));
    assert_eq!(event.attributes["cuda_api_name"], "cudaLaunchKernel");
    assert_eq!(event.attributes["cuda_api_domain"], "runtime_api");
}

#[test]
fn malformed_cupti_capture_returns_structured_error() {
    let path = capture_path("cupti-invalid");
    fs::write(&path, [0_u8; HEADER_SIZE]).expect("capture fixture must be written");

    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "dev",
            "cupti",
            "--input",
            path.to_str().expect("temporary path must be UTF-8"),
            "--session-id",
            "xp_test",
            "--json",
        ])
        .output()
        .expect("xprobe dev cupti must run");
    fs::remove_file(path).expect("capture fixture must be removed");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let response: ErrorResponse =
        serde_json::from_slice(&output.stdout).expect("error must be JSON");
    assert_eq!(response.error.code, ErrorCode::TraceExportFailed);
}
