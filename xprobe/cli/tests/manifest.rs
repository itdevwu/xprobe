//! Offline correlation trusts what a capture manifest records about the
//! events beside it, and nothing more.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use xprobe_protocol::{
    CaptureManifest, CaptureWindow, ClockDomain, CorrelationConfidence, CoverageSource, CudaEvent,
    ErrorCode, ErrorResponse, Event, EventSource, EventType, ExportFormat, ManifestArtifact,
    ManifestVersion, MeasurementResult, QualityVerdict, SchemaVersion, TargetIdentity,
    manifest_path,
};

const PID: u32 = 1234;

/// A fresh directory for one test's artifacts.
fn workdir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("xprobe-manifest-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("test directory must be created");
    path
}

fn kernel(event_type: EventType, timestamp: u64, correlation_id: u32, name: &str) -> Event {
    Event {
        schema_version: SchemaVersion::current(),
        session_id: "capture".to_owned(),
        event_id: format!("evt_{timestamp}_{correlation_id}"),
        sequence: timestamp,
        source: EventSource::CuptiActivity,
        event_type,
        pid: PID,
        tid: PID,
        cpu: None,
        timestamp_raw: timestamp,
        timestamp_ns: timestamp,
        clock_domain: ClockDomain::Cupti,
        timestamp_error_ns: None,
        process_start_time: None,
        host: None,
        cuda: Some(CudaEvent {
            device_id: Some(0),
            context_id: Some(1),
            stream_id: Some(7),
            correlation_id: Some(correlation_id),
            runtime_correlation_id: None,
            callback_domain: None,
            callback_id: None,
            kernel_name: Some(name.to_owned()),
            kernel_name_mangled: None,
            start_ns: None,
            end_ns: None,
            grid: None,
            block: None,
            bytes: None,
            memcpy_kind: None,
        }),
        nvtx: None,
        attributes: BTreeMap::new(),
    }
}

/// Kernels A, B, and C back to back on one stream: two end-to-start gaps.
fn write_events(path: &Path) -> Vec<u8> {
    let events = [(0, 10, "A"), (12, 20, "B"), (25, 30, "C")]
        .iter()
        .zip(1..)
        .flat_map(|(&(start, end, name), id)| {
            [
                kernel(EventType::GpuKernelStart, start, id, name),
                kernel(EventType::GpuKernelEnd, end, id, name),
            ]
        })
        .collect::<Vec<_>>();
    let bytes = events
        .iter()
        .map(|event| serde_json::to_string(event).expect("event serializes") + "\n")
        .collect::<String>()
        .into_bytes();
    fs::write(path, &bytes).expect("events must be written");
    bytes
}

fn manifest(bytes: &[u8], all_gpu_activity: bool) -> CaptureManifest {
    CaptureManifest {
        schema_version: ManifestVersion::current(),
        artifact: ManifestArtifact::of(ExportFormat::Jsonl, 6, bytes),
        target: TargetIdentity {
            pid: PID,
            process_start_time: 99,
        },
        window: CaptureWindow {
            start_ns: 0,
            end_ns: 100,
        },
        selectors: vec!["cuda:kernel_end".to_owned(), "cuda:kernel_start".to_owned()],
        all_gpu_activity,
        peer_copies: all_gpu_activity,
        dropped_records: 0,
        unknown_records: 0,
        record_limit_reached: None,
        capture_failed: false,
    }
}

fn write_manifest(events: &Path, manifest: &CaptureManifest) {
    fs::write(
        manifest_path(events),
        serde_json::to_vec(manifest).expect("manifest serializes"),
    )
    .expect("manifest must be written");
}

fn measure(inputs: &[&Path], extra: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xprobe"));
    command.arg("measure");
    for input in inputs {
        command.arg("--input").arg(input);
    }
    command
        .args([
            "--from",
            "cuda:kernel_end",
            "--to",
            "cuda:kernel_start",
            "--match",
            "stream-order",
            "--json",
        ])
        .args(extra)
        .output()
        .expect("xprobe measure must run")
}

fn result(output: &std::process::Output) -> MeasurementResult {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).expect("measurement result parses")
}

fn issue_codes(result: &MeasurementResult) -> Vec<&str> {
    result
        .quality
        .issues
        .iter()
        .map(|issue| issue.code.as_str())
        .collect()
}

#[test]
fn stream_order_without_a_manifest_is_heuristic() {
    let dir = workdir("none");
    let events = dir.join("events.jsonl");
    write_events(&events);

    let result = result(&measure(&[&events], &[]));
    assert_eq!(result.measurement.samples.matched, 2);
    assert_eq!(
        result.collection.coverage.source,
        CoverageSource::Unverified
    );
    assert_eq!(
        result.correlation.confidence,
        CorrelationConfidence::Heuristic
    );
    assert_eq!(result.quality.verdict, QualityVerdict::Caution);
    assert!(issue_codes(&result).contains(&"STREAM_COVERAGE_UNVERIFIED"));
}

#[test]
fn a_manifest_of_every_gpu_activity_keeps_stream_order_high() {
    let dir = workdir("all");
    let events = dir.join("events.jsonl");
    let bytes = write_events(&events);
    write_manifest(&events, &manifest(&bytes, true));

    let result = result(&measure(&[&events], &[]));
    assert_eq!(result.collection.coverage.source, CoverageSource::Manifest);
    assert!(result.collection.coverage.all_gpu_activity);
    assert_eq!(result.correlation.confidence, CorrelationConfidence::High);
    assert!(!issue_codes(&result).contains(&"STREAM_COVERAGE_UNVERIFIED"));

    // A narrower capture's manifest proves its own losses, not adjacency.
    write_manifest(&events, &manifest(&bytes, false));
    let narrow = self::result(&measure(&[&events], &[]));
    assert_eq!(
        narrow.correlation.confidence,
        CorrelationConfidence::Heuristic
    );
}

#[test]
fn a_manifest_keeps_losses_the_live_capture_reported() {
    let dir = workdir("drops");
    let events = dir.join("events.jsonl");
    let bytes = write_events(&events);
    let mut lossy = manifest(&bytes, true);
    lossy.dropped_records = 3;
    write_manifest(&events, &lossy);

    let output = measure(&[&events], &[]);
    assert_eq!(output.status.code(), Some(1));
    let error: ErrorResponse = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error.error.code, ErrorCode::EventsDropped);
}

#[test]
fn a_stale_manifest_is_an_error() {
    let dir = workdir("stale");
    let events = dir.join("events.jsonl");
    let bytes = write_events(&events);
    write_manifest(&events, &manifest(&bytes, true));
    // Trim the events after capture, as a hand-filtered artifact would.
    let trimmed = String::from_utf8(bytes)
        .unwrap()
        .split_inclusive('\n')
        .take(4)
        .collect::<String>();
    fs::write(&events, trimmed).unwrap();

    let output = measure(&[&events], &[]);
    assert_eq!(output.status.code(), Some(1));
    let error: ErrorResponse = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error.error.code, ErrorCode::TraceExportFailed);
    assert!(
        error
            .error
            .message
            .contains("describes a different artifact")
    );
}

#[test]
fn merging_inputs_without_manifests_is_a_caution() {
    let dir = workdir("merge");
    let first = dir.join("first.jsonl");
    let second = dir.join("second.jsonl");
    write_events(&first);
    fs::copy(&first, &second).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args(["measure", "--input"])
        .arg(&first)
        .arg("--input")
        .arg(&second)
        .args([
            "--from",
            "cuda:kernel_start",
            "--to",
            "cuda:kernel_end",
            "--match",
            "nearest",
            "--json",
        ])
        .output()
        .unwrap();
    let result = result(&output);
    assert_eq!(
        result.collection.coverage.source,
        CoverageSource::UnverifiedMerge
    );
    assert!(issue_codes(&result).contains(&"CAPTURE_COVERAGE_UNKNOWN"));
}

#[test]
fn re_exported_artifacts_keep_or_drop_their_manifest() {
    let dir = workdir("export");
    let events = dir.join("events.jsonl");
    let bytes = write_events(&events);
    write_manifest(&events, &manifest(&bytes, true));
    let copy = dir.join("copy.jsonl");

    result(&measure(
        &[&events],
        &["--events-out", copy.to_str().unwrap()],
    ));
    let written: CaptureManifest =
        serde_json::from_slice(&fs::read(manifest_path(&copy)).unwrap()).unwrap();
    assert!(written.artifact.matches(&fs::read(&copy).unwrap()));
    assert!(written.all_gpu_activity);

    // Without a manifest on the input, a stale one at the output goes away.
    fs::remove_file(manifest_path(&events)).unwrap();
    result(&measure(
        &[&events],
        &["--events-out", copy.to_str().unwrap()],
    ));
    assert!(!manifest_path(&copy).exists());
}
