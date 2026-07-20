use std::{
    collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command,
};

use xprobe_protocol::{
    ClockDomain, Event, EventSource, EventType, ExportFormat, SchemaVersion, TraceExportResult,
};

fn path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("xprobe-export-{name}-{}", std::process::id()))
}

#[test]
fn exports_event_jsonl_as_chrome_trace() {
    let input = path("events.jsonl");
    let output = path("trace.json");
    let event = Event {
        schema_version: SchemaVersion::current(),
        session_id: "source".to_owned(),
        event_id: "evt_source".to_owned(),
        sequence: 0,
        source: EventSource::CuptiActivity,
        event_type: EventType::GpuKernelStart,
        pid: 1234,
        tid: 1235,
        cpu: None,
        timestamp_raw: 12_345,
        timestamp_ns: 12_345,
        clock_domain: ClockDomain::Cupti,
        timestamp_error_ns: None,
        process_start_time: None,
        host: None,
        cuda: None,
        attributes: BTreeMap::new(),
    };
    fs::write(
        &input,
        format!("{}\n", serde_json::to_string(&event).unwrap()),
    )
    .expect("event fixture must be written");

    let completed = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "export",
            "--input",
            input.to_str().expect("temporary path must be UTF-8"),
            "--format",
            "chrome",
            "--output",
            output.to_str().expect("temporary path must be UTF-8"),
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .output()
        .expect("xprobe export must run");
    fs::remove_file(input).expect("event fixture must be removed");

    assert!(
        completed.status.success(),
        "{}",
        String::from_utf8_lossy(&completed.stderr)
    );
    let result: TraceExportResult =
        serde_json::from_slice(&completed.stdout).expect("export result JSON");
    assert_eq!(result.format, ExportFormat::Chrome);
    assert_eq!(result.event_count, 1);
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let trace: serde_json::Value =
        serde_json::from_slice(&fs::read(&output).unwrap()).expect("Chrome trace JSON");
    fs::remove_file(output).expect("trace fixture must be removed");
    assert_eq!(trace["traceEvents"][0]["ph"], "i");
    assert_eq!(trace["traceEvents"][0]["args"]["timestamp_ns"], 12_345);
}
