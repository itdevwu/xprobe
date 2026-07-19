use std::process::Command;

use xprobe_protocol::{CapabilityReport, SchemaVersion};

#[test]
fn doctor_json_is_machine_readable() {
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args(["doctor", "--json", "--non-interactive", "--no-color"])
        .output()
        .expect("xprobe doctor must run");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());

    let report: CapabilityReport =
        serde_json::from_slice(&output.stdout).expect("stdout must contain only capability JSON");
    assert_eq!(report.schema_version, SchemaVersion::current());
    assert_eq!(report.environment.operating_system, "linux");
}

#[test]
fn doctor_has_a_human_readable_report() {
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .arg("doctor")
        .output()
        .expect("xprobe doctor must run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    assert!(stdout.contains("Capabilities:"));
    assert!(stdout.contains("Checks:"));
}
