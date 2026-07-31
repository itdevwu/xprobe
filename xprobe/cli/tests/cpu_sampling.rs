use std::{
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use xprobe_protocol::{CpuFrameLanguage, CpuSampleInventoryResult};

#[test]
#[ignore = "requires permission to open perf events for a sibling process"]
fn samples_and_symbolizes_a_busy_native_process() {
    let mut target = Command::new("sh")
        .args(["-c", "while :; do :; done"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("busy target must start");
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "measure",
            "--pid",
            &target.id().to_string(),
            "--cpu-sample",
            "--duration-ms",
            "250",
            "--frequency-hz",
            "199",
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .output()
        .expect("xprobe CPU sampling must run");
    target.kill().expect("busy target must stop");
    target.wait().expect("busy target must be reaped");

    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let result: CpuSampleInventoryResult =
        serde_json::from_slice(&output.stdout).expect("stdout must contain CPU inventory JSON");
    assert!(result.collection.observed_samples > 0);
    assert!(!result.inventory.stack_groups.is_empty());
    assert!(
        result.inventory.hotspots.iter().any(|hotspot| {
            hotspot.frame.language == CpuFrameLanguage::Native && hotspot.frame.symbol.is_some()
        }),
        "{}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[test]
#[ignore = "requires CPython perf trampoline support and perf event access"]
fn resolves_cpython_perf_map_frames() {
    let mut target = Command::new("/usr/bin/python3")
        .args([
            "-X",
            "perf",
            "-c",
            "def leaf():\n    return sum(range(100))\nwhile True:\n    leaf()",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Python target must start");
    thread::sleep(Duration::from_millis(100));
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "measure",
            "--pid",
            &target.id().to_string(),
            "--cpu-sample",
            "--duration-ms",
            "250",
            "--frequency-hz",
            "199",
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .output()
        .expect("xprobe CPU sampling must run");
    target.kill().expect("Python target must stop");
    target.wait().expect("Python target must be reaped");

    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let result: CpuSampleInventoryResult =
        serde_json::from_slice(&output.stdout).expect("stdout must contain CPU inventory JSON");
    assert!(
        result.inventory.hotspots.iter().any(|hotspot| {
            hotspot.frame.language == CpuFrameLanguage::Python
                && hotspot
                    .frame
                    .symbol
                    .as_deref()
                    .is_some_and(|name| name.contains("leaf"))
        }),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
