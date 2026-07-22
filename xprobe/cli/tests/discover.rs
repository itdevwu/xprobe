use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

use xprobe_protocol::{DiscoveryResult, ErrorCode, ErrorResponse};

struct FakeNvidiaSmi {
    directory: PathBuf,
}

impl FakeNvidiaSmi {
    fn new(pid: u32) -> Self {
        let directory = std::env::temp_dir().join(format!("xprobe-nvidia-smi-{pid}"));
        fs::create_dir(&directory).expect("fake nvidia-smi directory must be created");
        let executable = directory.join("nvidia-smi");
        fs::write(
            &executable,
            format!("#!/bin/sh\nprintf '%s\\n' '{pid}, GPU-test'\n"),
        )
        .expect("fake nvidia-smi must be written");
        let mut permissions = fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(executable, permissions).unwrap();
        Self { directory }
    }

    fn path(&self) -> String {
        format!(
            "{}:{}",
            self.directory.display(),
            std::env::var("PATH").unwrap_or_default()
        )
    }
}

impl Drop for FakeNvidiaSmi {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).expect("fake nvidia-smi must be removed");
    }
}

#[test]
fn discovers_only_nvml_confirmed_cuda_workers() {
    let pid = std::process::id();
    let fake = FakeNvidiaSmi::new(pid);
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "discover",
            "--pid",
            &pid.to_string(),
            "--limit",
            "10",
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .env("PATH", fake.path())
        .output()
        .expect("xprobe discover must run");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let result: DiscoveryResult = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result.root.pid, pid);
    assert_eq!(result.total_candidates, 1);
    assert_eq!(result.candidates[0].target.pid, pid);
    assert_eq!(result.candidates[0].gpu_uuids, ["GPU-test"]);
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
    let error: ErrorResponse = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error.error.code, ErrorCode::SessionLimitExceeded);
}
