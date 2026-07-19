use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};

use xprobe_protocol::{
    ElfObjectKind, ErrorCode, ErrorResponse, HostProbeKind, ResolvedProbe, ValidationResult,
};

static FIXTURE_ID: AtomicUsize = AtomicUsize::new(0);

struct ResolveTarget {
    child: Child,
    directory: PathBuf,
    executable: PathBuf,
    library: PathBuf,
}

impl ResolveTarget {
    fn spawn() -> Self {
        let fixture_id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "xprobe-resolve-{}-{fixture_id}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary fixture directory must be created");
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let executable = directory.join("resolve-target");
        let library = directory.join("libresolve-target.so");

        compile(&[
            "-O0",
            "-g",
            "-fPIC",
            "-shared",
            "-Wl,--build-id",
            workspace
                .join("tests/fixtures/resolve_library.c")
                .to_str()
                .expect("workspace path must be UTF-8"),
            "-o",
            library.to_str().expect("fixture path must be UTF-8"),
        ]);
        compile(&[
            "-O0",
            "-g",
            "-fPIE",
            "-pie",
            "-Wl,--build-id",
            workspace
                .join("tests/fixtures/resolve_target.c")
                .to_str()
                .expect("workspace path must be UTF-8"),
            "-ldl",
            "-o",
            executable.to_str().expect("fixture path must be UTF-8"),
        ]);

        let mut child = Command::new(&executable)
            .arg(&library)
            .stdout(Stdio::piped())
            .spawn()
            .expect("resolve fixture must start");
        let stdout = child.stdout.take().expect("fixture stdout must be piped");
        let mut ready = String::new();
        BufReader::new(stdout)
            .read_line(&mut ready)
            .expect("fixture readiness must be readable");
        assert_eq!(ready, "ready\n");

        Self {
            child,
            directory,
            executable,
            library,
        }
    }
}

impl Drop for ResolveTarget {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn compile(arguments: &[&str]) {
    let output = Command::new("cc")
        .args(arguments)
        .output()
        .expect("C compiler must run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn resolve(pid: u32, selector: &str) -> ResolvedProbe {
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "resolve",
            "--pid",
            &pid.to_string(),
            "--selector",
            selector,
            "--json",
            "--non-interactive",
            "--no-color",
        ])
        .output()
        .expect("xprobe resolve must run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).expect("stdout must contain resolved probe JSON")
}

#[test]
fn resolves_pie_shared_library_symbol_and_file_offset() {
    let target = ResolveTarget::spawn();
    let pid = target.child.id();

    let executable = resolve(
        pid,
        &format!(
            "uprobe:{}:xprobe_resolve_executable_marker:entry",
            target.executable.display()
        ),
    );
    assert_eq!(
        executable.object_kind,
        ElfObjectKind::PositionIndependentExecutable
    );
    assert_eq!(executable.probe_kind, HostProbeKind::Uprobe);
    assert!(executable.build_id.is_some());
    assert!(executable.symbol_virtual_address.is_some());

    let library = resolve(
        pid,
        &format!(
            "uprobe:{}:xprobe_resolve_library_marker:return",
            target.library.display()
        ),
    );
    assert_eq!(library.object_kind, ElfObjectKind::SharedLibrary);
    assert_eq!(library.probe_kind, HostProbeKind::Uretprobe);
    assert!(library.build_id.is_some());

    let by_offset = resolve(
        pid,
        &format!(
            "uprobe:{}:+{:#x}:entry",
            target.library.display(),
            library.file_offset
        ),
    );
    assert_eq!(by_offset.symbol, None);
    assert_eq!(by_offset.file_offset, library.file_offset);
    assert_eq!(by_offset.runtime_address, library.runtime_address);
}

#[test]
fn rejects_an_unknown_symbol_with_a_structured_error() {
    let target = ResolveTarget::spawn();
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "resolve",
            "--pid",
            &target.child.id().to_string(),
            "--selector",
            &format!(
                "uprobe:{}:xprobe_symbol_that_does_not_exist:entry",
                target.executable.display()
            ),
            "--json",
        ])
        .output()
        .expect("xprobe resolve must run");

    assert_eq!(output.status.code(), Some(1));
    let error: ErrorResponse =
        serde_json::from_slice(&output.stdout).expect("stdout must contain error JSON");
    assert_eq!(error.error.code, ErrorCode::SymbolNotFound);
    assert!(error.error.recoverable);
}

#[test]
fn validate_resolves_a_host_endpoint_without_attaching() {
    let target = ResolveTarget::spawn();
    let output = Command::new(env!("CARGO_BIN_EXE_xprobe"))
        .args([
            "validate",
            "--pid",
            &target.child.id().to_string(),
            "--from",
            &format!(
                "uprobe:{}:xprobe_resolve_executable_marker:entry",
                target.executable.display()
            ),
            "--to",
            "cuda:kernel_start:name~test.*",
            "--match",
            "first-after",
            "--json",
        ])
        .output()
        .expect("xprobe validate must run");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result: ValidationResult =
        serde_json::from_slice(&output.stdout).expect("stdout must contain validation JSON");
    assert!(result.requirements.needs_ebpf);
    assert!(result.requirements.needs_cupti_activity);
    assert_eq!(
        result
            .start
            .host
            .as_ref()
            .and_then(|host| host.symbol.as_deref()),
        Some("xprobe_resolve_executable_marker")
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.code == "HEURISTIC_CORRELATION")
    );
}
