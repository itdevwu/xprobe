use crate::EXPORT_SEQUENCE;
use crate::args::CuptiArgs;
use crate::args::DevArgs;
use crate::args::DevCommand;
use crate::args::EventOutputArgs;
use crate::args::ExportArgs;
use crate::args::ExportFormatArg;
use crate::args::InspectArgs;
use crate::args::ResolveArgs;
use crate::args::TraceArgs;
use crate::args::UprobeArgs;
use crate::emit_measurement;
use crate::failure::CommandFailure;
use crate::failure::emit_command_failure;
use crate::failure::emit_error;
use crate::live::LiveMeasureRequest;
use crate::live::collect_live_measurement;
use crate::live::match_policy_name;
use crate::render::print_host_capture;
use crate::render::print_process_report;
use crate::render::print_resolved_probe;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use xprobe_collector::completed;
use xprobe_collector::cupti;
use xprobe_collector::uprobe;
use xprobe_collector::uprobe::UprobeRequest;
use xprobe_core::inspect;
use xprobe_core::resolve;
use xprobe_correlator::MeasureOptions;
use xprobe_exporter::events_to_chrome_trace;
use xprobe_exporter::events_to_jsonl;
use xprobe_protocol::ErrorCode;
use xprobe_protocol::EvidenceMode;
use xprobe_protocol::ExportFormat;
use xprobe_protocol::MeasurementMode;
use xprobe_protocol::MeasurementSpec;
use xprobe_protocol::ProcessReport;
use xprobe_protocol::SchemaVersion;
use xprobe_protocol::TraceExportResult;

pub(crate) fn run_capture(args: DevArgs) -> ExitCode {
    match args.command {
        DevCommand::Uprobe(args) => run_uprobe(args),
        DevCommand::Cupti(args) => run_cupti(args),
    }
}

pub(crate) fn run_trace(args: TraceArgs) -> ExitCode {
    let TraceArgs {
        spec,
        cupti_socket,
        json,
        no_color: _,
        non_interactive: _,
    } = args;
    let bytes = match fs::read(&spec) {
        Ok(bytes) => bytes,
        Err(error) => {
            return emit_error(
                ErrorCode::TraceExportFailed,
                format!("failed to read {}: {error}", spec.display()),
                false,
                json,
            );
        }
    };
    let spec: MeasurementSpec = match serde_json::from_slice(&bytes) {
        Ok(spec) => spec,
        Err(error) => {
            return emit_error(
                ErrorCode::InvalidEventSelector,
                format!("invalid MeasurementSpec {}: {error}", spec.display()),
                true,
                json,
            );
        }
    };
    if spec.measurement_mode != MeasurementMode::Exact || spec.max_groups.is_some() {
        return emit_error(
            ErrorCode::InvalidEventSelector,
            "legacy trace accepts only exact MeasurementSpec requests".to_owned(),
            true,
            json,
        );
    }
    let samples = match spec.samples.map(usize::try_from).transpose() {
        Ok(samples) => samples,
        Err(error) => {
            return emit_error(
                ErrorCode::SessionLimitExceeded,
                format!("MeasurementSpec samples exceed this platform: {error}"),
                true,
                json,
            );
        }
    };
    let Some(max_events) = spec.max_events else {
        return emit_error(
            ErrorCode::SessionLimitExceeded,
            "exact MeasurementSpec requires max_events".to_owned(),
            true,
            json,
        );
    };
    let max_events = match usize::try_from(max_events) {
        Ok(max_events) => max_events,
        Err(error) => {
            return emit_error(
                ErrorCode::SessionLimitExceeded,
                format!("MeasurementSpec max_events exceed this platform: {error}"),
                true,
                json,
            );
        }
    };
    let request = LiveMeasureRequest {
        pid: spec.target.pid,
        expected_target: Some(spec.target),
        cupti_socket,
        agent_path: None,
        timeout: Duration::from_millis(spec.timeout_ms),
        match_policy_text: match_policy_name(spec.match_policy),
        mode: MeasurementMode::Exact,
        options: MeasureOptions {
            session_id: format!("xp_trace_{}", std::process::id()),
            name: spec.name,
            start_selector: spec.start_selector,
            end_selector: spec.end_selector,
            match_policy: spec.match_policy,
            samples,
            duration: spec.duration_ms.map(Duration::from_millis),
            max_events,
            dropped_events: 0,
        },
    };
    match collect_live_measurement(&request) {
        Ok(execution) => emit_measurement(execution.result, EvidenceMode::Full, json),
        Err(error) => emit_command_failure(error, json),
    }
}

pub(crate) fn run_export(args: ExportArgs) -> ExitCode {
    let ExportArgs {
        input,
        format,
        output,
        json,
        no_color: _,
        non_interactive: _,
    } = args;
    let session_id = format!("xp_export_{}", std::process::id());
    let capture = match load_completed_inputs(&input, &session_id) {
        Ok(capture) => capture,
        Err(error) => return emit_command_failure(error, json),
    };
    let (format, artifact) = match format {
        ExportFormatArg::Jsonl => (
            ExportFormat::Jsonl,
            events_to_jsonl(&capture.events).map_err(|error| error.to_string()),
        ),
        ExportFormatArg::Chrome => (
            ExportFormat::Chrome,
            events_to_chrome_trace(&capture.events).map_err(|error| error.to_string()),
        ),
    };
    let artifact = match artifact {
        Ok(artifact) => artifact,
        Err(error) => {
            return emit_error(ErrorCode::TraceExportFailed, error, false, json);
        }
    };
    if let Err(error) = write_export_file(&output, artifact.as_bytes()) {
        return emit_error(
            ErrorCode::TraceExportFailed,
            format!("failed to write {}: {error}", output.display()),
            false,
            json,
        );
    }
    let event_count = u64::try_from(capture.events.len()).expect("event count fits u64");
    let result = TraceExportResult {
        schema_version: SchemaVersion::current(),
        ok: true,
        format,
        output: output.to_string_lossy().into_owned(),
        event_count,
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("export result must serialize")
        );
    } else {
        println!(
            "Exported {} events to {} ({:?})",
            result.event_count, result.output, result.format
        );
    }
    ExitCode::SUCCESS
}

pub(crate) fn load_completed_inputs(
    input: &[PathBuf],
    session_id: &str,
) -> Result<completed::CompletedCapture, CommandFailure> {
    let mut captures = Vec::with_capacity(input.len());
    for path in input {
        let bytes = fs::read(path).map_err(|error| {
            CommandFailure::new(
                ErrorCode::TraceExportFailed,
                format!("failed to read {}: {error}", path.display()),
                false,
            )
        })?;
        captures.push(completed::decode(&bytes, session_id).map_err(|error| {
            CommandFailure::new(
                ErrorCode::TraceExportFailed,
                format!("failed to decode {}: {error}", path.display()),
                false,
            )
        })?);
    }
    let capture = completed::merge(captures, session_id).map_err(|error| {
        CommandFailure::new(ErrorCode::TraceExportFailed, error.to_string(), false)
    })?;
    if capture.unknown_records != 0 {
        return Err(CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!(
                "capture contains {} unknown CUPTI activity records",
                capture.unknown_records
            ),
            false,
        )
        .with_detail("unknown_records", capture.unknown_records)
        .with_hint("rebuild xprobe and the CUPTI Agent from the same release"));
    }
    Ok(capture)
}

pub(crate) fn write_export_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("artifact path {} has no file name", path.display()))?;
    let temporary = parent.join(format!(
        ".{}.xprobe-{}-{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        EXPORT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("failed to create {}: {error}", temporary.display()))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let original = format!("failed to write {}: {error}", temporary.display());
        return Err(remove_temporary_artifact(&temporary, original));
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let original = format!(
            "failed to atomically replace {} with {}: {error}",
            path.display(),
            temporary.display()
        );
        return Err(remove_temporary_artifact(&temporary, original));
    }
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!(
                "failed to sync artifact directory {}: {error}",
                parent.display()
            )
        })
}

pub(crate) fn remove_temporary_artifact(path: &Path, original: String) -> String {
    match fs::remove_file(path) {
        Ok(()) => original,
        Err(cleanup) => format!(
            "{original}; failed to remove temporary artifact {}: {cleanup}",
            path.display()
        ),
    }
}

pub(crate) fn run_resolve(args: ResolveArgs) -> ExitCode {
    let ResolveArgs {
        pid,
        selector,
        json,
        no_color: _,
        non_interactive: _,
    } = args;
    let report = match inspect::run(pid) {
        Ok(report) => report,
        Err(error) => {
            return emit_error(error.code(), error.to_string(), error.recoverable(), json);
        }
    };

    match resolve::run(&report, &selector) {
        Ok(resolved) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resolved).expect("resolved probe must serialize")
                );
            } else {
                print_resolved_probe(&resolved);
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_error(error.code(), error.to_string(), error.recoverable(), json),
    }
}

pub(crate) fn run_inspect(args: InspectArgs) -> ExitCode {
    let InspectArgs {
        pid,
        json,
        no_color: _,
        non_interactive: _,
    } = args;

    match inspect::run(pid) {
        Ok(report) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("process report must serialize")
                );
            } else {
                print_process_report(&report);
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_error(error.code(), error.to_string(), error.recoverable(), json),
    }
}

pub(crate) fn run_uprobe(args: UprobeArgs) -> ExitCode {
    let UprobeArgs {
        pid,
        binary,
        symbol,
        return_probe,
        probe_id,
        samples,
        timeout_ms,
        output: EventOutputArgs { json, jsonl },
        no_color: _,
        non_interactive: _,
    } = args;
    let machine_output = json || jsonl;

    let report = match inspect::run(pid) {
        Ok(report) => report,
        Err(error) => {
            return emit_error(
                error.code(),
                error.to_string(),
                error.recoverable(),
                machine_output,
            );
        }
    };
    let binary = match mapped_binary(&report, &binary) {
        Ok(binary) => binary,
        Err(message) => {
            return emit_error(ErrorCode::BinaryNotMapped, message, true, machine_output);
        }
    };
    let request = UprobeRequest {
        target: report.target.clone(),
        binary,
        symbol: Some(symbol),
        symbol_demangled: None,
        offset: 0,
        probe_kind: if return_probe {
            xprobe_protocol::HostProbeKind::Uretprobe
        } else {
            xprobe_protocol::HostProbeKind::Uprobe
        },
        probe_id,
        samples,
        timeout: Duration::from_millis(timeout_ms),
        cancelled: Arc::new(AtomicBool::new(false)),
        ready: None,
    };
    let result = match uprobe::capture(&request) {
        Ok(result) => result,
        Err(error) => {
            return emit_error(
                error.code(),
                error.to_string(),
                error.recoverable(),
                machine_output,
            );
        }
    };
    if let Err(error) = inspect::verify_target(&report.target) {
        return emit_error(
            error.code(),
            error.to_string(),
            error.recoverable(),
            machine_output,
        );
    }

    if jsonl {
        match events_to_jsonl(&result.events) {
            Ok(output) => print!("{output}"),
            Err(error) => {
                return emit_error(
                    ErrorCode::TraceExportFailed,
                    format!("failed to serialize host events: {error}"),
                    false,
                    true,
                );
            }
        }
    } else if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("host capture result must serialize")
        );
    } else {
        print_host_capture(&result);
    }
    ExitCode::SUCCESS
}

pub(crate) fn run_cupti(args: CuptiArgs) -> ExitCode {
    let CuptiArgs {
        input,
        socket,
        timeout_ms,
        session_id,
        json,
        no_color: _,
        non_interactive: _,
    } = args;
    let capture = if let Some(input) = input {
        let bytes = match fs::read(&input) {
            Ok(bytes) => bytes,
            Err(error) => {
                return emit_error(
                    ErrorCode::TraceExportFailed,
                    format!("failed to read {}: {error}", input.display()),
                    false,
                    json,
                );
            }
        };
        match cupti::decode_capture(&bytes, &session_id) {
            Ok(capture) => capture,
            Err(error) => {
                return emit_error(ErrorCode::TraceExportFailed, error.to_string(), false, json);
            }
        }
    } else {
        let socket = socket.expect("clap requires one CUPTI capture source");
        match cupti::snapshot(&socket, Duration::from_millis(timeout_ms), &session_id, 0) {
            Ok(capture) => capture,
            Err(error) => {
                return emit_error(ErrorCode::TraceExportFailed, error.to_string(), true, json);
            }
        }
    };
    let output = match events_to_jsonl(&capture.events) {
        Ok(output) => output,
        Err(error) => {
            return emit_error(
                ErrorCode::TraceExportFailed,
                format!("failed to serialize CUPTI events: {error}"),
                false,
                json,
            );
        }
    };

    if capture.dropped_records != 0 || capture.unknown_records != 0 {
        eprintln!(
            "CUPTI capture diagnostics: dropped={}, unknown={}",
            capture.dropped_records, capture.unknown_records
        );
    }
    print!("{output}");
    ExitCode::SUCCESS
}

pub(crate) fn mapped_binary(report: &ProcessReport, binary: &Path) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(binary)
        .map_err(|error| format!("failed to resolve {}: {error}", binary.display()))?;
    let is_executable = Path::new(&report.executable) == canonical;
    let is_library = report
        .loaded_libraries
        .iter()
        .any(|mapped| Path::new(mapped) == canonical);
    if !is_executable && !is_library {
        return Err(format!(
            "{} is not mapped by target PID {}",
            canonical.display(),
            report.target.pid
        ));
    }
    Ok(canonical)
}
