use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

static EXPORT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

use clap::{Args, Parser, Subcommand, ValueEnum};
use xprobe_collector::{
    completed, cupti,
    uprobe::{self, UprobeRequest},
};
use xprobe_core::{cupti_compat, discover, doctor, inject, inspect, resolve, validate};
use xprobe_correlator::{MeasureError, MeasureOptions, measure};
use xprobe_exporter::{events_to_chrome_trace, events_to_jsonl};
use xprobe_protocol::{
    CapabilityReport, CheckResult, ClockDomain, CuptiCollectionSummary, DiscoveryResult, ErrorCode,
    ErrorResponse, Event, EventSource, EventType, ExportFormat, HostCaptureResult, MatchPolicy,
    MeasurementResult, MeasurementSpec, MemcpyKind, ProcessReport, ResolvedCudaSelector,
    ResolvedProbe, SchemaVersion, SessionStatus, TargetIdentity, TraceExportResult,
    ValidationResult, Warning, XprobeError,
};

#[derive(Debug, Parser)]
#[command(name = "xprobe", version, about = "Runtime host-to-GPU latency probe")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect local tracing and GPU capabilities.
    Doctor(DoctorArgs),
    /// Discover event selectors available in a target process.
    Discover(DiscoverArgs),
    /// Inspect a target process without attaching probes.
    #[command(hide = true)]
    Inspect(InspectArgs),
    /// Resolve a userspace event selector against a target process.
    #[command(hide = true)]
    Resolve(ResolveArgs),
    /// Validate two event selectors and their correlation policy.
    Validate(ValidateArgs),
    /// Measure latency between two events in files or a running process.
    Measure(MeasureArgs),
    /// Run a live measurement from a versioned specification.
    #[command(hide = true)]
    Trace(TraceArgs),
    /// Export completed captures to a stable trace format.
    #[command(hide = true)]
    Export(ExportArgs),
    /// Run bounded event collectors.
    #[command(hide = true)]
    Capture(DevArgs),
    /// Run low-level development probes.
    #[command(hide = true)]
    Dev(DevArgs),
}

#[derive(Debug, Args)]
struct DevArgs {
    #[command(subcommand)]
    command: DevCommand,
}

#[derive(Debug, Args)]
struct TraceArgs {
    /// Versioned `MeasurementSpec` JSON file.
    #[arg(long)]
    spec: PathBuf,

    /// Unix socket exposed by the target's xprobe CUPTI agent.
    #[arg(long, hide = true)]
    cupti_socket: Option<PathBuf>,

    /// Emit only the versioned JSON result on stdout.
    #[arg(long)]
    json: bool,

    /// Disable colored output.
    #[arg(long)]
    no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    non_interactive: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExportFormatArg {
    Jsonl,
    Chrome,
}

#[derive(Debug, Args)]
struct ExportArgs {
    /// Completed CUPTI binary, host capture JSON, or Event JSONL; repeat to merge.
    #[arg(long, required = true)]
    input: Vec<PathBuf>,

    /// Artifact format.
    #[arg(long, value_enum)]
    format: ExportFormatArg,

    /// Destination artifact path.
    #[arg(long)]
    output: PathBuf,

    /// Emit only the versioned export result on stdout.
    #[arg(long)]
    json: bool,

    /// Disable colored output.
    #[arg(long)]
    no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    non_interactive: bool,
}

#[derive(Debug, Subcommand)]
enum DevCommand {
    /// Capture entries to one userspace function.
    Uprobe(UprobeArgs),
    /// Decode an xprobe CUPTI capture as Event JSONL.
    Cupti(CuptiArgs),
}

#[derive(Debug, Clone, Copy, Args)]
struct DoctorArgs {
    /// Emit only the versioned JSON result on stdout.
    #[arg(long)]
    json: bool,

    /// Disable colored output.
    #[arg(long)]
    no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    non_interactive: bool,
}

#[derive(Debug, Clone, Copy, Args)]
struct DiscoverArgs {
    /// Target process ID.
    #[arg(long)]
    pid: u32,

    /// Maximum number of CUDA worker candidates to return.
    #[arg(long, default_value_t = 200)]
    limit: usize,

    /// Emit only the versioned JSON result on stdout.
    #[arg(long)]
    json: bool,

    /// Disable colored output.
    #[arg(long)]
    no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    non_interactive: bool,
}

#[derive(Debug, Clone, Copy, Args)]
struct InspectArgs {
    /// Target process ID.
    #[arg(long)]
    pid: u32,

    /// Emit only the versioned JSON result on stdout.
    #[arg(long)]
    json: bool,

    /// Disable colored output.
    #[arg(long)]
    no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    non_interactive: bool,
}

#[derive(Debug, Args)]
struct ResolveArgs {
    /// Target process ID.
    #[arg(long)]
    pid: u32,

    /// Event selector: uprobe:<binary>:<symbol|+0xoffset>:<entry|return>.
    #[arg(long, alias = "event")]
    selector: String,

    /// Emit only the versioned JSON result on stdout.
    #[arg(long)]
    json: bool,

    /// Disable colored output.
    #[arg(long)]
    no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    non_interactive: bool,
}

#[derive(Debug, Args)]
struct ValidateArgs {
    /// Target process ID.
    #[arg(long)]
    pid: u32,

    /// Start event selector.
    #[arg(long)]
    from: String,

    /// End event selector.
    #[arg(long)]
    to: String,

    /// Correlation policy.
    #[arg(long = "match")]
    match_policy: String,

    /// Emit only the versioned JSON result on stdout.
    #[arg(long)]
    json: bool,

    /// Disable colored output.
    #[arg(long)]
    no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    non_interactive: bool,
}

#[derive(Debug, Args)]
struct MeasureArgs {
    /// Versioned `MeasurementSpec` JSON for a live target.
    #[arg(long, conflicts_with_all = ["input", "pid", "from", "to", "match_policy", "samples", "duration_ms", "timeout_ms", "max_events", "name"])]
    spec: Option<PathBuf>,

    /// Completed CUPTI binary, host capture JSON, or Event JSONL; repeat to merge.
    #[arg(long)]
    input: Vec<PathBuf>,

    /// Collect from a running target process instead of completed capture files.
    #[arg(long)]
    pid: Option<u32>,

    /// Unix socket exposed by the target's xprobe CUPTI agent.
    #[arg(long, hide = true)]
    cupti_socket: Option<PathBuf>,

    /// CUPTI agent shared object used for automatic online injection.
    #[arg(long)]
    agent: Option<PathBuf>,

    /// Write matched start/end evidence events to this file.
    #[arg(long)]
    events_out: Option<PathBuf>,

    /// Evidence event format; defaults to jsonl when --events-out is set.
    #[arg(long, value_enum)]
    format: Option<ExportFormatArg>,

    /// Bound foreground collection and cleanup to this many milliseconds.
    #[arg(long, default_value_t = 30_000)]
    timeout_ms: u64,

    /// Start event selector.
    #[arg(long)]
    from: Option<String>,

    /// End event selector.
    #[arg(long)]
    to: Option<String>,

    /// Correlation policy.
    #[arg(long = "match")]
    match_policy: Option<String>,

    /// Stop after this many matched samples.
    #[arg(long)]
    samples: Option<usize>,

    /// Restrict events to this many milliseconds from the first selected event.
    #[arg(long)]
    duration_ms: Option<u64>,

    /// Reject captures containing more events than this limit.
    #[arg(long, default_value_t = 100_000)]
    max_events: usize,

    /// Optional measurement name.
    #[arg(long)]
    name: Option<String>,

    /// Emit only the versioned JSON result on stdout.
    #[arg(long)]
    json: bool,

    /// Disable colored output.
    #[arg(long)]
    no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    non_interactive: bool,
}

#[derive(Debug, Args)]
struct UprobeArgs {
    /// Target process ID.
    #[arg(long)]
    pid: u32,

    /// Executable or mapped shared library containing the symbol.
    #[arg(long)]
    binary: PathBuf,

    /// ELF function symbol to attach to.
    #[arg(long)]
    symbol: String,

    /// Attach at function return instead of function entry.
    #[arg(long = "return")]
    return_probe: bool,

    /// Probe identifier stored in each event.
    #[arg(long, default_value_t = 1)]
    probe_id: u32,

    /// Stop after this many events.
    #[arg(long, default_value_t = 1)]
    samples: usize,

    /// Stop waiting after this many milliseconds.
    #[arg(long, default_value_t = 5_000)]
    timeout_ms: u64,

    #[command(flatten)]
    output: EventOutputArgs,

    /// Disable colored output.
    #[arg(long)]
    no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    non_interactive: bool,
}

#[derive(Debug, Clone, Copy, Args)]
struct EventOutputArgs {
    /// Emit only the versioned JSON result on stdout.
    #[arg(long)]
    json: bool,

    /// Emit one versioned Event JSON object per line.
    #[arg(long, conflicts_with = "json")]
    jsonl: bool,
}

#[derive(Debug, Args)]
struct CuptiArgs {
    /// Raw binary capture written by the xprobe CUPTI agent.
    #[arg(long, required_unless_present = "socket", conflicts_with = "socket")]
    input: Option<PathBuf>,

    /// Unix socket exposed by a running xprobe CUPTI agent.
    #[arg(long, required_unless_present = "input", conflicts_with = "input")]
    socket: Option<PathBuf>,

    /// Stop waiting for an online snapshot after this many milliseconds.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,

    /// Session identifier written into every Event.
    #[arg(long)]
    session_id: String,

    /// Emit one versioned Event JSON object per line.
    #[arg(long)]
    json: bool,

    /// Disable colored output.
    #[arg(long)]
    no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    non_interactive: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Doctor(args) => run_doctor(args),
        Command::Discover(args) => run_discover(args),
        Command::Inspect(args) => run_inspect(args),
        Command::Resolve(args) => run_resolve(args),
        Command::Validate(args) => run_validate(args),
        Command::Measure(args) => run_measure(args),
        Command::Trace(args) => run_trace(args),
        Command::Export(args) => run_export(args),
        Command::Capture(args) | Command::Dev(args) => run_capture(args),
    }
}

fn run_capture(args: DevArgs) -> ExitCode {
    match args.command {
        DevCommand::Uprobe(args) => run_uprobe(args),
        DevCommand::Cupti(args) => run_cupti(args),
    }
}

fn run_trace(args: TraceArgs) -> ExitCode {
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
    let max_events = match usize::try_from(spec.max_events) {
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
        Ok(execution) => emit_measurement(&execution.result, json),
        Err(error) => emit_command_failure(error, json),
    }
}

fn run_export(args: ExportArgs) -> ExitCode {
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

fn load_completed_inputs(
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

fn write_export_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
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

fn remove_temporary_artifact(path: &Path, original: String) -> String {
    match fs::remove_file(path) {
        Ok(()) => original,
        Err(cleanup) => format!(
            "{original}; failed to remove temporary artifact {}: {cleanup}",
            path.display()
        ),
    }
}

fn run_measure(args: MeasureArgs) -> ExitCode {
    let MeasureArgs {
        spec,
        input,
        pid,
        cupti_socket,
        agent,
        events_out,
        format,
        timeout_ms,
        from,
        to,
        match_policy,
        samples,
        duration_ms,
        max_events,
        name,
        json,
        no_color: _,
        non_interactive: _,
    } = args;
    if let Some(spec) = spec {
        return run_measure_spec(
            &spec,
            cupti_socket,
            agent,
            events_out.as_deref(),
            format,
            json,
        );
    }
    let (from, to, match_policy) = match parse_measure_selection(from, to, match_policy) {
        Ok(selection) => selection,
        Err(error) => {
            return emit_command_failure(error, json);
        }
    };
    let session_id = format!("xp_measure_{}", std::process::id());
    let options = MeasureOptions {
        session_id: session_id.clone(),
        name,
        start_selector: from.clone(),
        end_selector: to.clone(),
        match_policy,
        samples,
        duration: duration_ms.map(Duration::from_millis),
        max_events,
        dropped_events: 0,
    };

    if pid.is_some() && !input.is_empty() {
        return emit_error(
            ErrorCode::InvalidEventSelector,
            "--pid and --input select different collection modes".to_owned(),
            true,
            json,
        );
    }
    if let Some(pid) = pid {
        let request = LiveMeasureRequest {
            pid,
            expected_target: None,
            cupti_socket,
            agent_path: agent,
            timeout: Duration::from_millis(timeout_ms),
            match_policy_text: match_policy_name(match_policy),
            options,
        };
        return match collect_live_measurement(&request) {
            Ok(execution) => finish_measurement(&execution, events_out.as_deref(), format, json),
            Err(error) => finish_measurement_failure(error, events_out.as_deref(), format, json),
        };
    }
    run_completed_measurement(
        &input,
        &options,
        cupti_socket.is_some(),
        agent.is_some(),
        events_out.as_deref(),
        format,
        json,
    )
}

fn parse_measure_selection(
    from: Option<String>,
    to: Option<String>,
    policy: Option<String>,
) -> Result<(String, String, MatchPolicy), CommandFailure> {
    let Some(from) = from else {
        return Err(CommandFailure::new(
            ErrorCode::InvalidEventSelector,
            "measure requires --from unless --spec is used",
            true,
        ));
    };
    let Some(to) = to else {
        return Err(CommandFailure::new(
            ErrorCode::InvalidEventSelector,
            "measure requires --to unless --spec is used",
            true,
        ));
    };
    let Some(policy) = policy else {
        return Err(CommandFailure::new(
            ErrorCode::InvalidCorrelationPolicy,
            "measure requires --match unless --spec is used",
            true,
        ));
    };
    let policy = match policy.as_str() {
        "exact" => MatchPolicy::Exact,
        "first-after" | "first_after" => MatchPolicy::FirstAfter,
        "nearest" => MatchPolicy::Nearest,
        "stack-nested" | "stack_nested" => MatchPolicy::StackNested,
        "stream-order" | "stream_order" => MatchPolicy::StreamOrder,
        _ => {
            return Err(CommandFailure::new(
                ErrorCode::InvalidCorrelationPolicy,
                "unsupported measurement correlation policy",
                true,
            ));
        }
    };
    Ok((from, to, policy))
}

fn run_completed_measurement(
    input: &[PathBuf],
    options: &MeasureOptions,
    has_cupti_socket: bool,
    has_agent: bool,
    events_out: Option<&Path>,
    format: Option<ExportFormatArg>,
    json: bool,
) -> ExitCode {
    let invalid = if input.is_empty() {
        Some((
            ErrorCode::TraceExportFailed,
            "measure requires --input or --pid",
        ))
    } else if has_cupti_socket {
        Some((
            ErrorCode::InvalidEventSelector,
            "--cupti-socket requires --pid",
        ))
    } else if has_agent {
        Some((ErrorCode::InvalidEventSelector, "--agent requires --pid"))
    } else {
        None
    };
    if let Some((code, message)) = invalid {
        return emit_error(code, message.to_owned(), true, json);
    }
    match measure_completed_inputs(input, options) {
        Ok(execution) => finish_measurement(&execution, events_out, format, json),
        Err(error) => finish_measurement_failure(error, events_out, format, json),
    }
}

fn run_measure_spec(
    path: &Path,
    cupti_socket: Option<PathBuf>,
    agent_path: Option<PathBuf>,
    events_out: Option<&Path>,
    format: Option<ExportFormatArg>,
    json: bool,
) -> ExitCode {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return emit_error(
                ErrorCode::TraceExportFailed,
                format!("failed to read {}: {error}", path.display()),
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
                format!("invalid MeasurementSpec {}: {error}", path.display()),
                true,
                json,
            );
        }
    };
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
    let max_events = match usize::try_from(spec.max_events) {
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
        agent_path,
        timeout: Duration::from_millis(spec.timeout_ms),
        match_policy_text: match_policy_name(spec.match_policy),
        options: MeasureOptions {
            session_id: format!("xp_measure_{}", std::process::id()),
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
        Ok(execution) => finish_measurement(&execution, events_out, format, json),
        Err(error) => finish_measurement_failure(error, events_out, format, json),
    }
}

fn finish_measurement(
    execution: &MeasurementExecution,
    events_out: Option<&Path>,
    format: Option<ExportFormatArg>,
    json: bool,
) -> ExitCode {
    if format.is_some() && events_out.is_none() {
        return emit_error(
            ErrorCode::TraceExportFailed,
            "--format requires --events-out".to_owned(),
            true,
            json,
        );
    }
    if let Some(path) = events_out {
        let format = format.unwrap_or(ExportFormatArg::Jsonl);
        if let Err(error) = export_measurement_capture(&execution.events, path, format) {
            return emit_command_failure(error, json);
        }
    }
    emit_measurement(&execution.result, json)
}

fn finish_measurement_failure(
    mut error: CommandFailure,
    events_out: Option<&Path>,
    format: Option<ExportFormatArg>,
    json: bool,
) -> ExitCode {
    if format.is_some() && events_out.is_none() {
        return emit_error(
            ErrorCode::TraceExportFailed,
            "--format requires --events-out".to_owned(),
            true,
            json,
        );
    }
    if let (Some(path), Some(events)) = (events_out, error.artifact_events.take()) {
        let format = format.unwrap_or(ExportFormatArg::Jsonl);
        if let Err(export) = export_measurement_capture(&events, path, format) {
            return emit_command_failure(
                export
                    .with_detail("original_error_code", error.code.to_string())
                    .with_hint("the measurement also failed; rerun after fixing artifact output"),
                json,
            );
        }
        error = error
            .with_detail("artifact_path", path.display().to_string())
            .with_detail("artifact_format", export_format_name(format))
            .with_detail("artifact_event_count", events.len() as u64);
    }
    emit_command_failure(error, json)
}

fn export_measurement_capture(
    events: &[Event],
    path: &Path,
    format: ExportFormatArg,
) -> Result<(), CommandFailure> {
    let artifact = match format {
        ExportFormatArg::Jsonl => events_to_jsonl(events),
        ExportFormatArg::Chrome => events_to_chrome_trace(events),
    }
    .map_err(|error| CommandFailure::new(ErrorCode::TraceExportFailed, error.to_string(), false))?;
    write_export_file(path, artifact.as_bytes()).map_err(|error| {
        CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!("failed to write {}: {error}", path.display()),
            false,
        )
    })
}

const fn export_format_name(format: ExportFormatArg) -> &'static str {
    match format {
        ExportFormatArg::Jsonl => "jsonl",
        ExportFormatArg::Chrome => "chrome",
    }
}

fn measure_completed_inputs(
    input: &[PathBuf],
    options: &MeasureOptions,
) -> Result<MeasurementExecution, CommandFailure> {
    let mut captures = Vec::with_capacity(input.len());
    for path in input {
        let bytes = fs::read(path).map_err(|error| {
            CommandFailure::new(
                ErrorCode::TraceExportFailed,
                format!("failed to read {}: {error}", path.display()),
                false,
            )
        })?;
        let capture = completed::decode(&bytes, &options.session_id).map_err(|error| {
            CommandFailure::new(
                ErrorCode::TraceExportFailed,
                format!("failed to decode {}: {error}", path.display()),
                false,
            )
        })?;
        captures.push(capture);
    }
    let capture = completed::merge(captures, &options.session_id).map_err(|error| {
        CommandFailure::new(ErrorCode::TraceExportFailed, error.to_string(), false)
    })?;
    reject_incomplete_capture(&capture, false, true)
        .map_err(|error| error.with_artifact_events(capture.events.clone()))?;
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
        .with_hint("rebuild xprobe and the CUPTI Agent from the same release")
        .with_artifact_events(capture.events));
    }
    let options = MeasureOptions {
        dropped_events: capture.dropped_records,
        ..options.clone()
    };
    let mut result = measure(&capture.events, &options)
        .map_err(|error| measurement_failure(&error, &options, &capture.events, true))?;
    apply_collection_summary(&mut result, &capture);
    Ok(MeasurementExecution {
        result,
        events: capture.events,
    })
}

#[derive(Debug)]
struct MeasurementExecution {
    result: MeasurementResult,
    events: Vec<Event>,
}

#[derive(Debug)]
struct CommandFailure {
    code: ErrorCode,
    message: String,
    recoverable: bool,
    details: BTreeMap<String, serde_json::Value>,
    hints: Vec<String>,
    artifact_events: Option<Vec<Event>>,
}

impl CommandFailure {
    fn new(code: ErrorCode, message: impl Into<String>, recoverable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable,
            details: BTreeMap::new(),
            hints: Vec::new(),
            artifact_events: None,
        }
    }

    fn with_detail(mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hints.push(hint.into());
        self
    }

    fn with_artifact_events(mut self, events: Vec<Event>) -> Self {
        self.artifact_events = Some(events);
        self
    }
}

fn measurement_failure(
    error: &MeasureError,
    options: &MeasureOptions,
    events: &[Event],
    preserve_artifact: bool,
) -> CommandFailure {
    let mut failure = CommandFailure::new(error.code(), error.to_string(), error.recoverable())
        .with_detail("start_selector", options.start_selector.clone())
        .with_detail("end_selector", options.end_selector.clone())
        .with_detail("match_policy", match_policy_name(options.match_policy));
    if preserve_artifact {
        failure = failure.with_artifact_events(events.to_vec());
    }
    match error {
        MeasureError::InvalidSelector(_) => {
            failure = failure.with_hint("run xprobe validate with the exact selector text");
        }
        MeasureError::InvalidPolicy(_) => {
            failure = failure
                .with_hint("use policy_recommendation.compatible_policies from xprobe validate");
        }
        MeasureError::InvalidLimit(_) => {
            failure = failure
                .with_hint("set positive samples or duration, timeout, and max-events bounds");
        }
        MeasureError::EventLimitExceeded { actual, maximum } => {
            failure = failure
                .with_detail("observed_events", *actual as u64)
                .with_detail("max_events", *maximum as u64)
                .with_hint("narrow the selectors or explicitly increase max-events");
        }
        MeasureError::EventsDropped { count } => {
            failure = failure
                .with_detail("dropped_events", *count)
                .with_hint("reduce the event rate or explicitly increase the capture capacity");
        }
        MeasureError::ClockDomainsDiffer { start, end } => {
            failure = failure
                .with_detail("start_clock", clock_domain_name(start))
                .with_detail("end_clock", clock_domain_name(end))
                .with_hint(
                    "use endpoints in one clock domain or a CUPTI capture normalized to host monotonic time",
                );
        }
        MeasureError::NoMatchedSamples => {
            let host_events = events
                .iter()
                .filter(|event| event.source == EventSource::Ebpf)
                .count() as u64;
            failure = failure
                .with_detail("captured_events", events.len() as u64)
                .with_detail("host_events", host_events)
                .with_detail("cuda_events", events.len() as u64 - host_events)
                .with_hint(
                    "inspect the events-out artifact, then adjust selectors or choose an explicitly compatible policy",
                );
        }
    }
    failure
}

const fn clock_domain_name(domain: &ClockDomain) -> &'static str {
    match domain {
        ClockDomain::HostMonotonic => "host_monotonic",
        ClockDomain::Cupti => "cupti",
        ClockDomain::CuptiNormalizedToHostMonotonic => "cupti_normalized_to_host_monotonic",
    }
}

struct LiveMeasureRequest {
    pid: u32,
    expected_target: Option<TargetIdentity>,
    cupti_socket: Option<PathBuf>,
    agent_path: Option<PathBuf>,
    timeout: Duration,
    match_policy_text: &'static str,
    options: MeasureOptions,
}

type HostCaptureHandle = JoinHandle<Result<HostCaptureResult, uprobe::UprobeError>>;
const SNAPSHOT_QUIET_PERIOD: Duration = Duration::from_millis(100);

struct HostCollectors {
    cancelled: Arc<AtomicBool>,
    handles: Vec<HostCaptureHandle>,
}

impl HostCollectors {
    fn finished(&self) -> bool {
        self.handles.iter().all(JoinHandle::is_finished)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn join(&mut self) -> Result<Vec<HostCaptureResult>, CommandFailure> {
        let mut captures = Vec::with_capacity(self.handles.len());
        for handle in self.handles.drain(..) {
            let result = handle.join().map_err(|_| {
                CommandFailure::new(ErrorCode::Internal, "host collector thread panicked", false)
            })?;
            captures.push(result.map_err(|error| {
                CommandFailure::new(error.code(), error.to_string(), error.recoverable())
            })?);
        }
        Ok(captures)
    }
}

impl Drop for HostCollectors {
    fn drop(&mut self) {
        self.cancel();
        for handle in self.handles.drain(..) {
            if handle.join().is_err() {
                eprintln!("xprobe: host collector thread panicked during cleanup");
            }
        }
    }
}

struct LiveCollection {
    report: ProcessReport,
    socket: Option<PathBuf>,
    deadline: Instant,
    collection_end: Option<Instant>,
    baseline_timestamp: Option<u64>,
    baseline_dropped: u64,
    baseline_unknown: u64,
    baseline_observed: u64,
    collectors: HostCollectors,
    host_captures: Option<Vec<HostCaptureResult>>,
    latest_cuda: Option<cupti::CuptiCapture>,
    cuda_record_offset: u64,
    managed_agent: bool,
    cupti_armed: bool,
    agent_injected: bool,
    agent_major: Option<u32>,
    agent_path: Option<PathBuf>,
    cupti_path: Option<PathBuf>,
}

fn collect_live_measurement(
    request: &LiveMeasureRequest,
) -> Result<MeasurementExecution, CommandFailure> {
    validate_live_limits(request)?;
    let mut collection = prepare_live_collection(request)?;

    let outcome = (|| {
        loop {
            refresh_live_sources(&mut collection, request)?;
            let now = Instant::now();
            if let Some(result) = evaluate_live_result(&collection, request, now)? {
                break Ok(result);
            }
            if now >= collection.deadline {
                break finish_live_timeout(&mut collection, request);
            }
            if collection.socket.is_none() {
                thread::sleep(Duration::from_millis(10));
            }
        }
    })();
    let cuda_capture = collection.cupti_armed;
    let stop_result = stop_cupti_agent(&mut collection, request);
    let mut execution = match (outcome, stop_result) {
        (Ok(mut execution), Ok(())) => {
            if cuda_capture && collection.host_captures.is_some() {
                let status = execution.result.status;
                execution = measure_live_capture(
                    collection.host_captures.as_deref().unwrap_or(&[]),
                    &collection,
                    &request.options,
                    true,
                )?;
                execution.result.status = status;
            }
            execution
        }
        (Err(error), Ok(())) => {
            if cuda_capture && collection.host_captures.is_some() {
                return match measure_live_capture(
                    collection.host_captures.as_deref().unwrap_or(&[]),
                    &collection,
                    &request.options,
                    true,
                ) {
                    Ok(_) => Err(error),
                    Err(final_error) => Err(final_error),
                };
            }
            return Err(error);
        }
        (Ok(execution), Err(cleanup)) => {
            return Err(cleanup.with_artifact_events(execution.events));
        }
        (Err(mut error), Err(cleanup)) => {
            let artifact_events = error.artifact_events.take();
            let mut failure = CommandFailure::new(
                ErrorCode::CleanupFailed,
                format!(
                    "{}; original measurement error: {}",
                    cleanup.message, error.message
                ),
                cleanup.recoverable,
            )
            .with_detail("cleanup_phase", "stop_cupti")
            .with_detail("original_error_code", error.code.to_string())
            .with_detail("cleanup_error_code", cleanup.code.to_string())
            .with_hint("verify the target state before starting another measurement");
            if let Some(events) = artifact_events {
                failure = failure.with_artifact_events(events);
            }
            return Err(failure);
        }
    };
    if collection.agent_injected {
        let mut details = BTreeMap::new();
        if let Some(major) = collection.agent_major {
            details.insert("cuda_major".to_owned(), serde_json::Value::from(major));
        }
        if let Some(path) = collection.agent_path.as_deref() {
            details.insert(
                "agent_path".to_owned(),
                serde_json::Value::from(path.display().to_string()),
            );
        }
        if let Some(path) = collection.cupti_path.as_deref() {
            details.insert(
                "cupti_path".to_owned(),
                serde_json::Value::from(path.display().to_string()),
            );
        }
        execution.result.warnings.push(Warning {
            code: "CUPTI_AGENT_INJECTED".to_owned(),
            message: "xprobe injected the CUPTI agent and left the shared object mapped".to_owned(),
            details,
        });
    }
    Ok(execution)
}

fn validate_live_limits(request: &LiveMeasureRequest) -> Result<(), CommandFailure> {
    if request.timeout.is_zero() {
        return Err(CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            "timeout must be greater than zero",
            true,
        ));
    }
    if request.options.samples == Some(0)
        || request
            .options
            .duration
            .is_some_and(|duration| duration.is_zero())
        || request.options.max_events == 0
        || (request.options.samples.is_none() && request.options.duration.is_none())
    {
        return Err(CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            "live measurement requires positive samples or duration and max-events limits",
            true,
        ));
    }
    Ok(())
}

fn prepare_live_collection(request: &LiveMeasureRequest) -> Result<LiveCollection, CommandFailure> {
    let report = inspect::run(request.pid).map_err(|error| {
        CommandFailure::new(error.code(), error.to_string(), error.recoverable())
    })?;
    if request
        .expected_target
        .as_ref()
        .is_some_and(|expected| expected != &report.target)
    {
        return Err(CommandFailure::new(
            ErrorCode::TargetReused,
            "trace specification target identity no longer matches the process",
            true,
        ));
    }
    let validation = validate::run(
        &report,
        &request.options.start_selector,
        &request.options.end_selector,
        request.match_policy_text,
    )
    .map_err(|error| CommandFailure::new(error.code(), error.to_string(), error.recoverable()))?;
    if let Some(issue) = validation.issues.first() {
        return Err(CommandFailure::new(issue.code, issue.message.clone(), true)
            .with_detail(
                "recommended_policy",
                match_policy_name(validation.policy_recommendation.policy),
            )
            .with_detail(
                "compatible_policies",
                serde_json::to_value(&validation.policy_recommendation.compatible_policies)
                    .expect("match policies must serialize"),
            )
            .with_hint("rerun validate with an explicitly compatible policy"));
    }

    let activation = prepare_cupti_activation(&report, &validation, request)?;
    let arm_config = cupti_arm_config(&validation, request.options.max_events)?;
    let baseline = arm_cupti_capture(&activation, arm_config.as_ref(), request)?;
    let socket = activation.socket;
    let baseline_timestamp = baseline
        .as_ref()
        .and_then(|capture| capture.events.last())
        .map(|event| event.timestamp_ns);
    let baseline_dropped = baseline
        .as_ref()
        .map_or(0, |capture| capture.dropped_records);
    let baseline_unknown = baseline
        .as_ref()
        .map_or(0, |capture| capture.unknown_records);
    let baseline_observed = baseline
        .as_ref()
        .map_or(0, |capture| capture.observed_records);
    let started = Instant::now();
    let deadline = started.checked_add(request.timeout).ok_or_else(|| {
        CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            "timeout exceeds Instant range",
            true,
        )
    })?;
    let collection_end = request
        .options
        .duration
        .and_then(|duration| started.checked_add(duration));
    let collectors = start_host_collectors(&report, &validation, request)?;
    let host_captures = collectors.handles.is_empty().then(Vec::new);

    Ok(LiveCollection {
        report,
        socket,
        deadline,
        collection_end,
        baseline_timestamp,
        baseline_dropped,
        baseline_unknown,
        baseline_observed,
        collectors,
        host_captures,
        latest_cuda: None,
        cuda_record_offset: 0,
        managed_agent: activation.managed,
        cupti_armed: baseline.is_some(),
        agent_injected: activation.injected,
        agent_major: activation.major,
        agent_path: activation.agent_path,
        cupti_path: activation.cupti_path,
    })
}

fn arm_cupti_capture(
    activation: &CuptiActivation,
    config: Option<&cupti::CuptiArmConfig>,
    request: &LiveMeasureRequest,
) -> Result<Option<cupti::CuptiCapture>, CommandFailure> {
    let (Some(path), Some(config)) = (activation.socket.as_deref(), config) else {
        assert!(activation.socket.is_none() && config.is_none());
        return Ok(None);
    };
    let capture = match cupti::arm(path, request.timeout, &request.options.session_id, config) {
        Ok(capture) => capture,
        Err(error) => {
            let failure =
                CommandFailure::new(ErrorCode::CuptiNotAvailable, error.to_string(), true);
            return cleanup_failed_arm(activation, request, failure);
        }
    };
    if capture.state != cupti::CuptiCaptureState::Active {
        let failure = CommandFailure::new(
            ErrorCode::CuptiNotAvailable,
            format!(
                "CUPTI Agent did not enter active state after ARM: {:?}",
                capture.state
            ),
            true,
        );
        return cleanup_failed_arm(activation, request, failure);
    }
    Ok(Some(capture))
}

fn cleanup_failed_arm(
    activation: &CuptiActivation,
    request: &LiveMeasureRequest,
    failure: CommandFailure,
) -> Result<Option<cupti::CuptiCapture>, CommandFailure> {
    if !activation.managed {
        return Err(failure);
    }
    let path = activation
        .socket
        .as_deref()
        .expect("managed activation has a socket");
    match cupti::close(path, request.timeout, &request.options.session_id, 0) {
        Ok(_) => Err(failure),
        Err(cleanup) => Err(CommandFailure::new(
            ErrorCode::CleanupFailed,
            format!(
                "failed to close CUPTI agent after ARM error: {cleanup}; original error: {}",
                failure.message
            ),
            true,
        )
        .with_detail("cleanup_phase", "close_after_arm_failure")
        .with_detail("original_error_code", failure.code.to_string())
        .with_hint("verify the target state before starting another measurement")),
    }
}

fn cupti_arm_config(
    validation: &ValidationResult,
    max_events: usize,
) -> Result<Option<cupti::CuptiArmConfig>, CommandFailure> {
    if !validation.requirements.needs_cupti {
        return Ok(None);
    }
    let filters = [&validation.start, &validation.end]
        .into_iter()
        .filter_map(|endpoint| endpoint.cuda.as_ref())
        .map(cupti_event_filter)
        .collect::<Result<Vec<_>, _>>()?;
    let record_capacity = u64::try_from(max_events).map_err(|error| {
        CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            format!("max-events exceeds the CUPTI Agent range: {error}"),
            true,
        )
    })?;
    Ok(Some(cupti::CuptiArmConfig {
        record_capacity,
        filters,
    }))
}

fn cupti_event_filter(
    selector: &ResolvedCudaSelector,
) -> Result<cupti::CuptiEventFilter, CommandFailure> {
    let record_kind = match selector.event_type {
        EventType::CudaApiEntry => cupti::CuptiRecordKind::CudaApiEntry,
        EventType::CudaApiExit => cupti::CuptiRecordKind::CudaApiExit,
        EventType::GpuKernelStart => cupti::CuptiRecordKind::GpuKernelStart,
        EventType::GpuKernelEnd => cupti::CuptiRecordKind::GpuKernelEnd,
        EventType::GpuMemcpyStart => cupti::CuptiRecordKind::GpuMemcpyStart,
        EventType::GpuMemcpyEnd => cupti::CuptiRecordKind::GpuMemcpyEnd,
        EventType::GpuMemsetStart => cupti::CuptiRecordKind::GpuMemsetStart,
        EventType::GpuMemsetEnd => cupti::CuptiRecordKind::GpuMemsetEnd,
        _ => {
            return Err(CommandFailure::new(
                ErrorCode::InvalidEventSelector,
                "validated CUDA endpoint has a non-CUDA event type",
                false,
            ));
        }
    };
    let api_domain = match selector.api_domain.as_deref() {
        None => cupti::CuptiApiDomain::Any,
        Some("driver_api") => cupti::CuptiApiDomain::Driver,
        Some("runtime_api") => cupti::CuptiApiDomain::Runtime,
        Some(domain) => {
            return Err(CommandFailure::new(
                ErrorCode::InvalidEventSelector,
                format!("validated CUDA endpoint has unsupported API domain {domain:?}"),
                false,
            ));
        }
    };
    let memcpy_kind = match selector.memcpy_kind {
        None | Some(MemcpyKind::Unknown) => cupti::CuptiMemcpyKind::Any,
        Some(MemcpyKind::HostToDevice) => cupti::CuptiMemcpyKind::HostToDevice,
        Some(MemcpyKind::DeviceToHost) => cupti::CuptiMemcpyKind::DeviceToHost,
        Some(MemcpyKind::DeviceToDevice) => cupti::CuptiMemcpyKind::DeviceToDevice,
        Some(MemcpyKind::HostToHost) => cupti::CuptiMemcpyKind::HostToHost,
        Some(MemcpyKind::PeerToPeer) => cupti::CuptiMemcpyKind::PeerToPeer,
    };
    let name = if let Some(name) = selector.api_name.as_ref() {
        cupti::CuptiNameFilter::Exact(name.clone())
    } else if let Some(pattern) = selector.kernel_name_regex.as_deref() {
        bounded_kernel_name_filter(pattern)
    } else {
        cupti::CuptiNameFilter::Any
    };
    Ok(cupti::CuptiEventFilter {
        record_kind,
        api_domain,
        memcpy_kind,
        name,
    })
}

fn bounded_kernel_name_filter(pattern: &str) -> cupti::CuptiNameFilter {
    if pattern == ".*" {
        return cupti::CuptiNameFilter::Any;
    }
    let candidates = [
        ("^", "$", 1_u8),
        ("^", ".*", 2),
        (".*", "$", 3),
        (".*", ".*", 4),
        ("^", "", 2),
        ("", "$", 3),
        (".*", "", 4),
        ("", "", 4),
    ];
    for (prefix, suffix, kind) in candidates {
        let Some(inner) = pattern
            .strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(suffix))
        else {
            continue;
        };
        let Some(literal) = regex_literal(inner) else {
            continue;
        };
        if literal.is_empty() || literal.len() >= 128 {
            continue;
        }
        return match kind {
            1 => cupti::CuptiNameFilter::Exact(literal),
            2 => cupti::CuptiNameFilter::Prefix(literal),
            3 => cupti::CuptiNameFilter::Suffix(literal),
            4 => cupti::CuptiNameFilter::Contains(literal),
            _ => unreachable!("fixed kernel filter kind"),
        };
    }
    cupti::CuptiNameFilter::Any
}

fn regex_literal(pattern: &str) -> Option<String> {
    let mut literal = String::with_capacity(pattern.len());
    let mut characters = pattern.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            let escaped = characters.next()?;
            if escaped.is_ascii_alphanumeric() {
                return None;
            }
            literal.push(escaped);
        } else if ".+*?()|[]{}^$".contains(character) {
            return None;
        } else {
            literal.push(character);
        }
    }
    Some(literal)
}

struct CuptiActivation {
    socket: Option<PathBuf>,
    managed: bool,
    injected: bool,
    major: Option<u32>,
    agent_path: Option<PathBuf>,
    cupti_path: Option<PathBuf>,
}

struct AgentSelection {
    path: PathBuf,
    major: Option<u32>,
    cupti_path: Option<PathBuf>,
}

fn prepare_cupti_activation(
    report: &ProcessReport,
    validation: &ValidationResult,
    request: &LiveMeasureRequest,
) -> Result<CuptiActivation, CommandFailure> {
    if !validation.requirements.needs_cupti {
        if request.cupti_socket.is_some() {
            return Err(CommandFailure::new(
                ErrorCode::InvalidEventSelector,
                "--cupti-socket is only valid when a CUDA endpoint is selected",
                true,
            ));
        }
        return Ok(CuptiActivation {
            socket: None,
            managed: false,
            injected: false,
            major: None,
            agent_path: None,
            cupti_path: None,
        });
    }
    if let Some(socket) = request.cupti_socket.clone() {
        return Ok(CuptiActivation {
            socket: Some(socket),
            managed: false,
            injected: false,
            major: None,
            agent_path: None,
            cupti_path: None,
        });
    }

    let socket = std::env::temp_dir().join(format!(
        "xprobe-{}-{}.sock",
        request.pid,
        std::process::id()
    ));
    let selection = if report.cuda.xprobe_cupti_loaded {
        AgentSelection {
            path: PathBuf::new(),
            major: cupti_compat::target_major(report)
                .map_err(|error| CommandFailure::new(error.code(), error.to_string(), true))?,
            cupti_path: None,
        }
    } else {
        resolve_agent_path(report, request.agent_path.as_deref())?
    };
    eprintln!(
        "xprobe: warning: activating the CUPTI agent modifies target PID {}{}{}",
        request.pid,
        selection
            .major
            .map_or_else(String::new, |major| format!(" with CUDA {major} Agent")),
        selection
            .cupti_path
            .as_deref()
            .map_or_else(String::new, |path| format!(" using {}", path.display()))
    );
    let record_capacity = u64::try_from(request.options.max_events).map_err(|error| {
        CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            format!("max-events exceeds the CUPTI Agent range: {error}"),
            true,
        )
    })?;
    let activation = inject::activate(
        report,
        &selection.path,
        &socket,
        record_capacity,
        request.timeout,
    )
    .map_err(|error| CommandFailure::new(error.code(), error.to_string(), error.recoverable()))?;
    Ok(CuptiActivation {
        socket: Some(activation.socket_path),
        managed: true,
        injected: activation.injected,
        major: selection.major,
        agent_path: activation.injected.then_some(selection.path),
        cupti_path: selection.cupti_path,
    })
}

fn resolve_agent_path(
    report: &ProcessReport,
    configured: Option<&Path>,
) -> Result<AgentSelection, CommandFailure> {
    if let Some(path) = configured {
        return Ok(AgentSelection {
            path: path.to_owned(),
            major: cupti_compat::target_major(report)
                .map_err(|error| CommandFailure::new(error.code(), error.to_string(), true))?,
            cupti_path: None,
        });
    }
    if let Some(path) = std::env::var_os("XPROBE_CUPTI_AGENT_PATH") {
        return Ok(AgentSelection {
            path: PathBuf::from(path),
            major: cupti_compat::target_major(report)
                .map_err(|error| CommandFailure::new(error.code(), error.to_string(), true))?,
            cupti_path: None,
        });
    }
    let cupti = cupti_compat::resolve_library(report)
        .map_err(|error| CommandFailure::new(error.code(), error.to_string(), true))?;
    let executable = std::env::current_exe().map_err(|error| {
        CommandFailure::new(
            ErrorCode::CuptiNotAvailable,
            format!("failed to locate xprobe executable: {error}"),
            true,
        )
    })?;
    let parent = executable
        .parent()
        .expect("executable has a parent directory");
    let candidates = [
        parent.join(format!(
            "../lib/xprobe/cuda{}/libxprobe-cupti.so",
            cupti.major
        )),
        parent.join(format!("cuda{}/libxprobe-cupti.so", cupti.major)),
        PathBuf::from(format!(
            "build/cupti/cuda{}/libxprobe-cupti.so",
            cupti.major
        )),
    ];
    let path = candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            CommandFailure::new(
                ErrorCode::CuptiNotAvailable,
                format!(
                    "CUDA {} CUPTI agent was not found; pass --agent or set XPROBE_CUPTI_AGENT_PATH",
                    cupti.major
                ),
                true,
            )
        })?;
    Ok(AgentSelection {
        path,
        major: Some(cupti.major),
        cupti_path: Some(cupti.path),
    })
}

fn stop_cupti_agent(
    collection: &mut LiveCollection,
    request: &LiveMeasureRequest,
) -> Result<(), CommandFailure> {
    if !collection.cupti_armed {
        return Ok(());
    }
    let socket = collection
        .socket
        .as_deref()
        .expect("armed CUPTI agent has a socket");
    collection.cupti_armed = false;
    let capture = if collection.managed_agent {
        cupti::close(
            socket,
            request.timeout,
            &request.options.session_id,
            collection.cuda_record_offset,
        )
    } else {
        cupti::stop(
            socket,
            request.timeout,
            &request.options.session_id,
            collection.cuda_record_offset,
        )
    }
    .map_err(|error| {
        CommandFailure::new(ErrorCode::CleanupFailed, error.to_string(), true)
            .with_detail("cleanup_phase", "stop_cupti")
            .with_hint("verify the target state before starting another measurement")
    })?;
    append_cuda_capture(collection, capture)?;
    collection.managed_agent = false;
    Ok(())
}

impl Drop for LiveCollection {
    fn drop(&mut self) {
        if self.cupti_armed {
            if let Some(socket) = self.socket.as_deref() {
                let result = if self.managed_agent {
                    cupti::close(
                        socket,
                        Duration::from_secs(2),
                        "xp_cleanup",
                        self.cuda_record_offset,
                    )
                } else {
                    cupti::stop(
                        socket,
                        Duration::from_secs(2),
                        "xp_cleanup",
                        self.cuda_record_offset,
                    )
                };
                if let Err(error) = result {
                    eprintln!("xprobe: failed to stop CUPTI agent during cleanup: {error}");
                }
            }
        }
    }
}

fn start_host_collectors(
    report: &ProcessReport,
    validation: &ValidationResult,
    request: &LiveMeasureRequest,
) -> Result<HostCollectors, CommandFailure> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut probes = Vec::new();
    for endpoint in [&validation.start, &validation.end] {
        let Some(probe) = endpoint.host.as_ref() else {
            continue;
        };
        if probes
            .iter()
            .any(|existing: &ResolvedProbe| existing.selector == probe.selector)
        {
            continue;
        }
        probes.push(probe.clone());
    }
    let host_timeout = request
        .options
        .duration
        .map_or(request.timeout, |duration| duration.min(request.timeout));
    let host_samples = request
        .options
        .samples
        .unwrap_or(request.options.max_events);
    let mut receivers = Vec::with_capacity(probes.len());
    let handles = probes
        .into_iter()
        .enumerate()
        .map(|(index, probe)| {
            let (ready, receiver) = mpsc::sync_channel(1);
            receivers.push(receiver);
            let offset = if probe.symbol.is_some() {
                0
            } else {
                probe.file_offset
            };
            let capture_request = UprobeRequest {
                target: report.target.clone(),
                binary: PathBuf::from(&probe.binary_path),
                symbol: probe.symbol,
                offset,
                probe_kind: probe.probe_kind,
                probe_id: u32::try_from(index + 1).expect("two endpoints fit u32"),
                samples: host_samples,
                timeout: host_timeout,
                cancelled: Arc::clone(&cancelled),
                ready: Some(ready),
            };
            thread::spawn(move || uprobe::capture(&capture_request))
        })
        .collect();
    let mut collectors = HostCollectors { cancelled, handles };
    for receiver in receivers {
        match receiver.recv_timeout(request.timeout) {
            Ok(()) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                collectors.cancel();
                return match collectors.join() {
                    Err(error) => Err(error),
                    Ok(_) => Err(CommandFailure::new(
                        ErrorCode::Internal,
                        "host collector exited before reporting readiness",
                        false,
                    )),
                };
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                collectors.cancel();
                collectors.join()?;
                return Err(CommandFailure::new(
                    ErrorCode::SessionLimitExceeded,
                    "timed out waiting for host collector readiness",
                    true,
                ));
            }
        }
    }
    Ok(collectors)
}

fn refresh_live_sources(
    collection: &mut LiveCollection,
    request: &LiveMeasureRequest,
) -> Result<(), CommandFailure> {
    if collection.host_captures.is_none() && collection.collectors.finished() {
        collection.host_captures = Some(collection.collectors.join()?);
    }
    let Some(path) = collection.socket.as_deref() else {
        return Ok(());
    };
    let remaining = collection
        .deadline
        .saturating_duration_since(Instant::now());
    if remaining <= SNAPSHOT_QUIET_PERIOD {
        collection.collectors.cancel();
        return Ok(());
    }
    let capture = cupti::snapshot(
        path,
        remaining,
        &request.options.session_id,
        collection.cuda_record_offset,
    )
    .map_err(|error| CommandFailure::new(ErrorCode::CuptiNotAvailable, error.to_string(), true))?;
    append_cuda_capture(collection, capture)?;
    Ok(())
}

fn append_cuda_capture(
    collection: &mut LiveCollection,
    mut capture: cupti::CuptiCapture,
) -> Result<(), CommandFailure> {
    if capture.record_offset != collection.cuda_record_offset {
        return Err(CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!(
                "CUPTI incremental capture started at record {}, expected {}",
                capture.record_offset, collection.cuda_record_offset
            ),
            false,
        ));
    }
    let returned = u64::try_from(capture.events.len()).map_err(|error| {
        CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!("CUPTI incremental event count exceeds u64: {error}"),
            false,
        )
    })?;
    let next_offset = capture.record_offset.checked_add(returned).ok_or_else(|| {
        CommandFailure::new(
            ErrorCode::TraceExportFailed,
            "CUPTI incremental record offset overflowed",
            false,
        )
    })?;
    if let Some(accumulated) = collection.latest_cuda.as_mut() {
        if accumulated.record_capacity != capture.record_capacity {
            return Err(CommandFailure::new(
                ErrorCode::TraceExportFailed,
                format!(
                    "CUPTI record capacity changed from {} to {} during capture",
                    accumulated.record_capacity, capture.record_capacity
                ),
                false,
            ));
        }
        if capture.observed_records < accumulated.observed_records
            || capture.agent_dropped_records < accumulated.agent_dropped_records
            || capture.cupti_dropped_records < accumulated.cupti_dropped_records
            || capture.unknown_records < accumulated.unknown_records
        {
            return Err(CommandFailure::new(
                ErrorCode::TraceExportFailed,
                "CUPTI incremental counters moved backwards",
                false,
            ));
        }
        accumulated.state = capture.state;
        accumulated.stop_reason = capture.stop_reason;
        accumulated.observed_records = capture.observed_records;
        accumulated.agent_dropped_records = capture.agent_dropped_records;
        accumulated.cupti_dropped_records = capture.cupti_dropped_records;
        accumulated.dropped_records = capture.dropped_records;
        accumulated.unknown_records = capture.unknown_records;
        accumulated.events.append(&mut capture.events);
    } else {
        capture.record_offset = 0;
        collection.latest_cuda = Some(capture);
    }
    collection.cuda_record_offset = next_offset;
    Ok(())
}

fn evaluate_live_result(
    collection: &LiveCollection,
    request: &LiveMeasureRequest,
    now: Instant,
) -> Result<Option<MeasurementExecution>, CommandFailure> {
    let Some(host) = collection.host_captures.as_ref() else {
        return Ok(None);
    };
    if collection.socket.is_some() && collection.latest_cuda.is_none() {
        return Ok(None);
    }
    let mut execution = match measure_live_capture(host, collection, &request.options, false) {
        Ok(execution) => execution,
        Err(error) if error.code == ErrorCode::NoMatchedSamples => return Ok(None),
        Err(error) => return Err(error),
    };
    let reached_samples = request.options.samples.is_some_and(|samples| {
        execution.result.measurement.samples.matched
            >= u64::try_from(samples).expect("sample limit fits u64")
    });
    let reached_duration = collection.collection_end.is_some_and(|end| now >= end);
    if reached_samples || reached_duration {
        inspect::verify_target(&collection.report.target).map_err(|error| {
            CommandFailure::new(error.code(), error.to_string(), error.recoverable())
        })?;
        return Ok(Some(execution));
    }
    if now >= collection.deadline {
        execution.result.status = SessionStatus::TimedOut;
        return Ok(Some(execution));
    }
    Ok(None)
}

fn finish_live_timeout(
    collection: &mut LiveCollection,
    request: &LiveMeasureRequest,
) -> Result<MeasurementExecution, CommandFailure> {
    collection.collectors.cancel();
    if collection.host_captures.is_none() {
        collection.host_captures = Some(collection.collectors.join()?);
    }
    let mut execution = measure_live_capture(
        collection
            .host_captures
            .as_ref()
            .expect("host captures were assigned"),
        collection,
        &request.options,
        true,
    )
    .map_err(|mut error| {
        if error.code == ErrorCode::NoMatchedSamples {
            let host_events = collection.host_captures.as_ref().map_or(0, |captures| {
                captures.iter().map(|capture| capture.events.len()).sum()
            });
            let cuda_events = collection.latest_cuda.as_ref().map_or(0, |capture| {
                capture
                    .events
                    .iter()
                    .filter(|event| {
                        collection
                            .baseline_timestamp
                            .is_none_or(|start| event.timestamp_ns > start)
                    })
                    .count()
            });
            error.message = format!(
                "no event pairs matched before the live measurement timeout \
                 (host events: {host_events}, CUDA events: {cuda_events})"
            );
            error
                .with_detail("timed_out", true)
                .with_detail("host_events", host_events as u64)
                .with_detail("cuda_events", cuda_events as u64)
        } else {
            error
        }
    })?;
    execution.result.status = SessionStatus::TimedOut;
    Ok(execution)
}

fn measure_live_capture(
    host_captures: &[HostCaptureResult],
    collection: &LiveCollection,
    options: &MeasureOptions,
    require_complete: bool,
) -> Result<MeasurementExecution, CommandFailure> {
    let capture = completed_live_capture(host_captures, collection, &options.session_id)?;
    reject_incomplete_capture(&capture, true, require_complete)
        .map_err(|error| error.with_artifact_events(capture.events.clone()))?;
    if capture.unknown_records != 0 {
        return Err(CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!(
                "live capture contains {} unknown CUPTI activity records",
                capture.unknown_records
            ),
            false,
        )
        .with_detail("unknown_records", capture.unknown_records)
        .with_hint("rebuild xprobe and the CUPTI Agent from the same release")
        .with_artifact_events(capture.events));
    }
    let options = MeasureOptions {
        dropped_events: capture.dropped_records,
        ..options.clone()
    };
    let mut result = measure(&capture.events, &options).map_err(|error| {
        measurement_failure(&error, &options, &capture.events, require_complete)
    })?;
    apply_collection_summary(&mut result, &capture);
    Ok(MeasurementExecution {
        result,
        events: capture.events,
    })
}

fn completed_live_capture(
    host_captures: &[HostCaptureResult],
    collection: &LiveCollection,
    session_id: &str,
) -> Result<completed::CompletedCapture, CommandFailure> {
    let mut captures = host_captures
        .iter()
        .map(|capture| completed::CompletedCapture {
            dropped_records: capture.dropped,
            unknown_records: 0,
            record_limit_reached: None,
            capture_failed: false,
            cupti: None,
            events: capture.events.clone(),
        })
        .collect::<Vec<_>>();
    if let Some(cuda) = collection.latest_cuda.as_ref() {
        let dropped_records = cuda
            .dropped_records
            .checked_sub(collection.baseline_dropped)
            .ok_or_else(|| {
                CommandFailure::new(
                    ErrorCode::TraceExportFailed,
                    "CUPTI dropped-record counter moved backwards",
                    false,
                )
            })?;
        let unknown_records = cuda
            .unknown_records
            .checked_sub(collection.baseline_unknown)
            .ok_or_else(|| {
                CommandFailure::new(
                    ErrorCode::TraceExportFailed,
                    "CUPTI unknown-record counter moved backwards",
                    false,
                )
            })?;
        let observed_records = cuda
            .observed_records
            .checked_sub(collection.baseline_observed)
            .ok_or_else(|| {
                CommandFailure::new(
                    ErrorCode::TraceExportFailed,
                    "CUPTI observed-record counter moved backwards",
                    false,
                )
            })?;
        captures.push(completed::CompletedCapture {
            dropped_records,
            unknown_records,
            record_limit_reached: (cuda.state == cupti::CuptiCaptureState::LimitReached)
                .then_some(cuda.record_capacity),
            capture_failed: matches!(
                cuda.state,
                cupti::CuptiCaptureState::Idle | cupti::CuptiCaptureState::Failed
            ),
            cupti: Some(completed::CompletedCuptiStatistics {
                complete: cuda.state == cupti::CuptiCaptureState::Stopped,
                record_capacity: cuda.record_capacity,
                observed_records,
                dropped_records,
            }),
            events: cuda
                .events
                .iter()
                .filter(|event| {
                    collection
                        .baseline_timestamp
                        .is_none_or(|start| event.timestamp_ns > start)
                })
                .cloned()
                .collect(),
        });
    }
    completed::merge(captures, session_id).map_err(|error| {
        CommandFailure::new(ErrorCode::TraceExportFailed, error.to_string(), false)
    })
}

fn reject_incomplete_capture(
    capture: &completed::CompletedCapture,
    live: bool,
    require_complete: bool,
) -> Result<(), CommandFailure> {
    if capture.capture_failed {
        return Err(CommandFailure::new(
            ErrorCode::CuptiNotAvailable,
            format!(
                "{}CUPTI capture entered a failed state",
                if live { "live " } else { "" }
            ),
            true,
        )
        .with_detail("capture_state", "failed")
        .with_hint("inspect target CUDA/CUPTI compatibility and retry a fresh bounded capture"));
    }
    if let Some(capacity) = capture.record_limit_reached {
        let mut failure = CommandFailure::new(
            ErrorCode::EventRateTooHigh,
            format!("CUPTI capture reached its configured limit of {capacity} records"),
            true,
        )
        .with_detail("record_capacity", capacity)
        .with_hint("narrow the selectors or explicitly increase max-events");
        if let Some(cupti) = capture.cupti.as_ref() {
            failure = failure
                .with_detail("observed_records", cupti.observed_records)
                .with_detail("retained_records", capture.events.len() as u64)
                .with_detail("dropped_records", cupti.dropped_records);
        }
        return Err(failure);
    }
    if require_complete && capture.cupti.as_ref().is_some_and(|cupti| !cupti.complete) {
        return Err(CommandFailure::new(
            ErrorCode::CuptiNotAvailable,
            format!(
                "{}CUPTI capture was not stopped before measurement",
                if live { "live " } else { "" }
            ),
            true,
        )
        .with_detail("capture_state", "active")
        .with_hint("stop the CUPTI capture before using it as completed input"));
    }
    Ok(())
}

fn apply_collection_summary(result: &mut MeasurementResult, capture: &completed::CompletedCapture) {
    let Some(cupti) = capture.cupti.as_ref() else {
        return;
    };
    let retained_records = result.collection.cuda_events;
    let buffer_utilization = utilization(retained_records, cupti.record_capacity);
    result.collection.cupti = Some(CuptiCollectionSummary {
        record_capacity: cupti.record_capacity,
        observed_records: cupti.observed_records,
        retained_records,
        dropped_records: cupti.dropped_records,
        buffer_utilization,
    });
}

#[allow(clippy::cast_precision_loss)]
fn utilization(retained: u64, capacity: u64) -> f64 {
    if capacity == 0 {
        0.0
    } else {
        retained as f64 / capacity as f64
    }
}

const fn match_policy_name(policy: MatchPolicy) -> &'static str {
    match policy {
        MatchPolicy::Exact => "exact",
        MatchPolicy::FirstAfter => "first-after",
        MatchPolicy::Nearest => "nearest",
        MatchPolicy::StackNested => "stack-nested",
        MatchPolicy::StreamOrder => "stream-order",
    }
}

fn emit_measurement(result: &MeasurementResult, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("measurement result must serialize")
        );
    } else {
        print_measurement_result(result);
    }
    ExitCode::SUCCESS
}

fn run_validate(args: ValidateArgs) -> ExitCode {
    let ValidateArgs {
        pid,
        from,
        to,
        match_policy,
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

    match validate::run(&report, &from, &to, &match_policy) {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result)
                        .expect("validation result must serialize")
                );
            } else {
                print_validation_result(&result);
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_error(error.code(), error.to_string(), error.recoverable(), json),
    }
}

fn run_resolve(args: ResolveArgs) -> ExitCode {
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

fn run_doctor(args: DoctorArgs) -> ExitCode {
    let DoctorArgs {
        json,
        no_color: _,
        non_interactive: _,
    } = args;

    match doctor::run() {
        Ok(report) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("capability report must serialize")
                );
            } else {
                print_human_report(&report);
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_error(ErrorCode::Internal, error.to_string(), false, json),
    }
}

fn run_discover(args: DiscoverArgs) -> ExitCode {
    let DiscoverArgs {
        pid,
        limit,
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
    match discover::run(&report, limit) {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).expect("discovery result must serialize")
                );
            } else {
                print_discovery_result(&result);
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_error(error.code(), error.to_string(), error.recoverable(), json),
    }
}

fn run_inspect(args: InspectArgs) -> ExitCode {
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

fn run_uprobe(args: UprobeArgs) -> ExitCode {
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

fn run_cupti(args: CuptiArgs) -> ExitCode {
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

fn mapped_binary(report: &ProcessReport, binary: &Path) -> Result<PathBuf, String> {
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

fn emit_error(code: ErrorCode, message: String, recoverable: bool, json: bool) -> ExitCode {
    emit_xprobe_error(
        XprobeError {
            code,
            message,
            recoverable,
            details: BTreeMap::new(),
            hints: Vec::new(),
        },
        json,
    )
}

fn emit_command_failure(error: CommandFailure, json: bool) -> ExitCode {
    emit_xprobe_error(
        XprobeError {
            code: error.code,
            message: error.message,
            recoverable: error.recoverable,
            details: error.details,
            hints: error.hints,
        },
        json,
    )
}

fn emit_xprobe_error(error: XprobeError, json: bool) -> ExitCode {
    let code = error.code;
    let response = ErrorResponse::new(error);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).expect("error response must serialize")
        );
    } else {
        eprintln!("{code}: {}", response.error.message);
    }

    match code {
        ErrorCode::TargetNotFound | ErrorCode::TargetExited | ErrorCode::TargetReused => {
            ExitCode::from(3)
        }
        ErrorCode::PermissionDenied => ExitCode::from(4),
        _ => ExitCode::from(1),
    }
}

fn print_human_report(report: &CapabilityReport) {
    println!(
        "xprobe doctor (schema {})",
        schema_version(report.schema_version)
    );
    println!();
    println!("Environment:");
    println!("  OS             {}", report.environment.operating_system);
    println!("  architecture   {}", report.environment.architecture);
    println!("  kernel         {}", report.environment.kernel_release);
    println!("  effective UID  {}", report.environment.effective_uid);
    println!(
        "  container      {}",
        report
            .environment
            .container
            .as_deref()
            .unwrap_or("none detected")
    );
    println!("  PID namespace  {}", report.environment.pid_namespace);
    println!();
    println!("Capabilities:");
    println!("  uprobe          {}", yes_no(report.capabilities.uprobe));
    println!(
        "  uretprobe       {}",
        yes_no(report.capabilities.uretprobe)
    );
    println!(
        "  tracepoint      {}",
        yes_no(report.capabilities.tracepoint)
    );
    println!(
        "  CUDA callback   {}",
        yes_no(report.capabilities.cuda_callback)
    );
    println!(
        "  CUDA activity   {}",
        yes_no(report.capabilities.cuda_activity)
    );
    println!(
        "  runtime inject  {}",
        yes_no(report.capabilities.runtime_injection)
    );
    println!();
    println!("Checks:");
    print_check("BTF", &report.checks.btf);
    print_check("eBPF permissions", &report.checks.ebpf_permissions);
    print_check("kernel lockdown", &report.checks.kernel_lockdown);
    print_check("perf paranoid", &report.checks.perf_event_paranoid);
    print_check("ptrace scope", &report.checks.ptrace_scope);
    print_check("NVIDIA driver", &report.checks.nvidia_driver);
    print_check("CUDA driver", &report.checks.cuda_driver);
    print_check("CUDA toolkit", &report.checks.cuda_toolkit);
    print_check("CUPTI", &report.checks.cupti);

    if !report.warnings.is_empty() {
        println!();
        println!("Warnings:");
        for warning in &report.warnings {
            println!("  {}: {}", warning.code, warning.message);
        }
    }
}

fn print_process_report(report: &ProcessReport) {
    println!("Process: PID {}", report.target.pid);
    println!("Executable: {}", report.executable);
    println!("Start time: {} ticks", report.target.process_start_time);
    println!("Namespace PIDs: {:?}", report.namespace_pids);
    println!("Mount namespace: {}", report.mount_namespace);
    println!(
        "Credentials: uid={} gid={}",
        report.credentials.effective_uid, report.credentials.effective_gid
    );
    println!();
    println!("CUDA:");
    println!("  libcuda          {}", yes_no(report.cuda.libcuda_loaded));
    println!(
        "  libcudart        {}",
        yes_no(report.cuda.libcudart_loaded)
    );
    println!(
        "  xprobe CUPTI    {}",
        yes_no(report.cuda.xprobe_cupti_loaded)
    );
    println!("  context          {:?}", report.cuda.context.status);
    println!();
    println!("Loaded shared libraries: {}", report.loaded_libraries.len());
}

fn print_discovery_result(result: &DiscoveryResult) {
    println!("Root: PID {}", result.root.pid);
    println!(
        "CUDA workers: {} of {}{}",
        result.candidates.len(),
        result.total_candidates,
        if result.truncated { " (truncated)" } else { "" }
    );
    for candidate in &result.candidates {
        println!(
            "  PID {} parent={} GPUs={} {}",
            candidate.target.pid,
            candidate.parent_pid,
            candidate.gpu_uuids.join(","),
            candidate.executable
        );
    }
    for warning in &result.warnings {
        eprintln!("{}: {}", warning.code, warning.message);
    }
}

fn print_host_capture(result: &HostCaptureResult) {
    println!(
        "Captured {} event(s), dropped {}, timed out: {}",
        result.captured, result.dropped, result.timed_out
    );
    for event in &result.events {
        println!(
            "  {}  pid={} tid={} cpu={} probe={}",
            event.timestamp_ns,
            event.pid,
            event.tid,
            event
                .cpu
                .map_or_else(|| "-".to_owned(), |cpu| cpu.to_string()),
            result.probe_id
        );
    }
}

fn print_resolved_probe(resolved: &ResolvedProbe) {
    println!("Target: PID {}", resolved.target.pid);
    println!("Binary: {}", resolved.binary_path);
    println!(
        "Build ID: {}",
        resolved.build_id.as_deref().unwrap_or("unavailable")
    );
    println!("Object: {:?}", resolved.object_kind);
    println!("Probe: {:?}", resolved.probe_kind);
    if let Some(symbol) = &resolved.symbol {
        println!("Symbol: {symbol}");
    }
    println!("File offset: {:#x}", resolved.file_offset);
    println!("Runtime address: {:#x}", resolved.runtime_address);
    println!(
        "Mapping: {:#x}-{:#x} (file offset {:#x})",
        resolved.mapping.start_address, resolved.mapping.end_address, resolved.mapping.file_offset
    );
}

fn print_validation_result(result: &ValidationResult) {
    println!(
        "Validation: {}",
        if result.valid { "valid" } else { "invalid" }
    );
    println!("Target: PID {}", result.target.pid);
    println!("Start: {}", result.start.selector);
    println!("End: {}", result.end.selector);
    println!("Match: {:?}", result.match_policy);
    println!(
        "Recommended match: {:?} ({:?})",
        result.policy_recommendation.policy, result.policy_recommendation.reason
    );
    println!(
        "Agent activation: {:?}",
        result.requirements.agent_activation
    );
    println!("Target mutation: {}", result.requirements.target_mutation);
    for issue in &result.issues {
        println!("Issue: {}: {}", issue.code, issue.message);
    }
    for warning in &result.warnings {
        println!("Warning: {}: {}", warning.code, warning.message);
    }
}

fn print_measurement_result(result: &MeasurementResult) {
    let latency = &result.measurement.latency_ns;
    println!(
        "Measurement: {}",
        result.measurement.name.as_deref().unwrap_or("unnamed")
    );
    println!("Matched samples: {}", result.measurement.samples.matched);
    println!("Evidence pairs: {}", result.evidence.len());
    println!("Correlation: {}", result.correlation.method);
    println!("Clock: {}", result.clock.alignment);
    println!("Latency (ns):");
    println!("  min   {}", latency.min);
    println!("  mean  {:.2}", latency.mean);
    println!("  p50   {}", latency.p50);
    println!("  p90   {}", latency.p90);
    println!("  p95   {}", latency.p95);
    println!("  p99   {}", latency.p99);
    println!("  max   {}", latency.max);
}

fn print_check(name: &str, result: &CheckResult) {
    println!(
        "  {name:<17} {:<11} {}",
        format!("{:?}", result.status).to_lowercase(),
        result.detail.as_deref().unwrap_or_default()
    );
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

const fn schema_version(version: SchemaVersion) -> &'static str {
    match version {
        SchemaVersion::V2 => "2.0",
    }
}

#[cfg(test)]
mod tests {
    use xprobe_collector::cupti::CuptiNameFilter;

    use super::{bounded_kernel_name_filter, regex_literal};

    #[test]
    fn lowers_only_equivalent_bounded_kernel_patterns() {
        assert_eq!(
            bounded_kernel_name_filter("^flash_.*"),
            CuptiNameFilter::Prefix("flash_".to_owned())
        );
        assert_eq!(
            bounded_kernel_name_filter(".*_kernel$"),
            CuptiNameFilter::Suffix("_kernel".to_owned())
        );
        assert_eq!(
            bounded_kernel_name_filter("cudaLaunch"),
            CuptiNameFilter::Contains("cudaLaunch".to_owned())
        );
        assert_eq!(
            bounded_kernel_name_filter("^(flash|attention)$"),
            CuptiNameFilter::Any
        );
    }

    #[test]
    fn decodes_escaped_regex_literals_conservatively() {
        assert_eq!(regex_literal("kernel\\.v1"), Some("kernel.v1".to_owned()));
        assert_eq!(regex_literal("kernel\\d"), None);
        assert_eq!(regex_literal("kernel+"), None);
    }
}
