use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use xprobe_collector::{
    completed, cupti,
    uprobe::{self, UprobeRequest},
};
use xprobe_core::{discover, doctor, inject, inspect, resolve, validate};
use xprobe_correlator::{MeasureOptions, measure};
use xprobe_exporter::{events_to_chrome_trace, events_to_jsonl};
use xprobe_protocol::{
    CapabilityReport, CheckResult, DiscoveryResult, ErrorCode, ErrorResponse, ExportFormat,
    HostCaptureResult, MatchPolicy, MeasurementResult, MeasurementSpec, ProcessReport,
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
    /// Measure latency from a completed bounded capture.
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
    #[arg(long)]
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

#[derive(Debug, Clone, Args)]
struct DiscoverArgs {
    /// Target process ID.
    #[arg(long)]
    pid: u32,

    /// Keep selectors containing this text in their path, symbol, or selector.
    #[arg(long)]
    query: Option<String>,

    /// Maximum number of selectors to return.
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
    /// Completed CUPTI binary, host capture JSON, or Event JSONL; repeat to merge.
    #[arg(long)]
    input: Vec<PathBuf>,

    /// Collect from a running target process instead of completed capture files.
    #[arg(long)]
    pid: Option<u32>,

    /// Unix socket exposed by the target's xprobe CUPTI agent.
    #[arg(long)]
    cupti_socket: Option<PathBuf>,

    /// CUPTI agent shared object used for automatic online injection.
    #[arg(long)]
    agent: Option<PathBuf>,

    /// Bound foreground collection and cleanup to this many milliseconds.
    #[arg(long, default_value_t = 30_000)]
    timeout_ms: u64,

    /// Start event selector.
    #[arg(long)]
    from: String,

    /// End event selector.
    #[arg(long)]
    to: String,

    /// Correlation policy: exact or first-after.
    #[arg(long = "match")]
    match_policy: String,

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
        Ok(result) => emit_measurement(&result, json),
        Err(error) => emit_error(error.code, error.message, error.recoverable, json),
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
        Err(error) => return emit_error(error.code, error.message, error.recoverable, json),
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
        ));
    }
    Ok(capture)
}

fn write_export_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn run_measure(args: MeasureArgs) -> ExitCode {
    let MeasureArgs {
        input,
        pid,
        cupti_socket,
        agent,
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
    let match_policy = match match_policy.as_str() {
        "exact" => MatchPolicy::Exact,
        "first-after" | "first_after" => MatchPolicy::FirstAfter,
        "nearest" => MatchPolicy::Nearest,
        "stack-nested" | "stack_nested" => MatchPolicy::StackNested,
        "stream-order" | "stream_order" => MatchPolicy::StreamOrder,
        _ => {
            return emit_error(
                ErrorCode::InvalidCorrelationPolicy,
                "unsupported measurement correlation policy".to_owned(),
                true,
                json,
            );
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
            Ok(result) => emit_measurement(&result, json),
            Err(error) => emit_error(error.code, error.message, error.recoverable, json),
        };
    }
    if input.is_empty() {
        return emit_error(
            ErrorCode::TraceExportFailed,
            "measure requires --input or --pid".to_owned(),
            true,
            json,
        );
    }
    if cupti_socket.is_some() {
        return emit_error(
            ErrorCode::InvalidEventSelector,
            "--cupti-socket requires --pid".to_owned(),
            true,
            json,
        );
    }

    match measure_completed_inputs(&input, &options) {
        Ok(result) => emit_measurement(&result, json),
        Err(error) => emit_error(error.code, error.message, error.recoverable, json),
    }
}

fn measure_completed_inputs(
    input: &[PathBuf],
    options: &MeasureOptions,
) -> Result<MeasurementResult, CommandFailure> {
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
    if capture.unknown_records != 0 {
        return Err(CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!(
                "capture contains {} unknown CUPTI activity records",
                capture.unknown_records
            ),
            false,
        ));
    }
    let options = MeasureOptions {
        dropped_events: capture.dropped_records,
        ..options.clone()
    };
    measure(&capture.events, &options)
        .map_err(|error| CommandFailure::new(error.code(), error.to_string(), error.recoverable()))
}

#[derive(Debug)]
struct CommandFailure {
    code: ErrorCode,
    message: String,
    recoverable: bool,
}

impl CommandFailure {
    fn new(code: ErrorCode, message: impl Into<String>, recoverable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable,
        }
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
    collectors: HostCollectors,
    host_captures: Option<Vec<HostCaptureResult>>,
    latest_cuda: Option<cupti::CuptiCapture>,
    managed_agent: bool,
    agent_injected: bool,
}

fn collect_live_measurement(
    request: &LiveMeasureRequest,
) -> Result<MeasurementResult, CommandFailure> {
    validate_live_limits(request)?;
    let mut collection = prepare_live_collection(request)?;

    let outcome = loop {
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
    };
    let managed_capture = collection.managed_agent;
    let stop_result = stop_managed_agent(&mut collection, request);
    let mut result = match (outcome, stop_result) {
        (Ok(mut result), Ok(())) => {
            if managed_capture {
                let status = result.status;
                result = measure_live_capture(
                    collection.host_captures.as_deref().unwrap_or(&[]),
                    &collection,
                    &request.options,
                )?;
                result.status = status;
            }
            result
        }
        (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
        (Err(error), Err(cleanup)) => {
            eprintln!(
                "xprobe: cleanup failed after measurement error: {}",
                cleanup.message
            );
            return Err(error);
        }
    };
    if collection.agent_injected {
        result.warnings.push(Warning {
            code: "CUPTI_AGENT_INJECTED".to_owned(),
            message: "xprobe injected the CUPTI agent and left the shared object mapped".to_owned(),
            details: BTreeMap::new(),
        });
    }
    Ok(result)
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
        return Err(CommandFailure::new(issue.code, issue.message.clone(), true));
    }

    let activation = prepare_cupti_activation(&report, &validation, request)?;
    let socket = activation.socket;
    let baseline = match socket.as_deref() {
        Some(path) => Some(
            cupti::snapshot(path, request.timeout, &request.options.session_id).map_err(
                |error| CommandFailure::new(ErrorCode::CuptiNotAvailable, error.to_string(), true),
            )?,
        ),
        None => None,
    };
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
        collectors,
        host_captures,
        latest_cuda: None,
        managed_agent: activation.managed,
        agent_injected: activation.injected,
    })
}

struct CuptiActivation {
    socket: Option<PathBuf>,
    managed: bool,
    injected: bool,
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
        });
    }
    if let Some(socket) = request.cupti_socket.clone() {
        return Ok(CuptiActivation {
            socket: Some(socket),
            managed: false,
            injected: false,
        });
    }

    let socket = std::env::temp_dir().join(format!(
        "xprobe-{}-{}.sock",
        request.pid,
        std::process::id()
    ));
    let agent = resolve_agent_path(request.agent_path.as_deref())?;
    eprintln!(
        "xprobe: warning: activating the CUPTI agent modifies target PID {}",
        request.pid
    );
    let activation =
        inject::activate(report, &agent, &socket, request.timeout).map_err(|error| {
            CommandFailure::new(error.code(), error.to_string(), error.recoverable())
        })?;
    Ok(CuptiActivation {
        socket: Some(activation.socket_path),
        managed: true,
        injected: activation.injected,
    })
}

fn resolve_agent_path(configured: Option<&Path>) -> Result<PathBuf, CommandFailure> {
    if let Some(path) = configured {
        return Ok(path.to_owned());
    }
    if let Some(path) = std::env::var_os("XPROBE_CUPTI_AGENT_PATH") {
        return Ok(PathBuf::from(path));
    }
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
        parent.join("../lib/xprobe/libxprobe-cupti.so"),
        parent.join("libxprobe-cupti.so"),
        PathBuf::from("build/cupti/libxprobe-cupti.so"),
    ];
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            CommandFailure::new(
                ErrorCode::CuptiNotAvailable,
                "CUPTI agent was not found; pass --agent or set XPROBE_CUPTI_AGENT_PATH",
                true,
            )
        })
}

fn stop_managed_agent(
    collection: &mut LiveCollection,
    request: &LiveMeasureRequest,
) -> Result<(), CommandFailure> {
    if !collection.managed_agent {
        return Ok(());
    }
    let socket = collection
        .socket
        .as_deref()
        .expect("managed CUPTI agent has a socket");
    let capture = cupti::stop(socket, request.timeout, &request.options.session_id)
        .map_err(|error| CommandFailure::new(ErrorCode::CleanupFailed, error.to_string(), true))?;
    collection.latest_cuda = Some(capture);
    collection.managed_agent = false;
    Ok(())
}

impl Drop for LiveCollection {
    fn drop(&mut self) {
        if self.managed_agent {
            if let Some(socket) = self.socket.as_deref() {
                if let Err(error) = cupti::stop(socket, Duration::from_secs(2), "xp_cleanup") {
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
    collection.latest_cuda = Some(
        cupti::snapshot(path, remaining, &request.options.session_id).map_err(|error| {
            CommandFailure::new(ErrorCode::CuptiNotAvailable, error.to_string(), true)
        })?,
    );
    Ok(())
}

fn evaluate_live_result(
    collection: &LiveCollection,
    request: &LiveMeasureRequest,
    now: Instant,
) -> Result<Option<MeasurementResult>, CommandFailure> {
    let Some(host) = collection.host_captures.as_ref() else {
        return Ok(None);
    };
    if collection.socket.is_some() && collection.latest_cuda.is_none() {
        return Ok(None);
    }
    let mut result = match measure_live_capture(host, collection, &request.options) {
        Ok(result) => result,
        Err(error) if error.code == ErrorCode::NoMatchedSamples => return Ok(None),
        Err(error) => return Err(error),
    };
    let reached_samples = request.options.samples.is_some_and(|samples| {
        result.measurement.samples.matched >= u64::try_from(samples).expect("sample limit fits u64")
    });
    let reached_duration = collection.collection_end.is_some_and(|end| now >= end);
    if reached_samples || reached_duration {
        inspect::verify_target(&collection.report.target).map_err(|error| {
            CommandFailure::new(error.code(), error.to_string(), error.recoverable())
        })?;
        return Ok(Some(result));
    }
    if now >= collection.deadline {
        result.status = SessionStatus::TimedOut;
        return Ok(Some(result));
    }
    Ok(None)
}

fn finish_live_timeout(
    collection: &mut LiveCollection,
    request: &LiveMeasureRequest,
) -> Result<MeasurementResult, CommandFailure> {
    collection.collectors.cancel();
    if collection.host_captures.is_none() {
        collection.host_captures = Some(collection.collectors.join()?);
    }
    let mut result = measure_live_capture(
        collection
            .host_captures
            .as_ref()
            .expect("host captures were assigned"),
        collection,
        &request.options,
    )
    .map_err(|error| {
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
            CommandFailure::new(
                ErrorCode::NoMatchedSamples,
                format!(
                    "no event pairs matched before the live measurement timeout \
                     (host events: {host_events}, CUDA events: {cuda_events})"
                ),
                true,
            )
        } else {
            error
        }
    })?;
    result.status = SessionStatus::TimedOut;
    Ok(result)
}

fn measure_live_capture(
    host_captures: &[HostCaptureResult],
    collection: &LiveCollection,
    options: &MeasureOptions,
) -> Result<MeasurementResult, CommandFailure> {
    let mut captures = host_captures
        .iter()
        .map(|capture| completed::CompletedCapture {
            dropped_records: capture.dropped,
            unknown_records: 0,
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
        captures.push(completed::CompletedCapture {
            dropped_records,
            unknown_records,
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
    let capture = completed::merge(captures, &options.session_id).map_err(|error| {
        CommandFailure::new(ErrorCode::TraceExportFailed, error.to_string(), false)
    })?;
    if capture.unknown_records != 0 {
        return Err(CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!(
                "live capture contains {} unknown CUPTI activity records",
                capture.unknown_records
            ),
            false,
        ));
    }
    let options = MeasureOptions {
        dropped_events: capture.dropped_records,
        ..options.clone()
    };
    measure(&capture.events, &options)
        .map_err(|error| CommandFailure::new(error.code(), error.to_string(), error.recoverable()))
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
        query,
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
    match discover::run(&report, query.as_deref(), limit) {
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
        match cupti::snapshot(&socket, Duration::from_millis(timeout_ms), &session_id) {
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
    let response = ErrorResponse::new(XprobeError {
        code,
        message,
        recoverable,
        details: BTreeMap::new(),
        hints: Vec::new(),
    });
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
    println!("Target: PID {}", result.target.pid);
    println!(
        "Selectors: {} of {}{}",
        result.events.len(),
        result.total_matches,
        if result.truncated { " (truncated)" } else { "" }
    );
    for event in &result.events {
        println!("  {}", event.selector);
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
        SchemaVersion::V1 => "1.0",
    }
}
