use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use clap::{Args, Parser, Subcommand};
use xprobe_collector::{
    completed, cupti,
    uprobe::{self, UprobeRequest},
};
use xprobe_core::{doctor, inspect, resolve, validate};
use xprobe_correlator::{MeasureOptions, measure};
use xprobe_exporter::events_to_jsonl;
use xprobe_protocol::{
    CapabilityReport, CheckResult, ErrorCode, ErrorResponse, HostCaptureResult, MatchPolicy,
    MeasurementResult, ProcessReport, ResolvedProbe, SchemaVersion, ValidationResult, XprobeError,
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
    /// Inspect a target process without attaching probes.
    Inspect(InspectArgs),
    /// Resolve a userspace event selector against a target process.
    Resolve(ResolveArgs),
    /// Validate two event selectors and their correlation policy.
    Validate(ValidateArgs),
    /// Measure latency from a completed bounded capture.
    Measure(MeasureArgs),
    /// Run low-level development probes.
    Dev(DevArgs),
}

#[derive(Debug, Args)]
struct DevArgs {
    #[command(subcommand)]
    command: DevCommand,
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
    #[arg(long, required = true)]
    input: Vec<PathBuf>,

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
    #[arg(long)]
    input: PathBuf,

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
        Command::Inspect(args) => run_inspect(args),
        Command::Resolve(args) => run_resolve(args),
        Command::Validate(args) => run_validate(args),
        Command::Measure(args) => run_measure(args),
        Command::Dev(args) => match args.command {
            DevCommand::Uprobe(args) => run_uprobe(args),
            DevCommand::Cupti(args) => run_cupti(args),
        },
    }
}

fn run_measure(args: MeasureArgs) -> ExitCode {
    let MeasureArgs {
        input,
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
        _ => {
            return emit_error(
                ErrorCode::InvalidCorrelationPolicy,
                "completed-capture measurement supports exact and first-after".to_owned(),
                true,
                json,
            );
        }
    };
    let session_id = format!("xp_measure_{}", std::process::id());
    let mut captures = Vec::with_capacity(input.len());
    for path in input {
        let bytes = match fs::read(&path) {
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
        let capture = match completed::decode(&bytes, &session_id) {
            Ok(capture) => capture,
            Err(error) => {
                return emit_error(
                    ErrorCode::TraceExportFailed,
                    format!("failed to decode {}: {error}", path.display()),
                    false,
                    json,
                );
            }
        };
        captures.push(capture);
    }
    let capture = match completed::merge(captures, &session_id) {
        Ok(capture) => capture,
        Err(error) => {
            return emit_error(ErrorCode::TraceExportFailed, error.to_string(), false, json);
        }
    };
    if capture.unknown_records != 0 {
        return emit_error(
            ErrorCode::TraceExportFailed,
            format!(
                "capture contains {} unknown CUPTI activity records",
                capture.unknown_records
            ),
            false,
            json,
        );
    }
    let options = MeasureOptions {
        session_id,
        name,
        start_selector: from,
        end_selector: to,
        match_policy,
        samples,
        duration: duration_ms.map(Duration::from_millis),
        max_events,
        dropped_events: capture.dropped_records,
    };
    match measure(&capture.events, &options) {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result)
                        .expect("measurement result must serialize")
                );
            } else {
                print_measurement_result(&result);
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_error(error.code(), error.to_string(), error.recoverable(), json),
    }
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
        symbol,
        probe_kind: if return_probe {
            xprobe_protocol::HostProbeKind::Uretprobe
        } else {
            xprobe_protocol::HostProbeKind::Uprobe
        },
        probe_id,
        samples,
        timeout: Duration::from_millis(timeout_ms),
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
        session_id,
        json,
        no_color: _,
        non_interactive: _,
    } = args;
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
    let capture = match cupti::decode_capture(&bytes, &session_id) {
        Ok(capture) => capture,
        Err(error) => {
            return emit_error(ErrorCode::TraceExportFailed, error.to_string(), false, json);
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
        "Target restart required: {}",
        result.requirements.target_restart_required
    );
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
