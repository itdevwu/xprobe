use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use clap::{Args, Parser, Subcommand};
use xprobe_collector::uprobe::{self, UprobeRequest};
use xprobe_core::{doctor, inspect};
use xprobe_protocol::{
    CapabilityReport, CheckResult, ErrorCode, ErrorResponse, HostCaptureResult, ProcessReport,
    SchemaVersion, XprobeError,
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

    /// Probe identifier stored in each event.
    #[arg(long, default_value_t = 1)]
    probe_id: u32,

    /// Stop after this many events.
    #[arg(long, default_value_t = 1)]
    samples: usize,

    /// Stop waiting after this many milliseconds.
    #[arg(long, default_value_t = 5_000)]
    timeout_ms: u64,

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

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Doctor(args) => run_doctor(args),
        Command::Inspect(args) => run_inspect(args),
        Command::Dev(args) => match args.command {
            DevCommand::Uprobe(args) => run_uprobe(args),
        },
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
        probe_id,
        samples,
        timeout_ms,
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
    let binary = match mapped_binary(&report, &binary) {
        Ok(binary) => binary,
        Err(message) => return emit_error(ErrorCode::BinaryNotMapped, message, true, json),
    };
    let request = UprobeRequest {
        target: report.target.clone(),
        binary,
        symbol,
        probe_id,
        samples,
        timeout: Duration::from_millis(timeout_ms),
    };
    let result = match uprobe::capture(&request) {
        Ok(result) => result,
        Err(error) => {
            return emit_error(error.code(), error.to_string(), error.recoverable(), json);
        }
    };
    if let Err(error) = inspect::verify_target(&report.target) {
        return emit_error(error.code(), error.to_string(), error.recoverable(), json);
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("host capture result must serialize")
        );
    } else {
        print_host_capture(&result);
    }
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
