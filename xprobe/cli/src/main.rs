use std::{
    fs::{self, DirBuilder},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::atomic::AtomicU64,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

static EXPORT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

use clap::Parser;
use xprobe_collector::completed;
use xprobe_core::{cpu_sampling, discover, doctor, inspect, syscall_aggregate, validate};
use xprobe_correlator::{MeasureOptions, finalize, measure};
use xprobe_exporter::{events_to_chrome_trace, events_to_jsonl};
use xprobe_protocol::{
    AggregateInventoryResult, ClockDomain, CpuSamplingValidationResult, ErrorCode, Event,
    EvidenceArtifact, EvidenceMode, ExportFormat, MatchPolicy, MeasurementMode, MeasurementResult,
    MeasurementSpec, SyscallAggregateValidationResult,
};

mod args;
mod dev;
mod failure;
mod inventory;
mod live;
mod render;

use args::{
    Cli, Command, CommonOutputArgs, DiscoverArgs, DoctorArgs, ExportFormatArg, MeasureArgs,
    ValidateArgs,
};
use dev::{run_capture, run_export, run_inspect, run_resolve, run_trace, write_export_file};
use failure::{CommandFailure, emit_command_failure, emit_error, measurement_failure};
use inventory::{
    run_cpu_sampling_file_spec, run_direct_cpu_sampling, run_direct_syscall_aggregate,
    run_syscall_aggregate_file_spec,
};
use live::{
    LiveMeasureRequest, apply_collection_summary, collect_live_aggregate, collect_live_measurement,
    match_policy_name, reject_incomplete_capture,
};
use render::{
    print_check, print_discovery_result, print_human_report, print_measurement_result,
    print_validation_result,
};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Doctor(args) => run_doctor(args),
        Command::Discover(args) => run_discover(args),
        Command::Inspect(args) => run_inspect(args),
        Command::Resolve(args) => run_resolve(args),
        Command::Validate(args) => run_validate(args),
        Command::Measure(args) => run_measure(*args),
        Command::Trace(args) => run_trace(args),
        Command::Export(args) => run_export(args),
        Command::Capture(args) | Command::Dev(args) => run_capture(args),
    }
}

#[allow(clippy::too_many_lines)]
fn run_measure(args: MeasureArgs) -> ExitCode {
    let MeasureArgs {
        spec,
        input,
        pid,
        cupti_socket,
        agent,
        events_out,
        evidence,
        format,
        timeout_ms,
        from,
        to,
        match_policy,
        cpu_sample,
        syscall_aggregate,
        frequency_hz,
        max_samples,
        stack_depth,
        max_threads,
        max_inflight,
        samples,
        duration_ms,
        max_events,
        aggregate,
        max_groups,
        name,
        output:
            CommonOutputArgs {
                json,
                no_color: _,
                non_interactive: _,
            },
    } = args;
    let output = EvidenceOutput {
        events_out: events_out.as_deref(),
        format,
        mode: evidence.mode(),
    };
    if let Some(spec) = spec {
        return run_measure_spec(&spec, cupti_socket, agent, output, json);
    }
    if cpu_sample {
        let Some(pid) = pid else {
            return emit_error(
                ErrorCode::InvalidEventSelector,
                "--cpu-sample requires --pid".to_owned(),
                true,
                json,
            );
        };
        let Some(duration_ms) = duration_ms else {
            return emit_error(
                ErrorCode::SessionLimitExceeded,
                "--cpu-sample requires --duration-ms".to_owned(),
                true,
                json,
            );
        };
        return run_direct_cpu_sampling(
            pid,
            name,
            frequency_hz.expect("clap supplies CPU sampling frequency"),
            duration_ms,
            timeout_ms,
            max_samples.expect("clap supplies CPU sample capacity"),
            u64::try_from(max_groups.expect("clap supplies CPU group capacity"))
                .unwrap_or(u64::MAX),
            stack_depth.expect("clap supplies CPU stack depth"),
            max_threads.expect("clap supplies CPU thread capacity"),
            json,
        );
    }
    if syscall_aggregate {
        let Some(pid) = pid else {
            return emit_error(
                ErrorCode::InvalidEventSelector,
                "--syscall-aggregate requires --pid".to_owned(),
                true,
                json,
            );
        };
        let Some(duration_ms) = duration_ms else {
            return emit_error(
                ErrorCode::SessionLimitExceeded,
                "--syscall-aggregate requires --duration-ms".to_owned(),
                true,
                json,
            );
        };
        return run_direct_syscall_aggregate(
            pid,
            name,
            duration_ms,
            timeout_ms,
            u64::try_from(max_groups.expect("clap supplies syscall group capacity"))
                .unwrap_or(u64::MAX),
            max_inflight.expect("clap supplies syscall inflight capacity"),
            json,
        );
    }
    if max_groups.is_some() && !aggregate {
        return emit_error(
            ErrorCode::InvalidEventSelector,
            "--max-groups requires --aggregate, --cpu-sample, or --syscall-aggregate".to_owned(),
            true,
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

    if let Err(error) = validate_measure_source(pid, &input) {
        return emit_command_failure(error, json);
    }
    if aggregate {
        let request = match direct_aggregate_request(
            pid,
            cupti_socket,
            agent,
            timeout_ms,
            duration_ms,
            max_groups,
            options,
        ) {
            Ok(request) => request,
            Err(error) => return emit_command_failure(error, json),
        };
        return match collect_live_aggregate(&request) {
            Ok(result) => emit_aggregate_inventory(&result, json),
            Err(error) => emit_command_failure(error, json),
        };
    }
    if let Some(pid) = pid {
        let request = LiveMeasureRequest {
            pid,
            expected_target: None,
            cupti_socket,
            agent_path: agent,
            timeout: Duration::from_millis(timeout_ms),
            match_policy_text: match_policy_name(match_policy),
            mode: MeasurementMode::Exact,
            options,
        };
        return match collect_live_measurement(&request) {
            Ok(execution) => finish_measurement(&execution, output, true, json),
            Err(error) => finish_measurement_failure(error, output, true, json),
        };
    }
    run_completed_measurement(
        &input,
        &options,
        cupti_socket.is_some(),
        agent.is_some(),
        output,
        json,
    )
}

fn validate_measure_source(pid: Option<u32>, input: &[PathBuf]) -> Result<(), CommandFailure> {
    if pid.is_some() && !input.is_empty() {
        return Err(CommandFailure::new(
            ErrorCode::InvalidEventSelector,
            "--pid and --input select different collection modes",
            true,
        ));
    }
    Ok(())
}

fn direct_aggregate_request(
    pid: Option<u32>,
    cupti_socket: Option<PathBuf>,
    agent_path: Option<PathBuf>,
    timeout_ms: u64,
    duration_ms: Option<u64>,
    max_groups: Option<usize>,
    options: MeasureOptions,
) -> Result<LiveMeasureRequest, CommandFailure> {
    let pid = pid.ok_or_else(|| {
        CommandFailure::new(
            ErrorCode::InvalidEventSelector,
            "--aggregate requires --pid",
            true,
        )
    })?;
    let duration_ms = duration_ms.ok_or_else(|| {
        CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            "--aggregate requires --duration-ms",
            true,
        )
    })?;
    Ok(LiveMeasureRequest {
        pid,
        expected_target: None,
        cupti_socket,
        agent_path,
        timeout: Duration::from_millis(timeout_ms),
        match_policy_text: match_policy_name(options.match_policy),
        mode: MeasurementMode::Aggregate,
        options: MeasureOptions {
            duration: Some(Duration::from_millis(duration_ms)),
            max_events: max_groups.expect("clap supplies aggregate group capacity"),
            ..options
        },
    })
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
    output: EvidenceOutput<'_>,
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
        Ok(execution) => finish_measurement(&execution, output, false, json),
        Err(error) => finish_measurement_failure(error, output, false, json),
    }
}

#[allow(clippy::too_many_lines)]
fn run_measure_spec(
    path: &Path,
    cupti_socket: Option<PathBuf>,
    agent_path: Option<PathBuf>,
    output: EvidenceOutput<'_>,
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
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(error) => {
            return emit_error(
                ErrorCode::InvalidEventSelector,
                format!("invalid measurement spec {}: {error}", path.display()),
                true,
                json,
            );
        }
    };
    if value.get("sample_event").is_some() {
        return run_cpu_sampling_file_spec(
            value,
            path,
            cupti_socket.is_some() || agent_path.is_some(),
            output.requests_artifact(),
            json,
        );
    }
    if value.get("max_inflight").is_some() {
        return run_syscall_aggregate_file_spec(
            value,
            path,
            cupti_socket.is_some() || agent_path.is_some(),
            output.requests_artifact(),
            json,
        );
    }
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
    let max_events = match measurement_spec_capacity(&spec) {
        Ok(capacity) => capacity,
        Err(error) => return emit_command_failure(error, json),
    };
    let request = LiveMeasureRequest {
        pid: spec.target.pid,
        expected_target: Some(spec.target),
        cupti_socket,
        agent_path,
        timeout: Duration::from_millis(spec.timeout_ms),
        match_policy_text: match_policy_name(spec.match_policy),
        mode: spec.measurement_mode,
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
    match request.mode {
        MeasurementMode::Exact => match collect_live_measurement(&request) {
            Ok(execution) => finish_measurement(&execution, output, true, json),
            Err(error) => finish_measurement_failure(error, output, true, json),
        },
        MeasurementMode::Aggregate => {
            if output.requests_artifact() {
                return emit_error(
                    ErrorCode::TraceExportFailed,
                    "aggregate measurement does not produce event evidence artifacts".to_owned(),
                    true,
                    json,
                );
            }
            match collect_live_aggregate(&request) {
                Ok(result) => emit_aggregate_inventory(&result, json),
                Err(error) => emit_command_failure(error, json),
            }
        }
    }
}

fn measurement_spec_capacity(spec: &MeasurementSpec) -> Result<usize, CommandFailure> {
    let capacity = match spec.measurement_mode {
        MeasurementMode::Exact if spec.max_groups.is_some() => {
            return Err(CommandFailure::new(
                ErrorCode::SessionLimitExceeded,
                "MeasurementSpec max_groups is only valid in aggregate mode",
                true,
            ));
        }
        MeasurementMode::Exact => spec.max_events.ok_or_else(|| {
            CommandFailure::new(
                ErrorCode::SessionLimitExceeded,
                "exact MeasurementSpec requires max_events",
                true,
            )
        })?,
        MeasurementMode::Aggregate => spec.max_groups.ok_or_else(|| {
            CommandFailure::new(
                ErrorCode::SessionLimitExceeded,
                "aggregate MeasurementSpec requires max_groups",
                true,
            )
        })?,
    };
    usize::try_from(capacity).map_err(|error| {
        CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            format!("MeasurementSpec capacity exceeds this platform: {error}"),
            true,
        )
    })
}

#[derive(Debug, Clone, Copy)]
struct EvidenceOutput<'a> {
    events_out: Option<&'a Path>,
    format: Option<ExportFormatArg>,
    mode: EvidenceMode,
}

impl EvidenceOutput<'_> {
    const fn requests_artifact(&self) -> bool {
        self.events_out.is_some() || self.format.is_some()
    }

    /// Resolve where the bounded capture goes. Live captures default to a
    /// private temporary file so summary output never loses evidence.
    fn artifact_path(&self, live: bool) -> Result<Option<PathBuf>, CommandFailure> {
        if self.format.is_some() && self.events_out.is_none() {
            return Err(CommandFailure::new(
                ErrorCode::TraceExportFailed,
                "--format requires --events-out",
                true,
            ));
        }
        match self.events_out {
            Some(path) => Ok(Some(path.to_path_buf())),
            None if live => default_artifact_path().map(Some),
            None => Ok(None),
        }
    }
}

fn default_artifact_path() -> Result<PathBuf, CommandFailure> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let directory = std::env::temp_dir().join(format!("xprobe-{}-{nanos}", std::process::id()));
    DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|error| {
            CommandFailure::new(
                ErrorCode::TraceExportFailed,
                format!(
                    "failed to create evidence directory {}: {error}",
                    directory.display()
                ),
                true,
            )
            .with_hint("pass --events-out PATH to choose a writable artifact location")
        })?;
    Ok(directory.join("events.jsonl"))
}

fn finish_measurement(
    execution: &MeasurementExecution,
    output: EvidenceOutput<'_>,
    live: bool,
    json: bool,
) -> ExitCode {
    let mut result = execution.result.clone();
    let path = match output.artifact_path(live) {
        Ok(path) => path,
        Err(error) => return emit_command_failure(error, json),
    };
    if let Some(path) = path {
        let format = output.format.unwrap_or(ExportFormatArg::Jsonl);
        if let Err(error) = export_measurement_capture(&execution.events, &path, format) {
            return emit_command_failure(error, json);
        }
        result.evidence.artifact = Some(EvidenceArtifact {
            path: path.display().to_string(),
            format: protocol_export_format(format),
            events: execution.events.len() as u64,
        });
    }
    emit_measurement(result, output.mode, json)
}

fn finish_measurement_failure(
    mut error: CommandFailure,
    output: EvidenceOutput<'_>,
    live: bool,
    json: bool,
) -> ExitCode {
    let Some(events) = error.artifact_events.take() else {
        if let Err(invalid) = output.artifact_path(false) {
            return emit_command_failure(invalid, json);
        }
        return emit_command_failure(error, json);
    };
    let path = match output.artifact_path(live) {
        Ok(Some(path)) => path,
        Ok(None) => return emit_command_failure(error, json),
        Err(invalid) => return emit_command_failure(invalid, json),
    };
    let format = output.format.unwrap_or(ExportFormatArg::Jsonl);
    if let Err(export) = export_measurement_capture(&events, &path, format) {
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
    emit_command_failure(error, json)
}

const fn protocol_export_format(format: ExportFormatArg) -> ExportFormat {
    match format {
        ExportFormatArg::Jsonl => ExportFormat::Jsonl,
        ExportFormatArg::Chrome => ExportFormat::Chrome,
    }
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

const fn clock_domain_name(domain: &ClockDomain) -> &'static str {
    match domain {
        ClockDomain::HostMonotonic => "host_monotonic",
        ClockDomain::Cupti => "cupti",
        ClockDomain::CuptiNormalizedToHostMonotonic => "cupti_normalized_to_host_monotonic",
    }
}

fn emit_measurement(mut result: MeasurementResult, mode: EvidenceMode, json: bool) -> ExitCode {
    finalize(&mut result, mode);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("measurement result must serialize")
        );
    } else {
        print_measurement_result(&result);
    }
    ExitCode::SUCCESS
}

fn emit_aggregate_inventory(result: &AggregateInventoryResult, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result)
                .expect("aggregate inventory result must serialize")
        );
    } else {
        println!(
            "aggregate inventory: {} activities in {} groups",
            result.collection.grouped_activities, result.collection.groups
        );
        for group in &result.inventory.groups {
            let label = group
                .name
                .as_deref()
                .map_or_else(|| format!("{:?}", group.activity), str::to_owned);
            println!(
                "  {label}: count={} mean={:.0}ns min={}ns max={}ns",
                group.count, group.duration_ns.mean, group.duration_ns.min, group.duration_ns.max
            );
        }
    }
    ExitCode::SUCCESS
}

fn run_validate(args: ValidateArgs) -> ExitCode {
    let ValidateArgs {
        pid,
        from,
        to,
        match_policy,
        cpu_sample,
        syscall_aggregate,
        output:
            CommonOutputArgs {
                json,
                no_color: _,
                non_interactive: _,
            },
    } = args;
    let report = match inspect::run(pid) {
        Ok(report) => report,
        Err(error) => {
            return emit_error(error.code(), error.to_string(), error.recoverable(), json);
        }
    };

    if cpu_sample {
        return match cpu_sampling::validate(&report) {
            Ok(result) => emit_cpu_sampling_validation(&result, json),
            Err(error) => emit_error(error.code(), error.to_string(), error.recoverable(), json),
        };
    }
    if syscall_aggregate {
        return match syscall_aggregate::validate(&report) {
            Ok(result) => emit_syscall_aggregate_validation(&result, json),
            Err(error) => emit_error(error.code(), error.to_string(), error.recoverable(), json),
        };
    }
    let (Some(from), Some(to), Some(match_policy)) = (from, to, match_policy) else {
        return emit_error(
            ErrorCode::InvalidEventSelector,
            "validate requires an event pair, --cpu-sample, or --syscall-aggregate".to_owned(),
            true,
            json,
        );
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

fn emit_cpu_sampling_validation(result: &CpuSamplingValidationResult, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result)
                .expect("CPU sampling validation result must serialize")
        );
    } else {
        println!(
            "CPU sampling validation: {}",
            if result.valid { "valid" } else { "invalid" }
        );
        println!("Target: PID {}", result.target.pid);
        println!("Threads: {}", result.target_threads);
        println!("Python symbols: {:?}", result.python_status);
        print_check("perf event", &result.perf_event);
        for issue in &result.issues {
            println!("Issue: {}: {}", issue.code, issue.message);
        }
        for warning in &result.warnings {
            println!("Warning: {}: {}", warning.code, warning.message);
        }
    }
    ExitCode::SUCCESS
}

fn emit_syscall_aggregate_validation(
    result: &SyscallAggregateValidationResult,
    json: bool,
) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result)
                .expect("syscall aggregate validation result must serialize")
        );
    } else {
        println!(
            "Syscall aggregate validation: {}",
            if result.valid { "valid" } else { "invalid" }
        );
        println!("Target: PID {}", result.target.pid);
        print_check("eBPF", &result.ebpf);
        for issue in &result.issues {
            println!("Issue: {}: {}", issue.code, issue.message);
        }
    }
    ExitCode::SUCCESS
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
