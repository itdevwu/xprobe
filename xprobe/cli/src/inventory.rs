use crate::failure::CommandFailure;
use crate::failure::emit_command_failure;
use crate::failure::emit_error;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use xprobe_collector::cpu_sampling as cpu_collector;
use xprobe_collector::cpu_sampling::CpuSamplingRequest;
use xprobe_collector::syscall_aggregate as syscall_collector;
use xprobe_collector::syscall_aggregate::SyscallAggregateRequest;
use xprobe_core::cpu_sampling;
use xprobe_core::cpu_sampling_analysis;
use xprobe_core::cpu_sampling_analysis::CpuCaptureData;
use xprobe_core::cpu_sampling_analysis::RawCpuSample;
use xprobe_core::inspect;
use xprobe_core::syscall_aggregate;
use xprobe_protocol::CpuSampleEvent;
use xprobe_protocol::CpuSampleInventoryResult;
use xprobe_protocol::CpuSamplingSpec;
use xprobe_protocol::ErrorCode;
use xprobe_protocol::ProcessReport;
use xprobe_protocol::SchemaVersion;
use xprobe_protocol::SyscallAggregateResult;
use xprobe_protocol::SyscallAggregateSpec;

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_direct_cpu_sampling(
    pid: u32,
    name: Option<String>,
    frequency_hz: u64,
    duration_ms: u64,
    timeout_ms: u64,
    max_samples: u64,
    max_groups: u64,
    stack_depth: u32,
    max_threads: u32,
    json: bool,
) -> ExitCode {
    let report = match inspect::run(pid) {
        Ok(report) => report,
        Err(error) => {
            return emit_error(error.code(), error.to_string(), error.recoverable(), json);
        }
    };
    let spec = CpuSamplingSpec {
        schema_version: SchemaVersion::current(),
        name,
        target: report.target.clone(),
        sample_event: CpuSampleEvent::CpuClock,
        frequency_hz,
        duration_ms,
        timeout_ms,
        max_samples,
        max_groups,
        stack_depth,
        max_threads,
    };
    run_cpu_sampling_spec(&spec, Some(report), json)
}

pub(crate) fn run_cpu_sampling_spec(
    spec: &CpuSamplingSpec,
    inspected: Option<ProcessReport>,
    json: bool,
) -> ExitCode {
    let report = match inspected.map_or_else(|| inspect::run(spec.target.pid), Ok) {
        Ok(report) => report,
        Err(error) => {
            return emit_error(error.code(), error.to_string(), error.recoverable(), json);
        }
    };
    if let Err(error) = inspect::verify_target(&spec.target) {
        return emit_error(error.code(), error.to_string(), error.recoverable(), json);
    }
    let validation = match cpu_sampling::validate(&report) {
        Ok(validation) => validation,
        Err(error) => {
            return emit_error(error.code(), error.to_string(), error.recoverable(), json);
        }
    };
    if !validation.valid {
        let message = validation.issues.first().map_or_else(
            || "CPU sampling requirements are not satisfied".to_owned(),
            |issue| issue.message.clone(),
        );
        return emit_error(ErrorCode::PermissionDenied, message, true, json);
    }
    let request = match cpu_collector_request(spec) {
        Ok(request) => request,
        Err(error) => return emit_command_failure(error, json),
    };
    let capture = match cpu_collector::collect(&request) {
        Ok(capture) => capture,
        Err(error) => return emit_command_failure(cpu_collector_failure(&error), json),
    };
    if capture.observed_samples == 0 {
        return emit_error(
            ErrorCode::NoMatchedSamples,
            "CPU sampling completed without observing an on-CPU sample".to_owned(),
            true,
            json,
        );
    }
    let capture = CpuCaptureData {
        samples: capture
            .stacks
            .into_iter()
            .map(|stack| RawCpuSample {
                thread_id: stack.thread_id,
                addresses: stack.addresses,
            })
            .collect(),
        observed_samples: capture.observed_samples,
        lost_samples: capture.lost_samples,
        truncated_stacks: capture.truncated_stacks,
        throttled_records: capture.throttled_records,
        threads_observed: capture.threads_observed,
        threads_attached: capture.threads_attached,
        skipped_threads: capture.skipped_threads,
        capacity_reached: capture.capacity_reached,
        python_status: validation.python_status,
    };
    let result = match cpu_sampling_analysis::analyze(
        &report,
        spec,
        format!("xp_cpu_{}", std::process::id()),
        &capture,
    ) {
        Ok(result) => result,
        Err(error) => {
            return emit_error(error.code(), error.to_string(), error.recoverable(), json);
        }
    };
    emit_cpu_inventory(&result, json)
}

pub(crate) fn cpu_collector_request(
    spec: &CpuSamplingSpec,
) -> Result<CpuSamplingRequest, CommandFailure> {
    if spec.frequency_hz == 0
        || spec.duration_ms == 0
        || spec.max_samples == 0
        || spec.max_groups == 0
        || spec.stack_depth == 0
        || spec.max_threads == 0
    {
        return Err(CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            "CPU sampling frequency, duration, samples, groups, stack depth, and threads must be positive",
            true,
        ));
    }
    let max_samples = usize::try_from(spec.max_samples).map_err(|error| {
        CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            format!("CPU max_samples exceed this platform: {error}"),
            true,
        )
    })?;
    let max_threads = usize::try_from(spec.max_threads).map_err(|error| {
        CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            format!("CPU max_threads exceed this platform: {error}"),
            true,
        )
    })?;
    let stack_depth = u16::try_from(spec.stack_depth).map_err(|error| {
        CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            format!("CPU stack_depth exceeds the perf ABI: {error}"),
            true,
        )
    })?;
    let thread_ids = cpu_sampling::target_thread_ids(&spec.target).map_err(|error| {
        CommandFailure::new(error.code(), error.to_string(), error.recoverable())
    })?;
    Ok(CpuSamplingRequest {
        thread_ids,
        frequency_hz: spec.frequency_hz,
        duration: Duration::from_millis(spec.duration_ms),
        timeout: Duration::from_millis(spec.timeout_ms),
        max_samples,
        max_threads,
        stack_depth,
    })
}

pub(crate) fn cpu_collector_failure(error: &cpu_collector::CpuSamplingError) -> CommandFailure {
    let code = match error {
        cpu_collector::CpuSamplingError::InvalidRequest(_)
        | cpu_collector::CpuSamplingError::Timeout => ErrorCode::SessionLimitExceeded,
        cpu_collector::CpuSamplingError::Open { source, .. }
        | cpu_collector::CpuSamplingError::Arm { source, .. }
            if source.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            ErrorCode::PermissionDenied
        }
        cpu_collector::CpuSamplingError::Cleanup { .. } => ErrorCode::CleanupFailed,
        cpu_collector::CpuSamplingError::NoThreadsAttached { .. } => ErrorCode::TargetExited,
        cpu_collector::CpuSamplingError::Open { .. }
        | cpu_collector::CpuSamplingError::Ring { .. }
        | cpu_collector::CpuSamplingError::Arm { .. } => ErrorCode::Internal,
    };
    let recoverable = !matches!(code, ErrorCode::Internal | ErrorCode::CleanupFailed);
    CommandFailure::new(code, error.to_string(), recoverable)
}

pub(crate) fn emit_cpu_inventory(result: &CpuSampleInventoryResult, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result).expect("CPU inventory must serialize")
        );
    } else {
        println!(
            "CPU sample inventory: {} samples",
            result.collection.observed_samples
        );
        println!(
            "Stacks: {} groups, {} lost, {} unresolved frames",
            result.collection.groups,
            result.collection.lost_samples,
            result.symbolization.unresolved_frames
        );
        for hotspot in result.inventory.hotspots.iter().take(10) {
            let label = hotspot
                .frame
                .symbol
                .as_deref()
                .or(hotspot.frame.module_path.as_deref())
                .map_or_else(|| format!("{:#x}", hotspot.frame.address), str::to_owned);
            println!(
                "  {:.1}% inclusive, {:.1}% self  {label}",
                hotspot.inclusive_proportion * 100.0,
                hotspot.exclusive_proportion * 100.0
            );
        }
        for warning in &result.warnings {
            println!("Warning: {}: {}", warning.code, warning.message);
        }
    }
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_direct_syscall_aggregate(
    pid: u32,
    name: Option<String>,
    duration_ms: u64,
    timeout_ms: u64,
    max_groups: u64,
    max_inflight: u64,
    json: bool,
) -> ExitCode {
    let report = match inspect::run(pid) {
        Ok(report) => report,
        Err(error) => {
            return emit_error(error.code(), error.to_string(), error.recoverable(), json);
        }
    };
    let spec = SyscallAggregateSpec {
        schema_version: SchemaVersion::current(),
        name,
        target: report.target.clone(),
        duration_ms,
        timeout_ms,
        max_groups,
        max_inflight,
    };
    run_syscall_aggregate_spec(&spec, Some(report), json)
}

pub(crate) fn run_syscall_aggregate_spec(
    spec: &SyscallAggregateSpec,
    inspected: Option<ProcessReport>,
    json: bool,
) -> ExitCode {
    let report = match inspected.map_or_else(|| inspect::run(spec.target.pid), Ok) {
        Ok(report) => report,
        Err(error) => {
            return emit_error(error.code(), error.to_string(), error.recoverable(), json);
        }
    };
    if let Err(error) = inspect::verify_target(&spec.target) {
        return emit_error(error.code(), error.to_string(), error.recoverable(), json);
    }
    let validation = match syscall_aggregate::validate(&report) {
        Ok(validation) => validation,
        Err(error) => {
            return emit_error(error.code(), error.to_string(), error.recoverable(), json);
        }
    };
    if !validation.valid {
        let message = validation.issues.first().map_or_else(
            || "syscall aggregate requirements are not satisfied".to_owned(),
            |issue| issue.message.clone(),
        );
        return emit_error(ErrorCode::PermissionDenied, message, true, json);
    }
    let request = match syscall_collector_request(spec) {
        Ok(request) => request,
        Err(error) => return emit_command_failure(error, json),
    };
    let capture = match syscall_collector::collect(&request) {
        Ok(capture) => capture,
        Err(error) => {
            return emit_error(error.code(), error.to_string(), error.recoverable(), json);
        }
    };
    let capture = syscall_aggregate::SyscallCaptureData {
        groups: capture
            .groups
            .into_iter()
            .map(|group| syscall_aggregate::RawSyscallGroup {
                syscall_number: group.syscall_number,
                count: group.count,
                errors: group.errors,
                total_duration_ns: group.total_duration_ns,
                min_duration_ns: group.min_duration_ns,
                max_duration_ns: group.max_duration_ns,
            })
            .collect(),
        observed_entries: capture.observed_entries,
        matched_exits: capture.matched_exits,
        unmatched_exits: capture.unmatched_exits,
        dropped_aggregates: capture.dropped_aggregates,
        inflight_at_end: capture.inflight_at_end,
    };
    let result = match syscall_aggregate::analyze(
        &report,
        spec,
        format!("xp_syscalls_{}", std::process::id()),
        &capture,
    ) {
        Ok(result) => result,
        Err(error) => {
            return emit_error(error.code(), error.to_string(), error.recoverable(), json);
        }
    };
    emit_syscall_inventory(&result, json)
}

pub(crate) fn syscall_collector_request(
    spec: &SyscallAggregateSpec,
) -> Result<SyscallAggregateRequest, CommandFailure> {
    if spec.duration_ms == 0 || spec.max_groups == 0 || spec.max_inflight == 0 {
        return Err(CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            "syscall aggregate duration, groups, and inflight capacity must be positive",
            true,
        ));
    }
    let max_groups = u32::try_from(spec.max_groups).map_err(|error| {
        CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            format!("syscall max_groups exceed the BPF map ABI: {error}"),
            true,
        )
    })?;
    let max_inflight = u32::try_from(spec.max_inflight).map_err(|error| {
        CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            format!("syscall max_inflight exceeds the BPF map ABI: {error}"),
            true,
        )
    })?;
    Ok(SyscallAggregateRequest {
        target: spec.target.clone(),
        duration: Duration::from_millis(spec.duration_ms),
        timeout: Duration::from_millis(spec.timeout_ms),
        max_groups,
        max_inflight,
    })
}

pub(crate) fn emit_syscall_inventory(result: &SyscallAggregateResult, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result).expect("syscall inventory must serialize")
        );
    } else {
        println!(
            "Syscall inventory: {} entries, {} matched exits",
            result.collection.observed_entries, result.collection.matched_exits
        );
        for group in result.inventory.groups.iter().take(10) {
            let label = group
                .syscall_name
                .clone()
                .unwrap_or_else(|| format!("syscall#{}", group.syscall_number));
            println!(
                "  {label}: count={} total={}ns mean={:.0}ns errors={}",
                group.count, group.duration_ns.total, group.duration_ns.mean, group.errors
            );
        }
        for warning in &result.warnings {
            println!("Warning: {}: {}", warning.code, warning.message);
        }
    }
    ExitCode::SUCCESS
}

pub(crate) fn run_cpu_sampling_file_spec(
    value: serde_json::Value,
    path: &Path,
    has_device_options: bool,
    has_artifact_options: bool,
    json: bool,
) -> ExitCode {
    if has_device_options || has_artifact_options {
        return emit_error(
            ErrorCode::InvalidEventSelector,
            "CpuSamplingSpec does not accept CUPTI or event artifact options".to_owned(),
            true,
            json,
        );
    }
    let spec: CpuSamplingSpec = match serde_json::from_value(value) {
        Ok(spec) => spec,
        Err(error) => {
            return emit_error(
                ErrorCode::InvalidEventSelector,
                format!("invalid CpuSamplingSpec {}: {error}", path.display()),
                true,
                json,
            );
        }
    };
    run_cpu_sampling_spec(&spec, None, json)
}

pub(crate) fn run_syscall_aggregate_file_spec(
    value: serde_json::Value,
    path: &Path,
    has_device_options: bool,
    has_artifact_options: bool,
    json: bool,
) -> ExitCode {
    if has_device_options || has_artifact_options {
        return emit_error(
            ErrorCode::InvalidEventSelector,
            "SyscallAggregateSpec does not accept CUPTI or event artifact options".to_owned(),
            true,
            json,
        );
    }
    let spec: SyscallAggregateSpec = match serde_json::from_value(value) {
        Ok(spec) => spec,
        Err(error) => {
            return emit_error(
                ErrorCode::InvalidEventSelector,
                format!("invalid SyscallAggregateSpec {}: {error}", path.display()),
                true,
                json,
            );
        }
    };
    run_syscall_aggregate_spec(&spec, None, json)
}
