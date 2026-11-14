//! `measure --triage`: one bounded window of concurrent inventories.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;
use xprobe_core::{
    cgroup_cpu, gpu_health, inspect, thread_time,
    triage::{TriageEvidence, findings},
};
use xprobe_correlator::MeasureOptions;
use xprobe_protocol::{
    AggregateInventoryResult, CpuSampleEvent, CpuSamplingSpec, ErrorCode, MatchPolicy,
    MeasurementMode, ProcessReport, SchemaVersion, SchemaVersion3, SessionStatus,
    SyscallAggregateSpec, TriageResult, TriageSource, TriageSourceKind, TriageSourceStatus,
    Warning,
};

use crate::{
    dev::write_export_file,
    failure::{CommandFailure, emit_command_failure},
    inventory::{cpu_inventory, syscall_inventory},
    live::{LiveMeasureRequest, collect_live_aggregate},
    private_artifact_dir,
    render::print_triage_result,
};

/// Entries kept inline per summary list; full results go to artifacts.
const TOP: usize = 5;
const CPU_FREQUENCY_HZ: u64 = 99;
const CPU_MAX_GROUPS: u64 = 256;
const CPU_STACK_DEPTH: u32 = 64;
const CPU_MAX_THREADS: u32 = 1024;
/// Concurrently running threads the CPU sample capacity is sized for.
const CPU_SAMPLED_THREAD_BUDGET: u64 = 64;
const SYSCALL_MAX_GROUPS: u64 = 256;
const SYSCALL_MAX_INFLIGHT: u64 = 1024;
const GPU_MAX_GROUPS: usize = 4096;
const GPU_HEALTH_INTERVAL: Duration = Duration::from_millis(250);

const NOT_COVERED: [&str; 3] = [
    "where blocked threads wait (off-CPU stacks, lock and I/O attribution)",
    "exact GPU busy intervals; NVML utilization is a device-wide sampled estimate",
    "memcpy and memset activity, including pageable versus pinned host memory; run a memcpy aggregate inventory",
];

#[derive(Debug)]
pub(crate) struct TriageRequest {
    pub(crate) pid: u32,
    pub(crate) duration_ms: u64,
    pub(crate) timeout_ms: u64,
    pub(crate) cupti_socket: Option<PathBuf>,
    pub(crate) agent_path: Option<PathBuf>,
}

pub(crate) fn run_triage(request: &TriageRequest, json: bool) -> ExitCode {
    match triage(request) {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).expect("triage result must serialize")
                );
            } else {
                print_triage_result(&result);
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_command_failure(error, json),
    }
}

fn inspect_failure(error: &inspect::InspectError) -> CommandFailure {
    CommandFailure::new(error.code(), error.to_string(), error.recoverable())
}

/// A source either produced a value or is unavailable for a stated reason.
enum Outcome<T> {
    Collected(T),
    Unavailable(String),
    Skipped(String),
}

/// Capability absence and bounded-capacity failures make one source
/// unavailable. Target identity, cleanup, and internal failures abort triage.
fn classify<T>(result: Result<T, CommandFailure>) -> Result<Outcome<T>, CommandFailure> {
    match result {
        Ok(value) => Ok(Outcome::Collected(value)),
        Err(error) => match error.code {
            ErrorCode::PermissionDenied
            | ErrorCode::CuptiNotAvailable
            | ErrorCode::CuptiAgentNotLoaded
            | ErrorCode::CudaContextNotFound
            | ErrorCode::UnsupportedCudaVersion
            | ErrorCode::EventRateTooHigh
            | ErrorCode::EventsDropped
            | ErrorCode::NoMatchedSamples
            | ErrorCode::HighUnmatchedRate => Ok(Outcome::Unavailable(format!(
                "{}: {}",
                error.code, error.message
            ))),
            _ => Err(error),
        },
    }
}

#[allow(clippy::too_many_lines)]
fn triage(request: &TriageRequest) -> Result<TriageResult, CommandFailure> {
    if request.duration_ms == 0 {
        return Err(CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            "--triage requires a positive --duration-ms",
            true,
        ));
    }
    let report = inspect::run(request.pid).map_err(|error| inspect_failure(&error))?;
    let target = report.target.clone();
    let artifacts = private_artifact_dir()?;
    let cgroup = cgroup_cpu::locate(request.pid).map_err(|error| inspect_failure(&error))?;
    let quota = match &cgroup {
        Some(cgroup) => cgroup
            .quota_cpus()
            .map_err(|error| inspect_failure(&error))?,
        None => None,
    };
    let cgroup_before = match &cgroup {
        Some(cgroup) => Some(cgroup.counters().map_err(|error| inspect_failure(&error))?),
        None => None,
    };
    let threads_before =
        thread_time::snapshot(request.pid).map_err(|error| inspect_failure(&error))?;
    let started = Instant::now();
    let window = Duration::from_millis(request.duration_ms);

    let (cpu, syscalls, gpu_activity, gpu_rounds) = thread::scope(|scope| {
        let cpu = scope.spawn(|| cpu_inventory(&cpu_spec(&report, request), Some(report.clone())));
        let syscalls = scope
            .spawn(|| syscall_inventory(&syscall_spec(&report, request), Some(report.clone())));
        let gpu_activity = report
            .cuda
            .libcuda_loaded
            .then(|| scope.spawn(|| collect_live_aggregate(&gpu_request(request))));
        let gpu_rounds = scope.spawn(|| sample_gpu_health(window));
        (
            cpu.join(),
            syscalls.join(),
            gpu_activity.map(thread::ScopedJoinHandle::join),
            gpu_rounds.join(),
        )
    });
    let elapsed = started.elapsed();
    let threads_after =
        thread_time::snapshot(request.pid).map_err(|error| inspect_failure(&error))?;
    let cgroup_after = match &cgroup {
        Some(cgroup) => Some(cgroup.counters().map_err(|error| inspect_failure(&error))?),
        None => None,
    };
    inspect::verify_target(&target).map_err(|error| inspect_failure(&error))?;

    let panicked = |source: &str| {
        CommandFailure::new(
            ErrorCode::Internal,
            format!("{source} collector panicked"),
            false,
        )
    };
    let cpu = classify(cpu.map_err(|_| panicked("CPU sampling"))?)?;
    let syscalls = classify(syscalls.map_err(|_| panicked("syscall aggregate"))?)?;
    let gpu_activity = match gpu_activity {
        Some(joined) => classify(joined.map_err(|_| panicked("GPU activity"))?)?,
        None => Outcome::Skipped("the target has not loaded libcuda".to_owned()),
    };
    let gpu_rounds = gpu_rounds.map_err(|_| panicked("GPU health"))?;

    let window_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
    let threads = thread_time::breakdown(&threads_before, &threads_after, window_ns, TOP);
    let cgroup_throttling = cgroup
        .as_ref()
        .zip(cgroup_before.zip(cgroup_after))
        .map(|(cgroup, (before, after))| cgroup_cpu::throttling(cgroup, quota, before, after));

    let mut sources = vec![
        source(
            TriageSourceKind::ThreadTime,
            TriageSourceStatus::Collected,
            None,
            None,
        ),
        match &cgroup_throttling {
            Some(_) => source(
                TriageSourceKind::Cgroup,
                TriageSourceStatus::Collected,
                None,
                None,
            ),
            None => source(
                TriageSourceKind::Cgroup,
                TriageSourceStatus::Unavailable,
                Some("no CPU cgroup controller is mounted for the target".to_owned()),
                None,
            ),
        },
    ];
    let mut warnings = Vec::new();

    let mut cpu_hotspots = Vec::new();
    let mut python_status = None;
    match cpu {
        Outcome::Collected(result) => {
            python_status = Some(result.symbolization.python_status);
            let path = write_artifact(&artifacts, "cpu-sample.json", &result)?;
            cpu_hotspots = result.inventory.hotspots;
            cpu_hotspots.sort_by(|left, right| {
                right
                    .exclusive_proportion
                    .total_cmp(&left.exclusive_proportion)
            });
            cpu_hotspots.truncate(TOP);
            warnings.extend(result.warnings);
            sources.push(source(
                TriageSourceKind::CpuSample,
                TriageSourceStatus::Collected,
                None,
                Some(path),
            ));
        }
        outcome => sources.push(not_collected(TriageSourceKind::CpuSample, outcome)),
    }

    let mut syscall_groups = Vec::new();
    match syscalls {
        Outcome::Collected(result) => {
            let path = write_artifact(&artifacts, "syscall-aggregate.json", &result)?;
            syscall_groups = result.inventory.groups;
            syscall_groups.sort_by_key(|group| std::cmp::Reverse(group.duration_ns.total));
            syscall_groups.truncate(TOP);
            warnings.extend(result.warnings);
            sources.push(source(
                TriageSourceKind::SyscallAggregate,
                TriageSourceStatus::Collected,
                None,
                Some(path),
            ));
        }
        outcome => sources.push(not_collected(TriageSourceKind::SyscallAggregate, outcome)),
    }

    let mut activity_groups = None;
    match gpu_activity {
        Outcome::Collected(result) => {
            let path = write_artifact(&artifacts, "gpu-activity.json", &result)?;
            let AggregateInventoryResult {
                inventory,
                warnings: activity_warnings,
                ..
            } = result;
            let mut groups = inventory.groups;
            groups.sort_by_key(|group| std::cmp::Reverse(group.duration_ns.total));
            groups.truncate(TOP);
            activity_groups = Some(groups);
            warnings.extend(activity_warnings);
            sources.push(source(
                TriageSourceKind::GpuActivity,
                TriageSourceStatus::Collected,
                None,
                Some(path),
            ));
        }
        outcome => sources.push(not_collected(TriageSourceKind::GpuActivity, outcome)),
    }

    let gpu_devices = match gpu_rounds {
        Ok(rounds) => {
            sources.push(source(
                TriageSourceKind::GpuHealth,
                TriageSourceStatus::Collected,
                None,
                None,
            ));
            gpu_health::summarize(&rounds)
        }
        Err(reason) => {
            sources.push(source(
                TriageSourceKind::GpuHealth,
                TriageSourceStatus::Unavailable,
                Some(reason),
                None,
            ));
            Vec::new()
        }
    };
    for unavailable in sources
        .iter()
        .filter(|source| source.status == TriageSourceStatus::Unavailable)
    {
        warnings.push(Warning {
            code: "TRIAGE_SOURCE_UNAVAILABLE".to_owned(),
            message: format!(
                "{:?} evidence is missing: {}",
                unavailable.source,
                unavailable.reason.as_deref().unwrap_or("unknown reason")
            ),
            details: std::collections::BTreeMap::new(),
        });
    }
    sources.sort_by_key(|source| source.source);

    let found = findings(&TriageEvidence {
        target: &target,
        threads: &threads,
        collection_window_ns: request.duration_ms.saturating_mul(1_000_000),
        cgroup: cgroup_throttling.as_ref(),
        cpu_hotspots: &cpu_hotspots,
        python_status,
        syscalls: &syscall_groups,
        gpu_devices: &gpu_devices,
        gpu_activity: activity_groups.as_deref(),
    });
    Ok(TriageResult {
        schema_version: SchemaVersion3::current(),
        ok: true,
        session_id: format!("xp_triage_{}", std::process::id()),
        status: SessionStatus::Completed,
        target,
        window_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        findings: found,
        threads,
        cgroup: cgroup_throttling,
        cpu_hotspots,
        syscalls: syscall_groups,
        gpu_devices,
        gpu_activity: activity_groups.unwrap_or_default(),
        sources,
        not_covered: NOT_COVERED.iter().map(|item| (*item).to_owned()).collect(),
        warnings,
    })
}

fn source(
    source: TriageSourceKind,
    status: TriageSourceStatus,
    reason: Option<String>,
    artifact: Option<String>,
) -> TriageSource {
    TriageSource {
        source,
        status,
        reason,
        artifact,
    }
}

fn not_collected<T>(kind: TriageSourceKind, outcome: Outcome<T>) -> TriageSource {
    match outcome {
        Outcome::Collected(_) => unreachable!("collected outcomes are handled by the caller"),
        Outcome::Unavailable(reason) => {
            source(kind, TriageSourceStatus::Unavailable, Some(reason), None)
        }
        Outcome::Skipped(reason) => source(kind, TriageSourceStatus::Skipped, Some(reason), None),
    }
}

fn write_artifact<T: Serialize>(
    directory: &Path,
    name: &str,
    value: &T,
) -> Result<String, CommandFailure> {
    let path = directory.join(name);
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        CommandFailure::new(
            ErrorCode::Internal,
            format!("failed to encode {name}: {error}"),
            false,
        )
    })?;
    write_export_file(&path, &bytes).map_err(|error| {
        CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!("failed to write {}: {error}", path.display()),
            false,
        )
    })?;
    Ok(path.display().to_string())
}

fn cpu_spec(report: &ProcessReport, request: &TriageRequest) -> CpuSamplingSpec {
    CpuSamplingSpec {
        schema_version: SchemaVersion::current(),
        name: Some("triage".to_owned()),
        target: report.target.clone(),
        sample_event: CpuSampleEvent::CpuClock,
        frequency_hz: CPU_FREQUENCY_HZ,
        duration_ms: request.duration_ms,
        timeout_ms: request.timeout_ms,
        max_samples: (CPU_FREQUENCY_HZ * request.duration_ms / 1000 + 1)
            * CPU_SAMPLED_THREAD_BUDGET,
        max_groups: CPU_MAX_GROUPS,
        stack_depth: CPU_STACK_DEPTH,
        max_threads: CPU_MAX_THREADS,
    }
}

fn syscall_spec(report: &ProcessReport, request: &TriageRequest) -> SyscallAggregateSpec {
    SyscallAggregateSpec {
        schema_version: SchemaVersion::current(),
        name: Some("triage".to_owned()),
        target: report.target.clone(),
        duration_ms: request.duration_ms,
        timeout_ms: request.timeout_ms,
        max_groups: SYSCALL_MAX_GROUPS,
        max_inflight: SYSCALL_MAX_INFLIGHT,
    }
}

fn gpu_request(request: &TriageRequest) -> LiveMeasureRequest {
    LiveMeasureRequest {
        pid: request.pid,
        expected_target: None,
        cupti_socket: request.cupti_socket.clone(),
        agent_path: request.agent_path.clone(),
        timeout: Duration::from_millis(request.timeout_ms),
        match_policy_text: "exact",
        mode: MeasurementMode::Aggregate,
        options: MeasureOptions {
            session_id: format!("xp_triage_gpu_{}", std::process::id()),
            name: Some("triage".to_owned()),
            start_selector: "cuda:kernel_start".to_owned(),
            end_selector: "cuda:kernel_end".to_owned(),
            match_policy: MatchPolicy::Exact,
            samples: None,
            duration: Some(Duration::from_millis(request.duration_ms)),
            max_events: GPU_MAX_GROUPS,
            dropped_events: 0,
        },
    }
}

/// Query NVML until the window ends. Any failed query makes the source
/// unavailable rather than silently summarizing a shorter window.
fn sample_gpu_health(window: Duration) -> Result<Vec<Vec<gpu_health::DeviceSample>>, String> {
    let deadline = Instant::now() + window;
    let mut rounds = Vec::new();
    loop {
        let round = gpu_health::query()
            .map_err(|error| format!("NVML query {} failed: {error}", rounds.len() + 1))?;
        rounds.push(round);
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        thread::sleep(GPU_HEALTH_INTERVAL.min(deadline - now));
    }
    Ok(rounds)
}
