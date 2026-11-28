//! `measure --python-sample`: external CPython stack sampling.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use xprobe_collector::python_sampling::{
    ProcessMemory, ReadError, SamplerConfig, SamplerError, Walker, sample,
};
use xprobe_core::cpu_sampling_analysis::symbolize_native;
use xprobe_core::inspect;
use xprobe_core::python_layout::{self, PythonLocateError};
use xprobe_core::python_sampling::{SamplingRequest, analyze, native_addresses, records};
use xprobe_protocol::{ErrorCode, EvidenceArtifact, ExportFormat, PythonSampleResult, ReadLatency};

use crate::failure::{CommandFailure, emit_command_failure};

/// Python frames kept per stack.
pub(crate) const STACK_DEPTH: usize = 128;
/// Threads assumed per sweep when sizing the sample capacity.
const SIZING_THREADS: u64 = 64;
/// Upper bound on kept samples.
const MAX_CAPACITY: u64 = 2_000_000;

pub(crate) struct PythonSampleRequest<'a> {
    pub(crate) pid: u32,
    /// The interpreter, when the caller already located it.
    pub(crate) runtime: Option<python_layout::PythonRuntime>,
    pub(crate) name: Option<String>,
    pub(crate) duration_ms: u64,
    pub(crate) gil_hz: u32,
    pub(crate) threads_hz: u32,
    pub(crate) events_out: Option<&'a Path>,
}

pub(crate) fn run_python_sample(request: &PythonSampleRequest<'_>, json: bool) -> ExitCode {
    match python_sample(request) {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result)
                        .expect("Python sample result must serialize")
                );
            } else {
                print_python_sample(&result);
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_command_failure(error, json),
    }
}

fn print_python_sample(result: &PythonSampleResult) {
    let collection = &result.collection;
    println!(
        "CPython {} PID {}: {} GIL samples at {:.0} Hz, GIL released {:.0}% of ticks",
        collection.python_version,
        result.target.pid,
        collection.gil_samples,
        collection.gil_hz_achieved,
        result.inventory.gil_released_proportion * 100.0
    );
    for hotspot in result.inventory.gil_hotspots.iter().take(10) {
        println!(
            "  {:5.1}% self {:5.1}% total  {} ({}:{})",
            hotspot.exclusive_proportion * 100.0,
            hotspot.inclusive_proportion * 100.0,
            hotspot.frame.function,
            hotspot.frame.file,
            hotspot.frame.first_line
        );
    }
    if let Some(ReadLatency { p50_ns, p99_ns, .. }) = collection.read_latency {
        println!("  stack read p50 {p50_ns} ns, p99 {p99_ns} ns");
    }
}

fn locate_failure(error: &PythonLocateError) -> CommandFailure {
    let code = match error {
        PythonLocateError::NotPython => ErrorCode::SymbolNotFound,
        PythonLocateError::UnknownVersion { .. } | PythonLocateError::UnsupportedVersion { .. } => {
            ErrorCode::UnsupportedPythonVersion
        }
        PythonLocateError::NotMapped { .. } => ErrorCode::BinaryNotMapped,
        PythonLocateError::Io { .. } | PythonLocateError::InvalidElf { .. } => {
            ErrorCode::PermissionDenied
        }
    };
    CommandFailure::new(code, error.to_string(), true)
}

fn sampler_failure(error: &SamplerError) -> CommandFailure {
    match error {
        SamplerError::Read {
            error: ReadError::Permission,
            ..
        } => CommandFailure::new(ErrorCode::PermissionDenied, error.to_string(), true).with_hint(
            "reading another process's memory needs ptrace access: the same user under kernel.yama.ptrace_scope 0, or CAP_SYS_PTRACE",
        ),
        SamplerError::Read {
            error: ReadError::Gone,
            ..
        } => CommandFailure::new(ErrorCode::TargetExited, error.to_string(), true),
        SamplerError::LayoutMismatch { .. }
        | SamplerError::NotDebugOffsets
        | SamplerError::FreeThreaded => {
            CommandFailure::new(ErrorCode::UnsupportedPythonVersion, error.to_string(), true)
        }
        SamplerError::Read { .. } | SamplerError::NoInterpreter | SamplerError::Clock(_) => {
            CommandFailure::new(ErrorCode::Internal, error.to_string(), false)
        }
    }
}

/// Samples kept for this request: every GIL tick and every thread per sweep.
fn capacity(request: &PythonSampleRequest<'_>) -> u64 {
    let per_second = u64::from(request.gil_hz) + u64::from(request.threads_hz) * SIZING_THREADS;
    (per_second.saturating_mul(request.duration_ms) / 1000).clamp(1, MAX_CAPACITY)
}

fn period(hz: u32) -> Option<Duration> {
    (hz != 0).then(|| Duration::from_secs(1) / hz)
}

pub(crate) fn python_sample(
    request: &PythonSampleRequest<'_>,
) -> Result<PythonSampleResult, CommandFailure> {
    if request.duration_ms == 0 || request.threads_hz == 0 {
        return Err(CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            "--python-sample needs a positive --duration-ms and --python-threads-hz",
            true,
        ));
    }
    let report = inspect::run(request.pid).map_err(|error| {
        CommandFailure::new(error.code(), error.to_string(), error.recoverable())
    })?;
    let runtime = match request.runtime.clone() {
        Some(runtime) => runtime,
        None => python_layout::locate(&report).map_err(|error| locate_failure(&error))?,
    };
    let memory = ProcessMemory::new(request.pid);
    let mut walker = Walker::new(&memory, runtime.clone(), STACK_DEPTH);
    let sample_capacity = capacity(request);
    let duration = Duration::from_millis(request.duration_ms);
    let wall_clock_start = crate::live::clock_anchor()?;
    let capture = sample(
        &mut walker,
        request.pid,
        SamplerConfig {
            duration,
            gil_period: period(request.gil_hz),
            threads_period: period(request.threads_hz).expect("threads rate is positive"),
            max_samples: usize::try_from(sample_capacity).unwrap_or(usize::MAX),
            max_depth: STACK_DEPTH,
        },
    )
    .map_err(|error| sampler_failure(&error))?;
    let wall_clock = xprobe_protocol::WallClock {
        start: wall_clock_start,
        end: crate::live::clock_anchor()?,
    };
    // A sample of a reused PID describes the wrong process.
    inspect::verify_target(&report.target).map_err(|error| {
        CommandFailure::new(error.code(), error.to_string(), error.recoverable())
    })?;
    // Symbolize native leaves while the target's mappings are still live.
    let native = symbolize_native(&report, &native_addresses(&capture))
        .map_err(|error| CommandFailure::new(error.code(), error.to_string(), true))?;
    let mut result = analyze(
        &SamplingRequest {
            session_id: format!("xp_python_{}", std::process::id()),
            name: request.name.clone(),
            target: report.target.clone(),
            python_minor: runtime.minor,
            python_binary: runtime.binary.display().to_string(),
            duration,
            gil_hz: request.gil_hz,
            threads_hz: request.threads_hz,
            sample_capacity,
            stack_depth: u32::try_from(STACK_DEPTH).unwrap_or(u32::MAX),
        },
        &capture,
        &native,
    );
    result.collection.wall_clock = Some(wall_clock);
    let path = match request.events_out {
        Some(path) => path.to_path_buf(),
        None => crate::private_artifact_dir()?.join("python-samples.jsonl"),
    };
    let lines = records(&capture, request.pid, &native);
    let mut text = String::new();
    for line in &lines {
        text.push_str(&serde_json::to_string(line).expect("sample record must serialize"));
        text.push('\n');
    }
    crate::dev::write_export_file(&path, text.as_bytes()).map_err(|error| {
        CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!("failed to write {}: {error}", path.display()),
            false,
        )
    })?;
    result.artifact = Some(EvidenceArtifact {
        path: path.display().to_string(),
        format: ExportFormat::Jsonl,
        events: lines.len() as u64,
    });
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{PythonSampleRequest, capacity};

    #[test]
    fn capacity_covers_the_requested_rates_with_a_bound() {
        let request = PythonSampleRequest {
            pid: 1,
            runtime: None,
            name: None,
            duration_ms: 2000,
            gil_hz: 2000,
            threads_hz: 100,
            events_out: None,
        };
        assert_eq!(capacity(&request), 2 * (2000 + 100 * 64));
        let long = PythonSampleRequest {
            duration_ms: 10_000_000,
            ..request
        };
        assert_eq!(capacity(&long), 2_000_000);
    }
}
