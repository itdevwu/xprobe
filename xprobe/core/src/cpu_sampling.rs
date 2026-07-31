use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsStr,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use object::{Object, ObjectSymbol};
use xprobe_protocol::{
    CheckResult, CheckStatus, CpuSamplingRequirements, CpuSamplingValidationResult, ErrorCode,
    ProcessReport, PythonSymbolizationStatus, SchemaVersion, ValidationIssue, Warning,
};

use crate::{
    doctor::{self, DoctorError},
    inspect::{self, InspectError},
};

const MAX_PERF_MAP_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum CpuSamplingError {
    Inspect(InspectError),
    Doctor(DoctorError),
    Io { path: PathBuf, source: io::Error },
    InvalidElf { path: PathBuf, reason: String },
    InvalidTask { path: PathBuf, value: String },
    Limit { name: &'static str, value: u64 },
}

impl CpuSamplingError {
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Inspect(error) => error.code(),
            Self::Io { source, .. } if source.kind() == io::ErrorKind::PermissionDenied => {
                ErrorCode::PermissionDenied
            }
            Self::Limit { .. } => ErrorCode::SessionLimitExceeded,
            Self::Doctor(_)
            | Self::Io { .. }
            | Self::InvalidElf { .. }
            | Self::InvalidTask { .. } => ErrorCode::Internal,
        }
    }

    #[must_use]
    pub fn recoverable(&self) -> bool {
        match self {
            Self::Inspect(error) => error.recoverable(),
            Self::Io { source, .. } => {
                matches!(
                    source.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                )
            }
            Self::Limit { .. } => true,
            Self::Doctor(_) | Self::InvalidElf { .. } | Self::InvalidTask { .. } => false,
        }
    }
}

impl fmt::Display for CpuSamplingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => error.fmt(formatter),
            Self::Doctor(error) => {
                write!(formatter, "CPU sampling capability check failed: {error}")
            }
            Self::Io { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::InvalidElf { path, reason } => {
                write!(
                    formatter,
                    "failed to parse ELF {}: {reason}",
                    path.display()
                )
            }
            Self::InvalidTask { path, value } => {
                write!(
                    formatter,
                    "invalid task entry {value:?} in {}",
                    path.display()
                )
            }
            Self::Limit { name, value } => {
                write!(
                    formatter,
                    "CPU sampling {name} exceeds the supported bound: {value}"
                )
            }
        }
    }
}

impl Error for CpuSamplingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inspect(error) => Some(error),
            Self::Doctor(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::InvalidElf { .. } | Self::InvalidTask { .. } | Self::Limit { .. } => None,
        }
    }
}

impl From<InspectError> for CpuSamplingError {
    fn from(error: InspectError) -> Self {
        Self::Inspect(error)
    }
}

impl From<DoctorError> for CpuSamplingError {
    fn from(error: DoctorError) -> Self {
        Self::Doctor(error)
    }
}

/// Validate CPU sampling requirements without opening a perf event or loading BPF.
///
/// # Errors
///
/// Returns [`CpuSamplingError`] when target identity, procfs, local capability,
/// or mapped ELF inspection fails unexpectedly.
pub fn validate(report: &ProcessReport) -> Result<CpuSamplingValidationResult, CpuSamplingError> {
    inspect::verify_target(&report.target)?;
    let target_threads = target_threads(&report.target)?;
    let capabilities = doctor::run()?;
    let perf_event = effective_perf_check(&capabilities, report.credentials.effective_uid);
    let python_status = python_symbolization_status(report)?;

    let mut issues = Vec::new();
    if perf_event.status != CheckStatus::Available {
        issues.push(ValidationIssue {
            code: ErrorCode::PermissionDenied,
            message: "CPU sampling is restricted by the effective perf event policy".to_owned(),
        });
    }

    let mut warnings = Vec::new();
    match python_status {
        PythonSymbolizationStatus::Inactive => warnings.push(warning(
            "PYTHON_PERF_TRAMPOLINE_INACTIVE",
            "CPython perf trampoline support is present but inactive; native frames remain available",
        )),
        PythonSymbolizationStatus::Unsupported => warnings.push(warning(
            "PYTHON_PERF_TRAMPOLINE_UNSUPPORTED",
            "the mapped CPython build does not expose perf trampoline symbols; native frames remain available",
        )),
        PythonSymbolizationStatus::NotDetected | PythonSymbolizationStatus::Active => {}
    }

    inspect::verify_target(&report.target)?;
    Ok(CpuSamplingValidationResult {
        schema_version: SchemaVersion::current(),
        ok: true,
        valid: issues.is_empty(),
        target: report.target.clone(),
        target_threads,
        requirements: CpuSamplingRequirements {
            needs_perf_event: true,
            target_mutation: false,
        },
        perf_event,
        python_status,
        issues,
        warnings,
    })
}

/// Return the target's current thread IDs after verifying process identity.
///
/// # Errors
///
/// Returns [`CpuSamplingError`] for target changes, malformed task entries, I/O
/// failures, or a task count that cannot be represented by the public contract.
pub fn target_thread_ids(
    target: &xprobe_protocol::TargetIdentity,
) -> Result<Vec<u32>, CpuSamplingError> {
    inspect::verify_target(target)?;
    let path = PathBuf::from(format!("/proc/{}/task", target.pid));
    let entries = fs::read_dir(&path).map_err(|source| CpuSamplingError::Io {
        path: path.clone(),
        source,
    })?;
    let mut threads = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|source| CpuSamplingError::Io {
            path: path.clone(),
            source,
        })?;
        let value = entry.file_name();
        let text = value
            .to_str()
            .ok_or_else(|| CpuSamplingError::InvalidTask {
                path: path.clone(),
                value: value.to_string_lossy().into_owned(),
            })?;
        let tid = text
            .parse::<u32>()
            .map_err(|_| CpuSamplingError::InvalidTask {
                path: path.clone(),
                value: text.to_owned(),
            })?;
        threads.insert(tid);
    }
    inspect::verify_target(target)?;
    Ok(threads.into_iter().collect())
}

fn target_threads(target: &xprobe_protocol::TargetIdentity) -> Result<u32, CpuSamplingError> {
    let count = target_thread_ids(target)?.len();
    u32::try_from(count).map_err(|_| CpuSamplingError::Limit {
        name: "thread count",
        value: u64::try_from(count).unwrap_or(u64::MAX),
    })
}

fn effective_perf_check(
    report: &xprobe_protocol::CapabilityReport,
    target_effective_uid: u32,
) -> CheckResult {
    let same_user = report.environment.effective_uid == target_effective_uid;
    let user_space_process_sampling_allowed = report
        .checks
        .perf_event_paranoid
        .detail
        .as_deref()
        .and_then(|value| value.parse::<i32>().ok())
        .is_some_and(|value| value <= 2);
    if report.environment.effective_uid == 0
        || report.capabilities.uprobe
        || (same_user && user_space_process_sampling_allowed)
    {
        return CheckResult {
            status: CheckStatus::Available,
            detail: Some(format!(
                "PID-scoped user-space sampling is permitted; perf_event_paranoid={}",
                report
                    .checks
                    .perf_event_paranoid
                    .detail
                    .as_deref()
                    .unwrap_or("unknown")
            )),
        };
    }
    report.checks.perf_event_paranoid.clone()
}

fn python_symbolization_status(
    report: &ProcessReport,
) -> Result<PythonSymbolizationStatus, CpuSamplingError> {
    let mut candidates = vec![PathBuf::from(&report.executable)];
    candidates.extend(
        report
            .loaded_libraries
            .iter()
            .map(PathBuf::from)
            .filter(|path| {
                path.file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.starts_with("libpython"))
            }),
    );
    candidates.sort();
    candidates.dedup();

    let mut python_detected = false;
    let mut trampoline_supported = false;
    for path in candidates {
        let symbols = elf_symbol_names(&path)?;
        let is_python = symbols.contains("Py_Initialize")
            || symbols.contains("_PyEval_EvalFrameDefault")
            || symbols.contains("PyUnstable_PerfMapState_Init");
        if !is_python {
            continue;
        }
        python_detected = true;
        trampoline_supported |= symbols.contains("_Py_trampoline_func_start")
            && symbols.contains("PyUnstable_WritePerfMapEntry");
    }
    if !python_detected {
        return Ok(PythonSymbolizationStatus::NotDetected);
    }
    if !trampoline_supported {
        return Ok(PythonSymbolizationStatus::Unsupported);
    }

    let path = PathBuf::from(format!(
        "/proc/{}/root/tmp/perf-{}.map",
        report.target.pid, report.target.pid
    ));
    match fs::metadata(&path) {
        Ok(metadata) if metadata.len() > MAX_PERF_MAP_BYTES => Err(CpuSamplingError::Limit {
            name: "perf map bytes",
            value: metadata.len(),
        }),
        Ok(metadata) if metadata.is_file() && metadata.len() != 0 => {
            Ok(PythonSymbolizationStatus::Active)
        }
        Ok(_) => Ok(PythonSymbolizationStatus::Inactive),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            Ok(PythonSymbolizationStatus::Inactive)
        }
        Err(source) => Err(CpuSamplingError::Io { path, source }),
    }
}

fn elf_symbol_names(path: &Path) -> Result<BTreeSet<String>, CpuSamplingError> {
    let bytes = fs::read(path).map_err(|source| CpuSamplingError::Io {
        path: path.to_owned(),
        source,
    })?;
    let file =
        object::File::parse(bytes.as_slice()).map_err(|error| CpuSamplingError::InvalidElf {
            path: path.to_owned(),
            reason: error.to_string(),
        })?;
    Ok(file
        .symbols()
        .chain(file.dynamic_symbols())
        .filter_map(|symbol| symbol.name().ok().map(str::to_owned))
        .collect())
}

fn warning(code: &str, message: &str) -> Warning {
    Warning {
        code: code.to_owned(),
        message: message.to_owned(),
        details: BTreeMap::new(),
    }
}
