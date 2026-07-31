use std::{collections::BTreeMap, error::Error, fmt};

use xprobe_protocol::{
    AggregateDuration, ErrorCode, ProcessReport, SchemaVersion, SessionStatus,
    SyscallAggregateCollectionSummary, SyscallAggregateCompleteness, SyscallAggregateGroup,
    SyscallAggregateInventory, SyscallAggregateRequirements, SyscallAggregateResult,
    SyscallAggregateSpec, SyscallAggregateValidationResult, ValidationIssue, Warning,
};

use crate::{
    doctor::{self, DoctorError},
    inspect::{self, InspectError},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSyscallGroup {
    pub syscall_number: u32,
    pub count: u64,
    pub errors: u64,
    pub total_duration_ns: u64,
    pub min_duration_ns: u64,
    pub max_duration_ns: u64,
}

#[derive(Debug, Clone)]
pub struct SyscallCaptureData {
    pub groups: Vec<RawSyscallGroup>,
    pub observed_entries: u64,
    pub matched_exits: u64,
    pub unmatched_exits: u64,
    pub dropped_aggregates: u64,
    pub inflight_at_end: u64,
}

#[derive(Debug)]
pub enum SyscallAggregateError {
    Inspect(InspectError),
    Doctor(DoctorError),
}

impl SyscallAggregateError {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Inspect(error) => error.code(),
            Self::Doctor(_) => ErrorCode::Internal,
        }
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::Inspect(error) => error.recoverable(),
            Self::Doctor(_) => false,
        }
    }
}

impl fmt::Display for SyscallAggregateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => error.fmt(formatter),
            Self::Doctor(error) => write!(
                formatter,
                "syscall aggregate capability check failed: {error}"
            ),
        }
    }
}

impl Error for SyscallAggregateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inspect(error) => Some(error),
            Self::Doctor(error) => Some(error),
        }
    }
}

impl From<InspectError> for SyscallAggregateError {
    fn from(error: InspectError) -> Self {
        Self::Inspect(error)
    }
}

impl From<DoctorError> for SyscallAggregateError {
    fn from(error: DoctorError) -> Self {
        Self::Doctor(error)
    }
}

/// Validate read-only requirements for PID-scoped syscall aggregation.
///
/// # Errors
///
/// Returns [`SyscallAggregateError`] if target identity or local capability
/// inspection fails.
pub fn validate(
    report: &ProcessReport,
) -> Result<SyscallAggregateValidationResult, SyscallAggregateError> {
    inspect::verify_target(&report.target)?;
    let capabilities = doctor::run()?;
    let ebpf = capabilities.checks.ebpf_permissions.clone();
    let mut issues = Vec::new();
    if !report.capabilities.tracepoint {
        issues.push(ValidationIssue {
            code: ErrorCode::PermissionDenied,
            message: "syscall aggregation requires effective eBPF tracepoint privileges".to_owned(),
        });
    }
    inspect::verify_target(&report.target)?;
    Ok(SyscallAggregateValidationResult {
        schema_version: SchemaVersion::current(),
        ok: true,
        valid: issues.is_empty(),
        target: report.target.clone(),
        requirements: SyscallAggregateRequirements {
            needs_ebpf: true,
            target_mutation: false,
        },
        ebpf,
        issues,
        warnings: Vec::new(),
    })
}

/// Normalize one completed BPF syscall aggregate capture.
///
/// # Errors
///
/// Returns [`SyscallAggregateError`] when the target identity changed around
/// collection.
pub fn analyze(
    report: &ProcessReport,
    spec: &SyscallAggregateSpec,
    session_id: String,
    capture: &SyscallCaptureData,
) -> Result<SyscallAggregateResult, SyscallAggregateError> {
    inspect::verify_target(&report.target)?;
    let mut groups = capture
        .groups
        .iter()
        .filter(|group| group.count != 0)
        .map(normalize_group)
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| {
        right
            .duration_ns
            .total
            .cmp(&left.duration_ns.total)
            .then_with(|| right.count.cmp(&left.count))
            .then_with(|| left.syscall_number.cmp(&right.syscall_number))
    });
    let complete = capture.unmatched_exits == 0
        && capture.inflight_at_end == 0
        && capture.dropped_aggregates == 0;
    let mut warnings = Vec::new();
    if capture.dropped_aggregates != 0 {
        warnings.push(warning(
            "SYSCALL_AGGREGATES_DROPPED",
            &format!(
                "{} syscall lifecycles could not be retained; increase max_groups or max_inflight",
                capture.dropped_aggregates
            ),
        ));
    }
    if capture.unmatched_exits != 0 || capture.inflight_at_end != 0 {
        warnings.push(warning(
            "SYSCALL_LIFECYCLES_UNMATCHED",
            &format!(
                "{} exits had no start and {} starts remained open at capture end",
                capture.unmatched_exits, capture.inflight_at_end
            ),
        ));
    }
    inspect::verify_target(&report.target)?;
    Ok(SyscallAggregateResult {
        schema_version: SchemaVersion::current(),
        ok: true,
        session_id,
        status: SessionStatus::Completed,
        target: report.target.clone(),
        inventory: SyscallAggregateInventory {
            name: spec.name.clone(),
            duration_ms: spec.duration_ms,
            groups,
        },
        collection: SyscallAggregateCollectionSummary {
            completeness: if complete {
                SyscallAggregateCompleteness::Complete
            } else {
                SyscallAggregateCompleteness::Incomplete
            },
            observed_entries: capture.observed_entries,
            matched_exits: capture.matched_exits,
            unmatched_exits: capture.unmatched_exits,
            inflight_at_end: capture.inflight_at_end,
            dropped_aggregates: capture.dropped_aggregates,
            group_capacity: spec.max_groups,
            groups: u64::try_from(capture.groups.len()).unwrap_or(u64::MAX),
            table_utilization: ratio(
                u64::try_from(capture.groups.len()).unwrap_or(u64::MAX),
                spec.max_groups.max(1),
            ),
        },
        warnings,
    })
}

fn normalize_group(group: &RawSyscallGroup) -> SyscallAggregateGroup {
    let syscall_name = syscall_name(group.syscall_number).map(str::to_owned);
    let (entry_selector_hint, exit_selector_hint) =
        syscall_name.as_ref().map_or((None, None), |name| {
            (
                Some(format!("syscall:{name}:entry")),
                Some(format!("syscall:{name}:exit")),
            )
        });
    SyscallAggregateGroup {
        syscall_number: group.syscall_number,
        syscall_name,
        count: group.count,
        errors: group.errors,
        duration_ns: AggregateDuration {
            min: group.min_duration_ns,
            mean: ratio(group.total_duration_ns, group.count),
            max: group.max_duration_ns,
            total: group.total_duration_ns,
        },
        entry_selector_hint,
        exit_selector_hint,
    }
}

fn syscall_name(number: u32) -> Option<&'static str> {
    Some(match number {
        0 => "read",
        1 => "write",
        3 => "close",
        5 => "fstat",
        7 => "poll",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        16 => "ioctl",
        17 => "pread64",
        18 => "pwrite64",
        19 => "readv",
        20 => "writev",
        24 => "sched_yield",
        25 => "mremap",
        26 => "msync",
        27 => "mincore",
        28 => "madvise",
        35 => "nanosleep",
        39 => "getpid",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        61 => "wait4",
        72 => "fcntl",
        73 => "flock",
        74 => "fsync",
        75 => "fdatasync",
        78 => "getdents",
        186 => "gettid",
        202 => "futex",
        203 => "sched_setaffinity",
        204 => "sched_getaffinity",
        232 => "epoll_wait",
        233 => "epoll_ctl",
        234 => "tgkill",
        257 => "openat",
        262 => "newfstatat",
        270 => "pselect6",
        271 => "ppoll",
        272 => "unshare",
        275 => "splice",
        281 => "epoll_pwait",
        288 => "accept4",
        290 => "eventfd2",
        291 => "epoll_create1",
        292 => "dup3",
        293 => "pipe2",
        295 => "preadv",
        296 => "pwritev",
        298 => "perf_event_open",
        299 => "recvmmsg",
        302 => "prlimit64",
        307 => "sendmmsg",
        309 => "getcpu",
        310 => "process_vm_readv",
        311 => "process_vm_writev",
        314 => "sched_setattr",
        315 => "sched_getattr",
        317 => "seccomp",
        318 => "getrandom",
        319 => "memfd_create",
        321 => "bpf",
        322 => "execveat",
        323 => "userfaultfd",
        324 => "membarrier",
        325 => "mlock2",
        326 => "copy_file_range",
        327 => "preadv2",
        328 => "pwritev2",
        332 => "statx",
        334 => "rseq",
        424 => "pidfd_send_signal",
        425 => "io_uring_setup",
        426 => "io_uring_enter",
        427 => "io_uring_register",
        434 => "pidfd_open",
        435 => "clone3",
        436 => "close_range",
        437 => "openat2",
        438 => "pidfd_getfd",
        439 => "faccessat2",
        440 => "process_madvise",
        441 => "epoll_pwait2",
        449 => "futex_waitv",
        _ => return None,
    })
}

fn warning(code: &str, message: &str) -> Warning {
    Warning {
        code: code.to_owned(),
        message: message.to_owned(),
        details: BTreeMap::new(),
    }
}

#[allow(clippy::cast_precision_loss)]
fn ratio(numerator: u64, denominator: u64) -> f64 {
    numerator as f64 / denominator as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_known_syscalls_and_selector_hints() {
        let group = normalize_group(&RawSyscallGroup {
            syscall_number: 9,
            count: 4,
            errors: 1,
            total_duration_ns: 100,
            min_duration_ns: 10,
            max_duration_ns: 50,
        });
        assert_eq!(group.syscall_name.as_deref(), Some("mmap"));
        assert!((group.duration_ns.mean - 25.0).abs() < f64::EPSILON);
        assert_eq!(
            group.entry_selector_hint.as_deref(),
            Some("syscall:mmap:entry")
        );
    }
}
