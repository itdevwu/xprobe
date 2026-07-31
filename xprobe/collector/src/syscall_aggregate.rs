use std::{
    error::Error,
    ffi::OsStr,
    fmt, fs, io,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use libbpf_rs::{ErrorKind, Link, MapCore, MapFlags, Object, ObjectBuilder};
use xprobe_protocol::{ErrorCode, TargetIdentity};

const WAIT_INTERVAL: Duration = Duration::from_millis(10);
const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/xprobe.bpf.o"));

#[derive(Debug, Clone)]
pub struct SyscallAggregateRequest {
    pub target: TargetIdentity,
    pub duration: Duration,
    pub timeout: Duration,
    pub max_groups: u32,
    pub max_inflight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSyscallAggregate {
    pub syscall_number: u32,
    pub count: u64,
    pub errors: u64,
    pub total_duration_ns: u64,
    pub min_duration_ns: u64,
    pub max_duration_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallAggregateCapture {
    pub groups: Vec<RawSyscallAggregate>,
    pub observed_entries: u64,
    pub matched_exits: u64,
    pub unmatched_exits: u64,
    pub dropped_aggregates: u64,
    pub inflight_at_end: u64,
}

#[derive(Debug)]
pub enum SyscallAggregateError {
    InvalidRequest(&'static str),
    TargetNamespace {
        path: PathBuf,
        source: io::Error,
    },
    MissingObjectMember {
        kind: &'static str,
        name: String,
    },
    Libbpf {
        operation: &'static str,
        source: libbpf_rs::Error,
    },
    MalformedMapValue {
        map: &'static str,
        expected: usize,
        actual: usize,
    },
    Timeout,
}

impl SyscallAggregateError {
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidRequest(_) | Self::Timeout => ErrorCode::SessionLimitExceeded,
            Self::TargetNamespace { source, .. }
                if source.kind() == io::ErrorKind::PermissionDenied =>
            {
                ErrorCode::PermissionDenied
            }
            Self::TargetNamespace { source, .. } if source.kind() == io::ErrorKind::NotFound => {
                ErrorCode::TargetExited
            }
            Self::Libbpf {
                operation: "disarm syscall aggregate",
                ..
            } => ErrorCode::CleanupFailed,
            Self::Libbpf { source, .. } if source.kind() == ErrorKind::PermissionDenied => {
                ErrorCode::PermissionDenied
            }
            Self::TargetNamespace { .. }
            | Self::MissingObjectMember { .. }
            | Self::Libbpf { .. }
            | Self::MalformedMapValue { .. } => ErrorCode::Internal,
        }
    }

    #[must_use]
    pub fn recoverable(&self) -> bool {
        matches!(
            self.code(),
            ErrorCode::SessionLimitExceeded | ErrorCode::PermissionDenied | ErrorCode::TargetExited
        )
    }
}

impl fmt::Display for SyscallAggregateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid syscall aggregate request: {message}")
            }
            Self::TargetNamespace { path, source } => write!(
                formatter,
                "failed to inspect target PID namespace at {}: {source}",
                path.display()
            ),
            Self::MissingObjectMember { kind, name } => {
                write!(formatter, "BPF object is missing {kind} {name}")
            }
            Self::Libbpf { operation, source } => {
                write!(formatter, "failed to {operation}: {source:#}")
            }
            Self::MalformedMapValue {
                map,
                expected,
                actual,
            } => write!(
                formatter,
                "BPF map {map} value has size {actual}, expected {expected}"
            ),
            Self::Timeout => formatter.write_str("syscall aggregate collection timed out"),
        }
    }
}

impl Error for SyscallAggregateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TargetNamespace { source, .. } => Some(source),
            Self::Libbpf { source, .. } => Some(source),
            Self::InvalidRequest(_)
            | Self::MissingObjectMember { .. }
            | Self::MalformedMapValue { .. }
            | Self::Timeout => None,
        }
    }
}

/// Collect bounded PID-scoped syscall lifecycle aggregates entirely in BPF maps.
///
/// # Errors
///
/// Returns [`SyscallAggregateError`] for invalid bounds, BPF setup, attachment,
/// timeout, cleanup, or map decoding failures.
pub fn collect(
    request: &SyscallAggregateRequest,
) -> Result<SyscallAggregateCapture, SyscallAggregateError> {
    validate_request(request)?;
    let started = Instant::now();
    let timeout_at =
        started
            .checked_add(request.timeout)
            .ok_or(SyscallAggregateError::InvalidRequest(
                "timeout overflows the monotonic clock",
            ))?;
    let object = load_object(request.max_groups, request.max_inflight)?;
    configure_object(&object, request)?;
    let _links = attach_programs(&object)?;
    set_armed(&object, true)?;
    let capture_end = Instant::now().checked_add(request.duration).ok_or(
        SyscallAggregateError::InvalidRequest("duration overflows the monotonic clock"),
    )?;
    while Instant::now() < capture_end {
        if Instant::now() >= timeout_at {
            set_armed(&object, false)?;
            return Err(SyscallAggregateError::Timeout);
        }
        thread::sleep(WAIT_INTERVAL.min(capture_end.saturating_duration_since(Instant::now())));
    }
    set_armed(&object, false)?;
    read_capture(&object)
}

fn validate_request(request: &SyscallAggregateRequest) -> Result<(), SyscallAggregateError> {
    if request.duration.is_zero() {
        return Err(SyscallAggregateError::InvalidRequest(
            "duration must be positive",
        ));
    }
    if request.timeout < request.duration {
        return Err(SyscallAggregateError::InvalidRequest(
            "timeout must be at least the capture duration",
        ));
    }
    if request.max_groups == 0 {
        return Err(SyscallAggregateError::InvalidRequest(
            "max_groups must be positive",
        ));
    }
    if request.max_inflight == 0 {
        return Err(SyscallAggregateError::InvalidRequest(
            "max_inflight must be positive",
        ));
    }
    Ok(())
}

fn load_object(max_groups: u32, max_inflight: u32) -> Result<Object, SyscallAggregateError> {
    let mut builder = ObjectBuilder::default();
    builder
        .name("xprobe_syscalls")
        .map_err(|source| libbpf_error("name BPF object", source))?;
    let mut open_object = builder
        .open_memory(BPF_OBJECT)
        .map_err(|source| libbpf_error("open BPF object", source))?;
    open_object
        .maps_mut()
        .find(|map| map.name() == OsStr::new("syscall_aggregate_groups"))
        .ok_or_else(|| missing("map", "syscall_aggregate_groups"))?
        .set_max_entries(max_groups)
        .map_err(|source| libbpf_error("size syscall aggregate groups", source))?;
    open_object
        .maps_mut()
        .find(|map| map.name() == OsStr::new("syscall_aggregate_inflight"))
        .ok_or_else(|| missing("map", "syscall_aggregate_inflight"))?
        .set_max_entries(max_inflight)
        .map_err(|source| libbpf_error("size syscall inflight table", source))?;
    open_object
        .load()
        .map_err(|source| libbpf_error("load BPF object", source))
}

fn configure_object(
    object: &Object,
    request: &SyscallAggregateRequest,
) -> Result<(), SyscallAggregateError> {
    let namespace_path = PathBuf::from(format!("/proc/{}/ns/pid", request.target.pid));
    let namespace =
        fs::metadata(&namespace_path).map_err(|source| SyscallAggregateError::TargetNamespace {
            path: namespace_path,
            source,
        })?;
    let mut config = [0_u8; 24];
    config[0..8].copy_from_slice(&namespace.dev().to_ne_bytes());
    config[8..16].copy_from_slice(&namespace.ino().to_ne_bytes());
    config[16..20].copy_from_slice(&request.target.pid.to_ne_bytes());
    let key = 0_u32.to_ne_bytes();
    object
        .maps()
        .find(|map| map.name() == OsStr::new("syscall_aggregate_config"))
        .ok_or_else(|| missing("map", "syscall_aggregate_config"))?
        .update(&key, &config, MapFlags::ANY)
        .map_err(|source| libbpf_error("configure syscall aggregate", source))
}

fn attach_programs(object: &Object) -> Result<Vec<Link>, SyscallAggregateError> {
    let mut links = Vec::with_capacity(2);
    for (program_name, tracepoint_name) in [
        ("xprobe_aggregate_syscall_entry", "sys_enter"),
        ("xprobe_aggregate_syscall_exit", "sys_exit"),
    ] {
        let program = object
            .progs_mut()
            .find(|program| program.name() == OsStr::new(program_name))
            .ok_or_else(|| missing("program", program_name))?;
        links.push(
            program
                .attach_raw_tracepoint(tracepoint_name)
                .map_err(|source| libbpf_error("attach syscall aggregate tracepoint", source))?,
        );
    }
    Ok(links)
}

fn set_armed(object: &Object, armed: bool) -> Result<(), SyscallAggregateError> {
    let key = 0_u32.to_ne_bytes();
    let map = object
        .maps()
        .find(|map| map.name() == OsStr::new("syscall_aggregate_config"))
        .ok_or_else(|| missing("map", "syscall_aggregate_config"))?;
    let mut config = map
        .lookup(&key, MapFlags::ANY)
        .map_err(|source| libbpf_error("read syscall aggregate config", source))?
        .ok_or_else(|| missing("map value", "syscall_aggregate_config"))?;
    if config.len() != 24 {
        return Err(SyscallAggregateError::MalformedMapValue {
            map: "syscall_aggregate_config",
            expected: 24,
            actual: config.len(),
        });
    }
    config[20..24].copy_from_slice(&u32::from(armed).to_ne_bytes());
    let operation = if armed {
        "arm syscall aggregate"
    } else {
        "disarm syscall aggregate"
    };
    map.update(&key, &config, MapFlags::ANY)
        .map_err(|source| libbpf_error(operation, source))
}

fn read_capture(object: &Object) -> Result<SyscallAggregateCapture, SyscallAggregateError> {
    let map = object
        .maps()
        .find(|map| map.name() == OsStr::new("syscall_aggregate_groups"))
        .ok_or_else(|| missing("map", "syscall_aggregate_groups"))?;
    let mut groups = Vec::new();
    for key in map.keys() {
        let syscall_number = decode_u32("syscall_aggregate_groups", &key)?;
        let values = map
            .lookup_percpu(&key, MapFlags::ANY)
            .map_err(|source| libbpf_error("read syscall aggregate group", source))?
            .ok_or_else(|| missing("map value", "syscall_aggregate_groups"))?;
        groups.push(sum_group(syscall_number, &values)?);
    }
    groups.sort_by(|left, right| {
        right
            .total_duration_ns
            .cmp(&left.total_duration_ns)
            .then_with(|| left.syscall_number.cmp(&right.syscall_number))
    });
    let summary = read_summary(object)?;
    let inflight_at_end = u64::try_from(
        object
            .maps()
            .find(|map| map.name() == OsStr::new("syscall_aggregate_inflight"))
            .ok_or_else(|| missing("map", "syscall_aggregate_inflight"))?
            .keys()
            .count(),
    )
    .unwrap_or(u64::MAX);
    Ok(SyscallAggregateCapture {
        groups,
        observed_entries: summary[0],
        matched_exits: summary[1],
        unmatched_exits: summary[2],
        dropped_aggregates: summary[3],
        inflight_at_end,
    })
}

fn sum_group(
    syscall_number: u32,
    values: &[Vec<u8>],
) -> Result<RawSyscallAggregate, SyscallAggregateError> {
    let mut group = RawSyscallAggregate {
        syscall_number,
        count: 0,
        errors: 0,
        total_duration_ns: 0,
        min_duration_ns: u64::MAX,
        max_duration_ns: 0,
    };
    for value in values {
        let fields = decode_u64_fields::<5>("syscall_aggregate_groups", value)?;
        if fields[0] == 0 {
            continue;
        }
        group.count = group.count.saturating_add(fields[0]);
        group.errors = group.errors.saturating_add(fields[1]);
        group.total_duration_ns = group.total_duration_ns.saturating_add(fields[2]);
        group.min_duration_ns = group.min_duration_ns.min(fields[3]);
        group.max_duration_ns = group.max_duration_ns.max(fields[4]);
    }
    if group.count == 0 {
        group.min_duration_ns = 0;
    }
    Ok(group)
}

fn read_summary(object: &Object) -> Result<[u64; 4], SyscallAggregateError> {
    let key = 0_u32.to_ne_bytes();
    let value = object
        .maps()
        .find(|map| map.name() == OsStr::new("syscall_aggregate_summary"))
        .ok_or_else(|| missing("map", "syscall_aggregate_summary"))?
        .lookup(&key, MapFlags::ANY)
        .map_err(|source| libbpf_error("read syscall aggregate summary", source))?
        .ok_or_else(|| missing("map value", "syscall_aggregate_summary"))?;
    decode_u64_fields::<4>("syscall_aggregate_summary", &value)
}

fn decode_u32(map: &'static str, bytes: &[u8]) -> Result<u32, SyscallAggregateError> {
    let bytes: [u8; 4] =
        bytes
            .try_into()
            .map_err(|_| SyscallAggregateError::MalformedMapValue {
                map,
                expected: 4,
                actual: bytes.len(),
            })?;
    Ok(u32::from_ne_bytes(bytes))
}

fn decode_u64_fields<const N: usize>(
    map: &'static str,
    bytes: &[u8],
) -> Result<[u64; N], SyscallAggregateError> {
    let expected = N * 8;
    if bytes.len() != expected {
        return Err(SyscallAggregateError::MalformedMapValue {
            map,
            expected,
            actual: bytes.len(),
        });
    }
    Ok(std::array::from_fn(|index| {
        let start = index * 8;
        u64::from_ne_bytes(
            bytes[start..start + 8]
                .try_into()
                .expect("checked u64 field"),
        )
    }))
}

fn missing(kind: &'static str, name: &str) -> SyscallAggregateError {
    SyscallAggregateError::MissingObjectMember {
        kind,
        name: name.to_owned(),
    }
}

fn libbpf_error(operation: &'static str, source: libbpf_rs::Error) -> SyscallAggregateError {
    SyscallAggregateError::Libbpf { operation, source }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_per_cpu_aggregate_values() {
        let values = vec![fields(&[3, 1, 30, 5, 15]), fields(&[2, 0, 50, 20, 30])];
        assert_eq!(
            sum_group(9, &values).unwrap(),
            RawSyscallAggregate {
                syscall_number: 9,
                count: 5,
                errors: 1,
                total_duration_ns: 80,
                min_duration_ns: 5,
                max_duration_ns: 30,
            }
        );
    }

    #[test]
    fn rejects_zero_map_capacities() {
        let request = SyscallAggregateRequest {
            target: TargetIdentity {
                pid: 1,
                process_start_time: 1,
            },
            duration: Duration::from_millis(1),
            timeout: Duration::from_millis(2),
            max_groups: 0,
            max_inflight: 1,
        };
        assert!(matches!(
            validate_request(&request),
            Err(SyscallAggregateError::InvalidRequest(_))
        ));
    }

    fn fields(values: &[u64]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_ne_bytes())
            .collect()
    }
}
