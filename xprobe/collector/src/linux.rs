use std::{
    cell::RefCell,
    collections::BTreeMap,
    error::Error,
    ffi::OsStr,
    fmt, fs, io,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::SyncSender,
    },
    time::{Duration, Instant},
};

use libbpf_rs::{
    ErrorKind, Link, MapCore, MapFlags, Object, ObjectBuilder, RingBufferBuilder,
    TracepointCategory,
};
use serde_json::Value;
use xprobe_protocol::{
    ArgumentValue, ClockDomain, ErrorCode, Event, EventSource, EventType, HostCaptureResult,
    HostEvent, HostProbeKind, ResolvedLinuxSelector, SchemaVersion, TargetIdentity,
};

const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/xprobe.bpf.o"));
const RAW_EVENT_SIZE: usize = 80;
const MIN_RING_BYTES: usize = 256 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
static SESSION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct LinuxCaptureRequest {
    pub target: TargetIdentity,
    pub probes: Vec<ResolvedLinuxSelector>,
    pub event_limit: usize,
    pub capacity_limit: bool,
    pub timeout: Duration,
    pub cancelled: Arc<AtomicBool>,
    pub ready: Option<SyncSender<()>>,
}

#[derive(Debug)]
pub enum LinuxCaptureError {
    InvalidRequest(String),
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
    MalformedEvent {
        expected: usize,
        actual: usize,
    },
    UnknownProbeId(u32),
}

impl LinuxCaptureError {
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidRequest(_) => ErrorCode::InvalidEventSelector,
            Self::TargetNamespace { source, .. }
                if source.kind() == io::ErrorKind::PermissionDenied =>
            {
                ErrorCode::PermissionDenied
            }
            Self::TargetNamespace { source, .. } if source.kind() == io::ErrorKind::NotFound => {
                ErrorCode::TargetExited
            }
            Self::Libbpf { source, .. } if source.kind() == ErrorKind::PermissionDenied => {
                ErrorCode::PermissionDenied
            }
            Self::Libbpf {
                operation: "attach tracepoint",
                source,
            } if source.kind() == ErrorKind::NotFound => ErrorCode::InvalidEventSelector,
            Self::TargetNamespace { .. }
            | Self::MissingObjectMember { .. }
            | Self::Libbpf { .. }
            | Self::MalformedEvent { .. }
            | Self::UnknownProbeId(_) => ErrorCode::Internal,
        }
    }

    #[must_use]
    pub fn recoverable(&self) -> bool {
        matches!(
            self.code(),
            ErrorCode::InvalidEventSelector | ErrorCode::PermissionDenied | ErrorCode::TargetExited
        )
    }
}

impl fmt::Display for LinuxCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => formatter.write_str(message),
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
            Self::MalformedEvent { expected, actual } => write!(
                formatter,
                "BPF ring buffer record has size {actual}, expected {expected}"
            ),
            Self::UnknownProbeId(probe_id) => {
                write!(
                    formatter,
                    "BPF record has unknown Linux probe ID {probe_id}"
                )
            }
        }
    }
}

impl Error for LinuxCaptureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TargetNamespace { source, .. } => Some(source),
            Self::Libbpf { source, .. } => Some(source),
            Self::InvalidRequest(_)
            | Self::MissingObjectMember { .. }
            | Self::MalformedEvent { .. }
            | Self::UnknownProbeId(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawEvent {
    timestamp_ns: u64,
    sequence: u64,
    values: [u64; 6],
    pid: u32,
    tid: u32,
    cpu: u32,
    probe_id: u32,
}

impl RawEvent {
    fn decode(bytes: &[u8]) -> Result<Self, LinuxCaptureError> {
        if bytes.len() != RAW_EVENT_SIZE {
            return Err(LinuxCaptureError::MalformedEvent {
                expected: RAW_EVENT_SIZE,
                actual: bytes.len(),
            });
        }
        let mut values = [0_u64; 6];
        for (index, value) in values.iter_mut().enumerate() {
            let start = 16 + index * 8;
            *value = u64::from_ne_bytes(bytes[start..start + 8].try_into().expect("u64 field"));
        }
        Ok(Self {
            timestamp_ns: u64::from_ne_bytes(bytes[0..8].try_into().expect("u64 field")),
            sequence: u64::from_ne_bytes(bytes[8..16].try_into().expect("u64 field")),
            values,
            pid: u32::from_ne_bytes(bytes[64..68].try_into().expect("u32 field")),
            tid: u32::from_ne_bytes(bytes[68..72].try_into().expect("u32 field")),
            cpu: u32::from_ne_bytes(bytes[72..76].try_into().expect("u32 field")),
            probe_id: u32::from_ne_bytes(bytes[76..80].try_into().expect("u32 field")),
        })
    }
}

/// Capture up to two PID-scoped Linux tracepoint or syscall endpoints.
///
/// # Errors
///
/// Returns [`LinuxCaptureError`] when the request is invalid, the BPF object
/// cannot be loaded or attached, or a ring-buffer record is malformed.
pub fn capture(request: &LinuxCaptureRequest) -> Result<HostCaptureResult, LinuxCaptureError> {
    validate_request(request)?;
    let deadline = Instant::now()
        .checked_add(request.timeout)
        .ok_or_else(|| LinuxCaptureError::InvalidRequest("timeout exceeds Instant range".into()))?;
    let object = load_object(request.event_limit)?;
    configure_object(&object, request)?;
    let (raw_events, dropped) = collect_raw_events(&object, request, deadline)?;
    let session_id = format!(
        "xp_linux_{}_{}_{}",
        request.target.pid,
        std::process::id(),
        SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let events = raw_events
        .iter()
        .map(|event| normalize_event(event, request, &session_id))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(HostCaptureResult {
        schema_version: SchemaVersion::current(),
        ok: true,
        session_id,
        target: request.target.clone(),
        probe_id: 0,
        captured: events.len() as u64,
        dropped,
        timed_out: events.len() < request.event_limit,
        record_limit_reached: request.capacity_limit && events.len() == request.event_limit,
        events,
    })
}

fn load_object(event_limit: usize) -> Result<Object, LinuxCaptureError> {
    let ring_bytes = event_limit
        .checked_mul(RAW_EVENT_SIZE)
        .and_then(usize::checked_next_power_of_two)
        .unwrap_or(usize::MAX)
        .max(MIN_RING_BYTES);
    let ring_bytes = u32::try_from(ring_bytes).map_err(|_| {
        LinuxCaptureError::InvalidRequest(
            "max-events requires a Linux ring buffer larger than u32".to_owned(),
        )
    })?;
    let mut builder = ObjectBuilder::default();
    builder
        .name("xprobe_linux")
        .map_err(|source| libbpf_error("name BPF object", source))?;
    let mut open_object = builder
        .open_memory(BPF_OBJECT)
        .map_err(|source| libbpf_error("open BPF object", source))?;
    open_object
        .maps_mut()
        .find(|map| map.name() == OsStr::new("linux_events"))
        .ok_or_else(|| missing("map", "linux_events"))?
        .set_max_entries(ring_bytes)
        .map_err(|source| libbpf_error("size Linux ring buffer", source))?;
    open_object
        .load()
        .map_err(|source| libbpf_error("load BPF object", source))
}

fn configure_object(
    object: &Object,
    request: &LinuxCaptureRequest,
) -> Result<(), LinuxCaptureError> {
    let namespace_path = PathBuf::from(format!("/proc/{}/ns/pid", request.target.pid));
    let namespace =
        fs::metadata(&namespace_path).map_err(|source| LinuxCaptureError::TargetNamespace {
            path: namespace_path,
            source,
        })?;
    let key = 0_u32.to_ne_bytes();
    let mut config = [0_u8; 56];
    config[0..8].copy_from_slice(&namespace.dev().to_ne_bytes());
    config[8..16].copy_from_slice(&namespace.ino().to_ne_bytes());
    config[16..20].copy_from_slice(&request.target.pid.to_ne_bytes());
    for slot in 0..4 {
        let start = 24 + slot * 8;
        config[start..start + 8].copy_from_slice(&(-1_i64).to_ne_bytes());
    }
    for (index, probe) in request.probes.iter().enumerate() {
        let Some(number) = probe.syscall_number else {
            continue;
        };
        let base = match probe.event_type {
            EventType::SyscallEntry => 24,
            EventType::SyscallExit => 40,
            _ => continue,
        };
        let start = base + index * 8;
        config[start..start + 8].copy_from_slice(&i64::from(number).to_ne_bytes());
    }
    object
        .maps()
        .find(|map| map.name() == OsStr::new("linux_config"))
        .ok_or_else(|| missing("map", "linux_config"))?
        .update(&key, &config, MapFlags::ANY)
        .map_err(|source| libbpf_error("configure Linux BPF map", source))
}

fn collect_raw_events(
    object: &Object,
    request: &LinuxCaptureRequest,
    deadline: Instant,
) -> Result<(Vec<RawEvent>, u64), LinuxCaptureError> {
    let raw_events = Rc::new(RefCell::new(Vec::with_capacity(request.event_limit)));
    let callback_events = Rc::clone(&raw_events);
    let callback_error = Rc::new(RefCell::new(None));
    let callback_error_slot = Rc::clone(&callback_error);
    let event_limit = request.event_limit;
    let events_map = object
        .maps()
        .find(|map| map.name() == OsStr::new("linux_events"))
        .ok_or_else(|| missing("map", "linux_events"))?;
    let mut ring_builder = RingBufferBuilder::new();
    ring_builder
        .add(&events_map, move |bytes| {
            if callback_events.borrow().len() >= event_limit {
                return 0;
            }
            match RawEvent::decode(bytes) {
                Ok(event) => callback_events.borrow_mut().push(event),
                Err(error) => {
                    *callback_error_slot.borrow_mut() = Some(error);
                    return -1;
                }
            }
            0
        })
        .map_err(|source| libbpf_error("register Linux ring buffer", source))?;
    let ring_buffer = ring_builder
        .build()
        .map_err(|source| libbpf_error("build Linux ring buffer", source))?;
    let _links = attach_probes(object, &request.probes)?;
    arm_object(object)?;
    if let Some(ready) = &request.ready {
        ready.send(()).map_err(|_| {
            LinuxCaptureError::InvalidRequest(
                "Linux collector readiness receiver closed".to_owned(),
            )
        })?;
    }

    while raw_events.borrow().len() < request.event_limit
        && !request.cancelled.load(Ordering::Acquire)
    {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let wait = deadline.saturating_duration_since(now).min(POLL_INTERVAL);
        if let Err(source) = ring_buffer.poll(wait) {
            if let Some(error) = callback_error.borrow_mut().take() {
                return Err(error);
            }
            return Err(libbpf_error("poll Linux ring buffer", source));
        }
    }

    let key = 0_u32.to_ne_bytes();
    let dropped = read_counter(object, "linux_dropped", &key)?;
    let collected = raw_events.borrow().clone();
    Ok((collected, dropped))
}

fn arm_object(object: &Object) -> Result<(), LinuxCaptureError> {
    let key = 0_u32.to_ne_bytes();
    let map = object
        .maps()
        .find(|map| map.name() == OsStr::new("linux_config"))
        .ok_or_else(|| missing("map", "linux_config"))?;
    let mut config = map
        .lookup(&key, MapFlags::ANY)
        .map_err(|source| libbpf_error("read Linux BPF config", source))?
        .ok_or_else(|| missing("map value", "linux_config"))?;
    if config.len() != 56 {
        return Err(LinuxCaptureError::MalformedEvent {
            expected: 56,
            actual: config.len(),
        });
    }
    config[20..24].copy_from_slice(&1_u32.to_ne_bytes());
    map.update(&key, &config, MapFlags::ANY)
        .map_err(|source| libbpf_error("arm Linux BPF collection", source))
}

fn attach_probes(
    object: &Object,
    probes: &[ResolvedLinuxSelector],
) -> Result<Vec<Link>, LinuxCaptureError> {
    let mut links = Vec::with_capacity(probes.len());
    for (event_type, program_name, tracepoint_name) in [
        (
            EventType::SyscallEntry,
            "xprobe_handle_syscall_entry",
            "sys_enter",
        ),
        (
            EventType::SyscallExit,
            "xprobe_handle_syscall_exit",
            "sys_exit",
        ),
    ] {
        if probes.iter().any(|probe| probe.event_type == event_type) {
            let program = object
                .progs_mut()
                .find(|program| program.name() == OsStr::new(program_name))
                .ok_or_else(|| missing("program", program_name))?;
            links.push(
                program
                    .attach_raw_tracepoint(tracepoint_name)
                    .map_err(|source| libbpf_error("attach tracepoint", source))?,
            );
        }
    }
    for (index, probe) in probes.iter().enumerate() {
        if probe.event_type != EventType::Tracepoint {
            continue;
        }
        let raw = probe.category == "raw_syscalls";
        let stem = if raw {
            "xprobe_handle_raw_tracepoint"
        } else {
            "xprobe_handle_tracepoint"
        };
        let program_name = format!("{stem}_{}", index + 1);
        let program = object
            .progs_mut()
            .find(|program| program.name() == OsStr::new(&program_name))
            .ok_or_else(|| missing("program", &program_name))?;
        let link = if raw {
            program
                .attach_raw_tracepoint(&probe.name)
                .map_err(|source| libbpf_error("attach tracepoint", source))?
        } else {
            program
                .attach_tracepoint(
                    TracepointCategory::Custom(probe.category.clone()),
                    &probe.name,
                )
                .map_err(|source| libbpf_error("attach tracepoint", source))?
        };
        links.push(link);
    }
    Ok(links)
}

fn validate_request(request: &LinuxCaptureRequest) -> Result<(), LinuxCaptureError> {
    if request.probes.is_empty() || request.probes.len() > 2 {
        return Err(LinuxCaptureError::InvalidRequest(
            "Linux collector requires one or two endpoints".to_owned(),
        ));
    }
    if request.event_limit == 0 {
        return Err(LinuxCaptureError::InvalidRequest(
            "max-events must be greater than zero".to_owned(),
        ));
    }
    if request.timeout.is_zero() {
        return Err(LinuxCaptureError::InvalidRequest(
            "timeout must be greater than zero".to_owned(),
        ));
    }
    for probe in &request.probes {
        let valid = match probe.probe_kind {
            HostProbeKind::Syscall => {
                matches!(
                    probe.event_type,
                    EventType::SyscallEntry | EventType::SyscallExit
                ) && probe.category == "syscalls"
                    && probe.syscall_number.is_some()
            }
            HostProbeKind::Tracepoint => {
                probe.event_type == EventType::Tracepoint && probe.syscall_number.is_none()
            }
            _ => false,
        };
        if !valid || probe.category.is_empty() || probe.name.is_empty() {
            return Err(LinuxCaptureError::InvalidRequest(
                "Linux endpoint metadata is inconsistent".to_owned(),
            ));
        }
    }
    Ok(())
}

fn normalize_event(
    raw: &RawEvent,
    request: &LinuxCaptureRequest,
    session_id: &str,
) -> Result<Event, LinuxCaptureError> {
    let probe_index =
        usize::try_from(raw.probe_id.saturating_sub(1)).expect("u32 probe ID fits usize");
    let probe = request
        .probes
        .get(probe_index)
        .ok_or(LinuxCaptureError::UnknownProbeId(raw.probe_id))?;
    let arguments = if probe.event_type == EventType::SyscallEntry {
        raw.values
            .iter()
            .enumerate()
            .map(|(index, value)| ArgumentValue {
                index: u16::try_from(index).expect("six arguments fit u16"),
                abi_type: "u64".to_owned(),
                value: Some(Value::from(*value)),
                read_error: None,
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "tracepoint_category".to_owned(),
        Value::String(probe.category.clone()),
    );
    Ok(Event {
        schema_version: SchemaVersion::current(),
        session_id: session_id.to_owned(),
        event_id: format!("evt_{}", raw.sequence),
        sequence: raw.sequence,
        source: EventSource::Ebpf,
        event_type: probe.event_type.clone(),
        pid: raw.pid,
        tid: raw.tid,
        cpu: Some(raw.cpu),
        timestamp_raw: raw.timestamp_ns,
        timestamp_ns: raw.timestamp_ns,
        clock_domain: ClockDomain::HostMonotonic,
        timestamp_error_ns: None,
        process_start_time: Some(request.target.process_start_time),
        host: Some(HostEvent {
            probe_kind: probe.probe_kind.clone(),
            binary_path: None,
            build_id: None,
            symbol: Some(probe.name.clone()),
            offset: None,
            return_value: (probe.event_type == EventType::SyscallExit)
                .then_some(i64::from_ne_bytes(raw.values[0].to_ne_bytes())),
            arguments,
        }),
        cuda: None,
        attributes,
    })
}

fn read_counter(object: &Object, name: &'static str, key: &[u8]) -> Result<u64, LinuxCaptureError> {
    let value = object
        .maps()
        .find(|map| map.name() == OsStr::new(name))
        .ok_or_else(|| missing("map", name))?
        .lookup(key, MapFlags::ANY)
        .map_err(|source| libbpf_error("read Linux BPF map", source))?
        .ok_or_else(|| missing("map value", name))?;
    let bytes: [u8; 8] =
        value
            .try_into()
            .map_err(|value: Vec<u8>| LinuxCaptureError::MalformedEvent {
                expected: 8,
                actual: value.len(),
            })?;
    Ok(u64::from_ne_bytes(bytes))
}

fn missing(kind: &'static str, name: &str) -> LinuxCaptureError {
    LinuxCaptureError::MissingObjectMember {
        kind,
        name: name.to_owned(),
    }
}

fn libbpf_error(operation: &'static str, source: libbpf_rs::Error) -> LinuxCaptureError {
    LinuxCaptureError::Libbpf { operation, source }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use xprobe_protocol::{EventType, HostProbeKind, ResolvedLinuxSelector, TargetIdentity};

    use super::{
        LinuxCaptureError, LinuxCaptureRequest, RAW_EVENT_SIZE, RawEvent, normalize_event,
        validate_request,
    };

    fn syscall(event_type: EventType) -> ResolvedLinuxSelector {
        ResolvedLinuxSelector {
            event_type,
            probe_kind: HostProbeKind::Syscall,
            category: "syscalls".to_owned(),
            name: "mmap".to_owned(),
            syscall_number: Some(9),
        }
    }

    fn request(probes: Vec<ResolvedLinuxSelector>) -> LinuxCaptureRequest {
        LinuxCaptureRequest {
            target: TargetIdentity {
                pid: 1234,
                process_start_time: 99,
            },
            probes,
            event_limit: 4,
            capacity_limit: false,
            timeout: Duration::from_secs(1),
            cancelled: Arc::new(AtomicBool::new(false)),
            ready: None,
        }
    }

    #[test]
    fn decodes_native_ring_buffer_layout() {
        let mut bytes = [0_u8; RAW_EVENT_SIZE];
        bytes[0..8].copy_from_slice(&1000_u64.to_ne_bytes());
        bytes[8..16].copy_from_slice(&9_u64.to_ne_bytes());
        bytes[16..24].copy_from_slice(&0x1234_u64.to_ne_bytes());
        bytes[64..68].copy_from_slice(&1234_u32.to_ne_bytes());
        bytes[68..72].copy_from_slice(&1235_u32.to_ne_bytes());
        bytes[72..76].copy_from_slice(&3_u32.to_ne_bytes());
        bytes[76..80].copy_from_slice(&1_u32.to_ne_bytes());

        let raw = RawEvent::decode(&bytes).unwrap();
        assert_eq!(raw.timestamp_ns, 1000);
        assert_eq!(raw.sequence, 9);
        assert_eq!(raw.values[0], 0x1234);
        assert_eq!(raw.pid, 1234);
        assert_eq!(raw.tid, 1235);
        assert_eq!(raw.cpu, 3);
        assert_eq!(raw.probe_id, 1);
    }

    #[test]
    fn normalizes_syscall_scalars_without_pointer_reads() {
        let request = request(vec![
            syscall(EventType::SyscallEntry),
            syscall(EventType::SyscallExit),
        ]);
        let entry = RawEvent {
            timestamp_ns: 100,
            sequence: 1,
            values: [0x1000, 4096, 3, 0x22, u64::MAX, 0],
            pid: 1234,
            tid: 1235,
            cpu: 2,
            probe_id: 1,
        };
        let exit = RawEvent {
            timestamp_ns: 150,
            sequence: 2,
            values: [u64::MAX, 0, 0, 0, 0, 0],
            probe_id: 2,
            ..entry
        };

        let entry = normalize_event(&entry, &request, "session").unwrap();
        let exit = normalize_event(&exit, &request, "session").unwrap();
        assert_eq!(entry.event_type, EventType::SyscallEntry);
        assert_eq!(
            entry.host.unwrap().arguments[0].value,
            Some(serde_json::json!(4096_u64))
        );
        assert_eq!(exit.event_type, EventType::SyscallExit);
        assert_eq!(exit.host.unwrap().return_value, Some(-1));
    }

    #[test]
    fn rejects_inconsistent_or_unbounded_requests() {
        let mut invalid = request(vec![ResolvedLinuxSelector {
            event_type: EventType::Tracepoint,
            probe_kind: HostProbeKind::Syscall,
            category: "syscalls".to_owned(),
            name: "mmap".to_owned(),
            syscall_number: Some(9),
        }]);
        assert!(matches!(
            validate_request(&invalid),
            Err(LinuxCaptureError::InvalidRequest(_))
        ));
        invalid.probes = vec![syscall(EventType::SyscallEntry)];
        invalid.event_limit = 0;
        assert!(validate_request(&invalid).is_err());
    }
}
