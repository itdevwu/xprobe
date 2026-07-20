use std::{
    cell::RefCell,
    collections::BTreeMap,
    error::Error,
    ffi::OsStr,
    fmt, fs, io,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use libbpf_rs::{
    ErrorKind, MapCore, MapFlags, Object, ObjectBuilder, RingBufferBuilder, UprobeOpts,
};
use xprobe_protocol::{
    ClockDomain, ErrorCode, Event, EventSource, EventType, HostCaptureResult, HostEvent,
    HostProbeKind, SchemaVersion, TargetIdentity,
};

const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/xprobe.bpf.o"));
const RAW_EVENT_SIZE: usize = 32;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
static SESSION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct UprobeRequest {
    pub target: TargetIdentity,
    pub binary: PathBuf,
    pub symbol: String,
    pub probe_kind: HostProbeKind,
    pub probe_id: u32,
    pub samples: usize,
    pub timeout: Duration,
}

#[derive(Debug)]
pub enum UprobeError {
    InvalidRequest(String),
    TargetNamespace {
        path: PathBuf,
        source: io::Error,
    },
    MissingObjectMember {
        kind: &'static str,
        name: &'static str,
    },
    Libbpf {
        operation: &'static str,
        source: libbpf_rs::Error,
    },
    MalformedEvent {
        expected: usize,
        actual: usize,
    },
}

impl UprobeError {
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
            Self::Libbpf { operation, source }
                if matches!(*operation, "attach uprobe" | "attach uretprobe")
                    && source.kind() == ErrorKind::NotFound =>
            {
                ErrorCode::SymbolNotFound
            }
            Self::TargetNamespace { .. }
            | Self::MissingObjectMember { .. }
            | Self::Libbpf { .. }
            | Self::MalformedEvent { .. } => ErrorCode::Internal,
        }
    }

    #[must_use]
    pub fn recoverable(&self) -> bool {
        matches!(
            self.code(),
            ErrorCode::PermissionDenied | ErrorCode::SymbolNotFound | ErrorCode::TargetExited
        )
    }
}

impl fmt::Display for UprobeError {
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
        }
    }
}

impl Error for UprobeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TargetNamespace { source, .. } => Some(source),
            Self::Libbpf { source, .. } => Some(source),
            Self::InvalidRequest(_)
            | Self::MissingObjectMember { .. }
            | Self::MalformedEvent { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawEvent {
    timestamp_ns: u64,
    sequence: u64,
    pid: u32,
    tid: u32,
    cpu: u32,
    probe_id: u32,
}

impl RawEvent {
    fn decode(bytes: &[u8]) -> Result<Self, UprobeError> {
        if bytes.len() != RAW_EVENT_SIZE {
            return Err(UprobeError::MalformedEvent {
                expected: RAW_EVENT_SIZE,
                actual: bytes.len(),
            });
        }

        Ok(Self {
            timestamp_ns: u64::from_ne_bytes(bytes[0..8].try_into().expect("u64 field")),
            sequence: u64::from_ne_bytes(bytes[8..16].try_into().expect("u64 field")),
            pid: u32::from_ne_bytes(bytes[16..20].try_into().expect("u32 field")),
            tid: u32::from_ne_bytes(bytes[20..24].try_into().expect("u32 field")),
            cpu: u32::from_ne_bytes(bytes[24..28].try_into().expect("u32 field")),
            probe_id: u32::from_ne_bytes(bytes[28..32].try_into().expect("u32 field")),
        })
    }
}

/// Capture function-entry events from one userspace symbol.
///
/// # Errors
///
/// Returns [`UprobeError`] when the request is invalid, the BPF object cannot
/// be loaded or attached, a map operation fails, or the kernel emits a record
/// that does not match the compiled wire layout.
pub fn capture(request: &UprobeRequest) -> Result<HostCaptureResult, UprobeError> {
    validate_request(request)?;
    let deadline = Instant::now()
        .checked_add(request.timeout)
        .ok_or_else(|| UprobeError::InvalidRequest("timeout exceeds Instant range".to_owned()))?;
    let pid = i32::try_from(request.target.pid)
        .map_err(|_| UprobeError::InvalidRequest("PID exceeds i32 range".to_owned()))?;
    let binary_path = request
        .binary
        .to_str()
        .ok_or_else(|| UprobeError::InvalidRequest("binary path is not valid UTF-8".to_owned()))?
        .to_owned();
    let object = load_object()?;
    configure_object(&object, request)?;
    let (raw_events, dropped) = collect_raw_events(&object, request, pid, deadline)?;
    let session_id = format!(
        "xp_uprobe_{}_{}_{}",
        request.target.pid,
        std::process::id(),
        SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let events = raw_events
        .iter()
        .map(|event| normalize_event(event, request, &session_id, &binary_path))
        .collect::<Vec<_>>();

    Ok(HostCaptureResult {
        schema_version: SchemaVersion::current(),
        ok: true,
        session_id,
        target: request.target.clone(),
        probe_id: request.probe_id,
        captured: events.len() as u64,
        dropped,
        timed_out: events.len() < request.samples,
        events,
    })
}

fn load_object() -> Result<Object, UprobeError> {
    let mut builder = ObjectBuilder::default();
    builder
        .name("xprobe_uprobe")
        .map_err(|source| libbpf_error("name BPF object", source))?;
    builder
        .open_memory(BPF_OBJECT)
        .map_err(|source| libbpf_error("open BPF object", source))?
        .load()
        .map_err(|source| libbpf_error("load BPF object", source))
}

fn configure_object(object: &Object, request: &UprobeRequest) -> Result<(), UprobeError> {
    let namespace_path = PathBuf::from(format!("/proc/{}/ns/pid", request.target.pid));
    let namespace =
        fs::metadata(&namespace_path).map_err(|source| UprobeError::TargetNamespace {
            path: namespace_path,
            source,
        })?;
    let key = 0_u32.to_ne_bytes();
    let mut config = [0_u8; 24];
    config[0..8].copy_from_slice(&namespace.dev().to_ne_bytes());
    config[8..16].copy_from_slice(&namespace.ino().to_ne_bytes());
    config[16..20].copy_from_slice(&request.target.pid.to_ne_bytes());
    config[20..24].copy_from_slice(&request.probe_id.to_ne_bytes());
    object
        .maps()
        .find(|map| map.name() == OsStr::new("config"))
        .ok_or(UprobeError::MissingObjectMember {
            kind: "map",
            name: "config",
        })?
        .update(&key, &config, MapFlags::ANY)
        .map_err(|source| libbpf_error("configure BPF map", source))
}

fn collect_raw_events(
    object: &Object,
    request: &UprobeRequest,
    pid: i32,
    deadline: Instant,
) -> Result<(Vec<RawEvent>, u64), UprobeError> {
    let raw_events = Rc::new(RefCell::new(Vec::with_capacity(request.samples)));
    let callback_events = Rc::clone(&raw_events);
    let callback_error = Rc::new(RefCell::new(None));
    let callback_error_slot = Rc::clone(&callback_error);
    let sample_limit = request.samples;
    let events_map = object
        .maps()
        .find(|map| map.name() == OsStr::new("events"))
        .ok_or(UprobeError::MissingObjectMember {
            kind: "map",
            name: "events",
        })?;
    let mut ring_builder = RingBufferBuilder::new();
    ring_builder
        .add(&events_map, move |bytes| {
            if callback_events.borrow().len() >= sample_limit {
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
        .map_err(|source| libbpf_error("register ring buffer", source))?;
    let ring_buffer = ring_builder
        .build()
        .map_err(|source| libbpf_error("build ring buffer", source))?;

    let program = object
        .progs_mut()
        .find(|program| program.name() == OsStr::new("xprobe_handle_uprobe"))
        .ok_or(UprobeError::MissingObjectMember {
            kind: "program",
            name: "xprobe_handle_uprobe",
        })?;
    let operation = if request.probe_kind == HostProbeKind::Uretprobe {
        "attach uretprobe"
    } else {
        "attach uprobe"
    };
    let _link = program
        .attach_uprobe_with_opts(
            pid,
            &request.binary,
            0,
            UprobeOpts {
                func_name: Some(request.symbol.clone()),
                retprobe: request.probe_kind == HostProbeKind::Uretprobe,
                ..UprobeOpts::default()
            },
        )
        .map_err(|source| libbpf_error(operation, source))?;

    while raw_events.borrow().len() < request.samples {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let wait = deadline.saturating_duration_since(now).min(POLL_INTERVAL);
        if let Err(source) = ring_buffer.poll(wait) {
            if let Some(error) = callback_error.borrow_mut().take() {
                return Err(error);
            }
            return Err(libbpf_error("poll ring buffer", source));
        }
    }

    let key = 0_u32.to_ne_bytes();
    let dropped = read_counter(object, "dropped", &key)?;
    let collected = raw_events.borrow().clone();
    Ok((collected, dropped))
}

fn validate_request(request: &UprobeRequest) -> Result<(), UprobeError> {
    if request.samples == 0 {
        return Err(UprobeError::InvalidRequest(
            "samples must be greater than zero".to_owned(),
        ));
    }
    if request.timeout.is_zero() {
        return Err(UprobeError::InvalidRequest(
            "timeout must be greater than zero".to_owned(),
        ));
    }
    if request.symbol.is_empty() {
        return Err(UprobeError::InvalidRequest(
            "symbol must not be empty".to_owned(),
        ));
    }
    if !matches!(
        request.probe_kind,
        HostProbeKind::Uprobe | HostProbeKind::Uretprobe
    ) {
        return Err(UprobeError::InvalidRequest(
            "userspace collector requires uprobe or uretprobe kind".to_owned(),
        ));
    }
    Ok(())
}

fn read_counter(
    object: &libbpf_rs::Object,
    name: &'static str,
    key: &[u8],
) -> Result<u64, UprobeError> {
    let value = object
        .maps()
        .find(|map| map.name() == OsStr::new(name))
        .ok_or(UprobeError::MissingObjectMember { kind: "map", name })?
        .lookup(key, MapFlags::ANY)
        .map_err(|source| libbpf_error("read BPF map", source))?
        .ok_or(UprobeError::MissingObjectMember {
            kind: "map value",
            name,
        })?;
    let bytes: [u8; 8] =
        value
            .try_into()
            .map_err(|value: Vec<u8>| UprobeError::MalformedEvent {
                expected: 8,
                actual: value.len(),
            })?;
    Ok(u64::from_ne_bytes(bytes))
}

fn normalize_event(
    raw: &RawEvent,
    request: &UprobeRequest,
    session_id: &str,
    binary_path: &str,
) -> Event {
    Event {
        schema_version: SchemaVersion::current(),
        session_id: session_id.to_owned(),
        event_id: format!("evt_{}", raw.sequence),
        sequence: raw.sequence,
        source: EventSource::Ebpf,
        event_type: if request.probe_kind == HostProbeKind::Uretprobe {
            EventType::HostFunctionExit
        } else {
            EventType::HostFunctionEntry
        },
        pid: raw.pid,
        tid: raw.tid,
        cpu: Some(raw.cpu),
        timestamp_raw: raw.timestamp_ns,
        timestamp_ns: raw.timestamp_ns,
        clock_domain: ClockDomain::HostMonotonic,
        timestamp_error_ns: None,
        process_start_time: Some(request.target.process_start_time),
        host: Some(HostEvent {
            probe_kind: request.probe_kind.clone(),
            binary_path: Some(binary_path.to_owned()),
            build_id: None,
            symbol: Some(request.symbol.clone()),
            offset: None,
            return_value: None,
            arguments: Vec::new(),
        }),
        cuda: None,
        attributes: BTreeMap::new(),
    }
}

fn libbpf_error(operation: &'static str, source: libbpf_rs::Error) -> UprobeError {
    UprobeError::Libbpf { operation, source }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use xprobe_protocol::{EventType, HostProbeKind, TargetIdentity};

    use super::{
        RAW_EVENT_SIZE, RawEvent, UprobeError, UprobeRequest, normalize_event, validate_request,
    };

    #[test]
    fn decodes_native_ring_buffer_layout() {
        let mut bytes = [0_u8; RAW_EVENT_SIZE];
        bytes[0..8].copy_from_slice(&1000_u64.to_ne_bytes());
        bytes[8..16].copy_from_slice(&9_u64.to_ne_bytes());
        bytes[16..20].copy_from_slice(&1234_u32.to_ne_bytes());
        bytes[20..24].copy_from_slice(&1235_u32.to_ne_bytes());
        bytes[24..28].copy_from_slice(&3_u32.to_ne_bytes());
        bytes[28..32].copy_from_slice(&7_u32.to_ne_bytes());

        assert_eq!(
            RawEvent::decode(&bytes).expect("record must decode"),
            RawEvent {
                timestamp_ns: 1000,
                sequence: 9,
                pid: 1234,
                tid: 1235,
                cpu: 3,
                probe_id: 7,
            }
        );
    }

    #[test]
    fn rejects_wrong_ring_buffer_layout() {
        let error = RawEvent::decode(&[0; RAW_EVENT_SIZE - 1]).expect_err("record must fail");
        let UprobeError::MalformedEvent { expected, actual } = error else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(expected, RAW_EVENT_SIZE);
        assert_eq!(actual, RAW_EVENT_SIZE - 1);
    }

    #[test]
    fn normalizes_return_probe_events() {
        let request = UprobeRequest {
            target: TargetIdentity {
                pid: 1234,
                process_start_time: 99,
            },
            binary: PathBuf::from("/srv/server"),
            symbol: "handle_request".to_owned(),
            probe_kind: HostProbeKind::Uretprobe,
            probe_id: 8,
            samples: 1,
            timeout: Duration::from_secs(1),
        };
        let raw = RawEvent {
            timestamp_ns: 1000,
            sequence: 1,
            pid: 1234,
            tid: 1235,
            cpu: 3,
            probe_id: 8,
        };
        let event = normalize_event(&raw, &request, "session", "/srv/server");
        assert_eq!(event.event_type, EventType::HostFunctionExit);
        assert_eq!(
            event.host.expect("host payload").probe_kind,
            HostProbeKind::Uretprobe
        );
    }

    #[test]
    fn rejects_non_userspace_probe_kinds() {
        let request = UprobeRequest {
            target: TargetIdentity {
                pid: 1234,
                process_start_time: 99,
            },
            binary: PathBuf::from("/srv/server"),
            symbol: "handle_request".to_owned(),
            probe_kind: HostProbeKind::Kprobe,
            probe_id: 8,
            samples: 1,
            timeout: Duration::from_secs(1),
        };
        assert!(matches!(
            validate_request(&request),
            Err(UprobeError::InvalidRequest(_))
        ));
    }
}
