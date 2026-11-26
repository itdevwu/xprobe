//! Cross-domain event correlation and latency statistics.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, ptr,
    time::Duration,
};

use regex::Regex;
use xprobe_protocol::{
    ActivityBoundary, CUDA_RECORD_NAME_MAX_BYTES, CaptureCompleteness, CaptureCoverage,
    ClockDomain, ClockQuality, CollectionSummary, CorrelationConfidence, CorrelationSummary,
    CoverageSource, ErrorCode, Event, EventSource, EventType, HostProbeKind, LatencyStatistics,
    MatchPolicy, MatchedEventPair, Measurement, MeasurementResult, MemcpyKind, NvtxRangeKind,
    QualityVerdict, ResultQuality, SampleSummary, SchemaVersion3, SessionStatus, Warning,
    activity_boundary,
};

mod quality;
pub mod spans;

pub use quality::{apply_coverage, assess as assess_quality, finalize};

#[derive(Debug, Clone)]
pub struct MeasureOptions {
    pub session_id: String,
    pub name: Option<String>,
    pub start_selector: String,
    pub end_selector: String,
    pub match_policy: MatchPolicy,
    pub samples: Option<usize>,
    pub duration: Option<Duration>,
    pub max_events: usize,
    pub dropped_events: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeasureError {
    InvalidSelector(String),
    InvalidPolicy(String),
    InvalidLimit(String),
    EventLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    EventsDropped {
        count: u64,
    },
    ClockDomainsDiffer {
        start: ClockDomain,
        end: ClockDomain,
    },
    NoMatchedSamples,
}

impl MeasureError {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidSelector(_) => ErrorCode::InvalidEventSelector,
            Self::InvalidPolicy(_) => ErrorCode::InvalidCorrelationPolicy,
            Self::InvalidLimit(_) => ErrorCode::SessionLimitExceeded,
            Self::EventLimitExceeded { .. } => ErrorCode::EventRateTooHigh,
            Self::EventsDropped { .. } => ErrorCode::EventsDropped,
            Self::ClockDomainsDiffer { .. } => ErrorCode::ClockAlignmentFailed,
            Self::NoMatchedSamples => ErrorCode::NoMatchedSamples,
        }
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        true
    }
}

impl fmt::Display for MeasureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSelector(reason) => write!(formatter, "invalid event selector: {reason}"),
            Self::InvalidPolicy(reason) => {
                write!(formatter, "invalid correlation policy: {reason}")
            }
            Self::InvalidLimit(reason) => write!(formatter, "invalid measurement limit: {reason}"),
            Self::EventLimitExceeded { actual, maximum } => write!(
                formatter,
                "capture contains {actual} events, exceeding the maximum of {maximum}"
            ),
            Self::EventsDropped { count } => write!(
                formatter,
                "capture dropped {count} events before correlation"
            ),
            Self::ClockDomainsDiffer { start, end } => write!(
                formatter,
                "cannot subtract unaligned {start:?} and {end:?} timestamps"
            ),
            Self::NoMatchedSamples => formatter.write_str("no event pairs matched the selectors"),
        }
    }
}

impl Error for MeasureError {}

#[derive(Debug)]
enum Selector {
    Host {
        event_type: EventType,
        probe_kind: HostProbeKind,
        binary_path: String,
        target: HostTarget,
    },
    Syscall {
        event_type: EventType,
        name: String,
    },
    Tracepoint {
        category: String,
        name: String,
    },
    PythonGc {
        event_type: EventType,
        marker: &'static str,
    },
    Api {
        event_type: EventType,
        domain: String,
        name: String,
    },
    LaunchApi {
        event_type: EventType,
    },
    Kernel {
        event_type: EventType,
        name: Option<Regex>,
    },
    Memcpy {
        event_type: EventType,
        kind: Option<MemcpyKind>,
    },
    Memset {
        event_type: EventType,
    },
    Nvtx {
        event_type: EventType,
        name: Regex,
        pattern: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum HostTarget {
    Symbol(String),
    Offset(u64),
}

impl Selector {
    fn parse(text: &str) -> Result<Self, MeasureError> {
        if text.starts_with("uprobe:") {
            return Self::parse_host(text);
        }
        if text.starts_with("syscall:") {
            return Self::parse_syscall(text);
        }
        if text.starts_with("tracepoint:") {
            return Self::parse_tracepoint(text);
        }
        if text.starts_with("python:") {
            return Self::parse_python(text);
        }
        let fields: Vec<&str> = text.splitn(3, ':').collect();
        if fields.first() != Some(&"cuda") || fields.len() < 2 {
            return Err(MeasureError::InvalidSelector(
                "completed captures require a uprobe:, syscall:, tracepoint:, python:, or cuda: selector"
                    .to_owned(),
            ));
        }
        match fields[1] {
            "runtime_api" | "driver_api" => Self::parse_api(text),
            "launch_api" => Self::parse_launch(&fields),
            "kernel_start" | "kernel_end" => Self::parse_kernel(&fields),
            "memcpy_start" | "memcpy_end" => Self::parse_memcpy(&fields),
            "memset_start" | "memset_end" => Self::parse_memset(text, &fields),
            "nvtx_range_start" | "nvtx_range_end" => Self::parse_nvtx(&fields),
            event => Err(MeasureError::InvalidSelector(format!(
                "event {event:?} is not present in completed CUPTI captures"
            ))),
        }
    }

    fn parse_host(text: &str) -> Result<Self, MeasureError> {
        let rest = text
            .strip_prefix("uprobe:")
            .expect("host selector prefix was checked");
        let (binary_and_target, boundary) = rest.rsplit_once(':').ok_or_else(|| {
            MeasureError::InvalidSelector(
                "uprobe selector requires an entry or return boundary".to_owned(),
            )
        })?;
        let (event_type, probe_kind) = match boundary {
            "entry" => (EventType::HostFunctionEntry, HostProbeKind::Uprobe),
            "return" => (EventType::HostFunctionExit, HostProbeKind::Uretprobe),
            _ => {
                return Err(MeasureError::InvalidSelector(
                    "uprobe boundary must be entry or return".to_owned(),
                ));
            }
        };
        let (binary_path, target) = if let Some(parts) = binary_and_target.split_once(":symbol=") {
            parts
        } else {
            binary_and_target.rsplit_once(':').ok_or_else(|| {
                MeasureError::InvalidSelector(
                    "uprobe selector requires a binary path and symbol or offset".to_owned(),
                )
            })?
        };
        if binary_path.is_empty() || target.is_empty() {
            return Err(MeasureError::InvalidSelector(
                "uprobe binary path and target must not be empty".to_owned(),
            ));
        }
        let target = if let Some(hex) = target.strip_prefix("+0x") {
            HostTarget::Offset(u64::from_str_radix(hex, 16).map_err(|_| {
                MeasureError::InvalidSelector(
                    "uprobe offset must be hexadecimal after +0x".to_owned(),
                )
            })?)
        } else if target.starts_with('+') {
            return Err(MeasureError::InvalidSelector(
                "uprobe offset must use +0x hexadecimal syntax".to_owned(),
            ));
        } else {
            HostTarget::Symbol(target.to_owned())
        };
        Ok(Self::Host {
            event_type,
            probe_kind,
            binary_path: binary_path.to_owned(),
            target,
        })
    }

    fn parse_api(text: &str) -> Result<Self, MeasureError> {
        let fields: Vec<&str> = text.split(':').collect();
        if fields.len() != 4 || fields[2].is_empty() {
            return Err(MeasureError::InvalidSelector(
                "API selector must be cuda:<runtime_api|driver_api>:<name>:<entry|exit>".to_owned(),
            ));
        }
        let event_type = match fields[3] {
            "entry" => EventType::CudaApiEntry,
            "exit" => EventType::CudaApiExit,
            _ => {
                return Err(MeasureError::InvalidSelector(
                    "CUDA API boundary must be entry or exit".to_owned(),
                ));
            }
        };
        Ok(Self::Api {
            event_type,
            domain: fields[1].to_owned(),
            name: fields[2].to_owned(),
        })
    }

    fn parse_launch(fields: &[&str]) -> Result<Self, MeasureError> {
        let event_type = match fields {
            ["cuda", "launch_api", "entry"] => EventType::CudaApiEntry,
            ["cuda", "launch_api", "exit"] => EventType::CudaApiExit,
            _ => {
                return Err(MeasureError::InvalidSelector(
                    "CUDA launch selector must be cuda:launch_api:<entry|exit>".to_owned(),
                ));
            }
        };
        Ok(Self::LaunchApi { event_type })
    }

    fn parse_syscall(text: &str) -> Result<Self, MeasureError> {
        let fields = text.split(':').collect::<Vec<_>>();
        let ["syscall", name, boundary] = fields.as_slice() else {
            return Err(MeasureError::InvalidSelector(
                "syscall selector must be syscall:<name>:<entry|exit>".to_owned(),
            ));
        };
        if !valid_linux_component(name) {
            return Err(MeasureError::InvalidSelector(
                "syscall name must contain only letters, digits, and underscores".to_owned(),
            ));
        }
        let event_type = match *boundary {
            "entry" => EventType::SyscallEntry,
            "exit" => EventType::SyscallExit,
            _ => {
                return Err(MeasureError::InvalidSelector(
                    "syscall boundary must be entry or exit".to_owned(),
                ));
            }
        };
        Ok(Self::Syscall {
            event_type,
            name: (*name).to_owned(),
        })
    }

    fn parse_tracepoint(text: &str) -> Result<Self, MeasureError> {
        let fields = text.split(':').collect::<Vec<_>>();
        let ["tracepoint", category, name] = fields.as_slice() else {
            return Err(MeasureError::InvalidSelector(
                "tracepoint selector must be tracepoint:<category>:<name>".to_owned(),
            ));
        };
        if !valid_linux_component(category) || !valid_linux_component(name) {
            return Err(MeasureError::InvalidSelector(
                "tracepoint category and name must contain only letters, digits, and underscores"
                    .to_owned(),
            ));
        }
        Ok(Self::Tracepoint {
            category: (*category).to_owned(),
            name: (*name).to_owned(),
        })
    }

    fn parse_python(text: &str) -> Result<Self, MeasureError> {
        match text {
            "python:gc_start" => Ok(Self::PythonGc {
                event_type: EventType::PythonGcStart,
                marker: "gc__start",
            }),
            "python:gc_end" => Ok(Self::PythonGc {
                event_type: EventType::PythonGcEnd,
                marker: "gc__done",
            }),
            _ => Err(MeasureError::InvalidSelector(
                "Python selector must be python:<gc_start|gc_end>".to_owned(),
            )),
        }
    }

    fn parse_kernel(fields: &[&str]) -> Result<Self, MeasureError> {
        let event_type = match fields[1] {
            "kernel_start" => EventType::GpuKernelStart,
            "kernel_end" => EventType::GpuKernelEnd,
            _ => unreachable!("kernel parser only receives kernel selectors"),
        };
        let name = match fields.get(2) {
            None => None,
            Some(filter) => {
                let pattern = filter.strip_prefix("name~").ok_or_else(|| {
                    MeasureError::InvalidSelector(
                        "kernel filter must use name~<regular-expression>".to_owned(),
                    )
                })?;
                if pattern.is_empty() {
                    return Err(MeasureError::InvalidSelector(
                        "kernel name regular expression must not be empty".to_owned(),
                    ));
                }
                Some(Regex::new(pattern).map_err(|error| {
                    MeasureError::InvalidSelector(format!(
                        "invalid kernel name regular expression: {error}"
                    ))
                })?)
            }
        };
        Ok(Self::Kernel { event_type, name })
    }

    fn parse_memcpy(fields: &[&str]) -> Result<Self, MeasureError> {
        let event_type = match fields[1] {
            "memcpy_start" => EventType::GpuMemcpyStart,
            "memcpy_end" => EventType::GpuMemcpyEnd,
            _ => unreachable!("memcpy parser only receives memcpy selectors"),
        };
        let kind = match fields.get(2) {
            None => None,
            Some(filter) => {
                let kind = filter.strip_prefix("kind=").ok_or_else(|| {
                    MeasureError::InvalidSelector(
                        "memcpy filter must use kind=<HtoD|DtoH|DtoD|HtoH|PtoP>".to_owned(),
                    )
                })?;
                Some(match kind {
                    "HtoD" => MemcpyKind::HostToDevice,
                    "DtoH" => MemcpyKind::DeviceToHost,
                    "DtoD" => MemcpyKind::DeviceToDevice,
                    "HtoH" => MemcpyKind::HostToHost,
                    "PtoP" => MemcpyKind::PeerToPeer,
                    _ => {
                        return Err(MeasureError::InvalidSelector(format!(
                            "unsupported memcpy kind {kind:?}"
                        )));
                    }
                })
            }
        };
        Ok(Self::Memcpy { event_type, kind })
    }

    fn parse_memset(text: &str, fields: &[&str]) -> Result<Self, MeasureError> {
        if fields.len() != 2 {
            return Err(MeasureError::InvalidSelector(format!(
                "memset selector {text:?} does not accept a filter"
            )));
        }
        let event_type = match fields[1] {
            "memset_start" => EventType::GpuMemsetStart,
            "memset_end" => EventType::GpuMemsetEnd,
            _ => unreachable!("memset parser only receives memset selectors"),
        };
        Ok(Self::Memset { event_type })
    }

    fn parse_nvtx(fields: &[&str]) -> Result<Self, MeasureError> {
        let event_type = match fields[1] {
            "nvtx_range_start" => EventType::NvtxRangeStart,
            "nvtx_range_end" => EventType::NvtxRangeEnd,
            _ => unreachable!("NVTX parser only receives NVTX range selectors"),
        };
        let Some(filter) = fields.get(2) else {
            return Err(MeasureError::InvalidSelector(
                "NVTX range selector requires name~<bounded-regular-expression>".to_owned(),
            ));
        };
        let pattern = filter.strip_prefix("name~").ok_or_else(|| {
            MeasureError::InvalidSelector(
                "NVTX range filter must use name~<bounded-regular-expression>".to_owned(),
            )
        })?;
        if !is_bounded_name_regex(pattern) {
            return Err(MeasureError::InvalidSelector(
                "NVTX range name must reduce to one nonempty exact, prefix, suffix, or contains filter shorter than 128 bytes".to_owned(),
            ));
        }
        let name = Regex::new(pattern).map_err(|error| {
            MeasureError::InvalidSelector(format!(
                "invalid NVTX range name regular expression: {error}"
            ))
        })?;
        Ok(Self::Nvtx {
            event_type,
            name,
            pattern: pattern.to_owned(),
        })
    }

    fn matches(&self, event: &Event) -> bool {
        match self {
            Self::Host {
                event_type,
                probe_kind,
                binary_path,
                target,
            } => {
                event.event_type == *event_type
                    && event.host.as_ref().is_some_and(|host| {
                        host.probe_kind == *probe_kind
                            && host.binary_path.as_deref() == Some(binary_path.as_str())
                            && match target {
                                HostTarget::Symbol(symbol) => {
                                    host.symbol.as_deref() == Some(symbol.as_str())
                                        || host.symbol_demangled.as_deref() == Some(symbol.as_str())
                                }
                                HostTarget::Offset(offset) => host.offset == Some(*offset),
                            }
                    })
            }
            Self::Api {
                event_type,
                domain,
                name,
            } => {
                event.event_type == *event_type
                    && cuda_api(event) == Some((domain.as_str(), name.as_str()))
            }
            Self::LaunchApi { event_type } => {
                event.event_type == *event_type
                    && cuda_api(event).is_some_and(|(domain, name)| {
                        xprobe_protocol::is_cuda_launch_api(domain, name)
                    })
            }
            Self::Kernel { event_type, name } => {
                event.event_type == *event_type
                    && name.as_ref().is_none_or(|pattern| {
                        event
                            .cuda
                            .as_ref()
                            .and_then(|cuda| cuda.kernel_name.as_deref())
                            .is_some_and(|kernel| pattern.is_match(kernel))
                    })
            }
            Self::Syscall { event_type, name } => {
                event.event_type == *event_type
                    && event.host.as_ref().is_some_and(|host| {
                        host.probe_kind == HostProbeKind::Syscall
                            && host.symbol.as_deref() == Some(name.as_str())
                    })
            }
            Self::Tracepoint { category, name } => {
                event.event_type == EventType::Tracepoint
                    && event.host.as_ref().is_some_and(|host| {
                        host.probe_kind == HostProbeKind::Tracepoint
                            && host.symbol.as_deref() == Some(name.as_str())
                    })
                    && event
                        .attributes
                        .get("tracepoint_category")
                        .and_then(serde_json::Value::as_str)
                        == Some(category.as_str())
            }
            Self::PythonGc { event_type, marker } => {
                event.event_type == *event_type
                    && event.host.as_ref().is_some_and(|host| {
                        host.probe_kind == HostProbeKind::Usdt
                            && host.symbol.as_deref() == Some(*marker)
                    })
                    && event
                        .attributes
                        .get("usdt_provider")
                        .and_then(serde_json::Value::as_str)
                        == Some("python")
            }
            Self::Memcpy { event_type, kind } => {
                event.event_type == *event_type
                    && kind.as_ref().is_none_or(|kind| {
                        event
                            .cuda
                            .as_ref()
                            .and_then(|cuda| cuda.memcpy_kind.as_ref())
                            == Some(kind)
                    })
            }
            Self::Memset { event_type } => event.event_type == *event_type,
            Self::Nvtx {
                event_type, name, ..
            } => {
                event.event_type == *event_type
                    && event
                        .nvtx
                        .as_ref()
                        .is_some_and(|nvtx| name.is_match(&nvtx.name))
            }
        }
    }

    fn supports_exact(&self, end: &Self) -> bool {
        match (self, end) {
            (
                Self::Syscall {
                    event_type: EventType::SyscallEntry,
                    name: start_name,
                },
                Self::Syscall {
                    event_type: EventType::SyscallExit,
                    name: end_name,
                },
            ) => start_name == end_name,
            (
                Self::Nvtx {
                    event_type: EventType::NvtxRangeStart,
                    pattern: start_pattern,
                    ..
                },
                Self::Nvtx {
                    event_type: EventType::NvtxRangeEnd,
                    pattern: end_pattern,
                    ..
                },
            ) => start_pattern == end_pattern,
            (
                Self::PythonGc {
                    event_type: EventType::PythonGcStart,
                    ..
                },
                Self::PythonGc {
                    event_type: EventType::PythonGcEnd,
                    ..
                },
            ) => true,
            (
                Self::Host { .. }
                | Self::Tracepoint { .. }
                | Self::Nvtx { .. }
                | Self::PythonGc { .. },
                _,
            )
            | (
                _,
                Self::Host { .. }
                | Self::Tracepoint { .. }
                | Self::Nvtx { .. }
                | Self::PythonGc { .. },
            ) => false,
            _ => true,
        }
    }

    fn is_syscall_lifecycle(&self, end: &Self) -> bool {
        matches!(
            (self, end),
            (
                Self::Syscall {
                    event_type: EventType::SyscallEntry,
                    name: start_name,
                },
                Self::Syscall {
                    event_type: EventType::SyscallExit,
                    name: end_name,
                },
            ) if start_name == end_name
        )
    }

    fn is_nvtx_lifecycle(&self, end: &Self) -> bool {
        matches!(
            (self, end),
            (
                Self::Nvtx {
                    event_type: EventType::NvtxRangeStart,
                    pattern: start_pattern,
                    ..
                },
                Self::Nvtx {
                    event_type: EventType::NvtxRangeEnd,
                    pattern: end_pattern,
                    ..
                },
            ) if start_pattern == end_pattern
        )
    }

    fn is_python_gc_lifecycle(&self, end: &Self) -> bool {
        matches!(
            (self, end),
            (
                Self::PythonGc {
                    event_type: EventType::PythonGcStart,
                    ..
                },
                Self::PythonGc {
                    event_type: EventType::PythonGcEnd,
                    ..
                },
            )
        )
    }

    fn supports_stack_nested(&self, end: &Self) -> bool {
        match (self, end) {
            (
                Self::Host {
                    event_type: EventType::HostFunctionEntry,
                    binary_path: start_binary,
                    target: start_target,
                    ..
                },
                Self::Host {
                    event_type: EventType::HostFunctionExit,
                    binary_path: end_binary,
                    target: end_target,
                    ..
                },
            ) => start_binary == end_binary && start_target == end_target,
            _ => false,
        }
    }

    const fn activity_boundary(&self) -> Option<ActivityBoundary> {
        match self {
            Self::Kernel { event_type, .. }
            | Self::Memcpy { event_type, .. }
            | Self::Memset { event_type } => activity_boundary(event_type),
            _ => None,
        }
    }
}

/// Count a Runtime launch and the Driver launch it makes once, as the Runtime
/// call. The Agent gives the nested Driver callback the Runtime correlation ID,
/// so both share a thread and correlation key; a Driver launch without an
/// enclosing Runtime launch (Triton, for example) is kept.
fn drop_nested_driver_launches(events: &mut Vec<&Event>) {
    let launch_key = |event: &Event, wanted: &str| {
        cuda_api(event)
            .is_some_and(|(domain, _)| domain == wanted)
            .then(|| correlation_key(event).map(|key| (event.tid, key)))
            .flatten()
    };
    let runtime = events
        .iter()
        .filter_map(|event| launch_key(event, "runtime_api"))
        .collect::<BTreeSet<_>>();
    if runtime.is_empty() {
        return;
    }
    events
        .retain(|event| launch_key(event, "driver_api").is_none_or(|key| !runtime.contains(&key)));
}

/// The `(domain, name)` of a CUDA API callback event.
fn cuda_api(event: &Event) -> Option<(&str, &str)> {
    let attribute = |key: &str| {
        event
            .attributes
            .get(key)
            .and_then(serde_json::Value::as_str)
    };
    attribute("cuda_api_domain").zip(attribute("cuda_api_name"))
}

fn is_bounded_name_regex(pattern: &str) -> bool {
    const CANDIDATES: [(&str, &str); 8] = [
        ("^", "$"),
        ("^", ".*"),
        (".*", "$"),
        (".*", ".*"),
        ("^", ""),
        ("", "$"),
        (".*", ""),
        ("", ""),
    ];
    CANDIDATES.iter().any(|(prefix, suffix)| {
        pattern
            .strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(suffix))
            .and_then(regex_literal)
            .is_some_and(|literal| !literal.is_empty() && literal.len() < 128)
    })
}

fn regex_literal(pattern: &str) -> Option<String> {
    let mut literal = String::with_capacity(pattern.len());
    let mut characters = pattern.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            let escaped = characters.next()?;
            if escaped.is_ascii_alphanumeric() {
                return None;
            }
            literal.push(escaped);
        } else if ".+*?()|[]{}^$".contains(character) {
            return None;
        } else {
            literal.push(character);
        }
    }
    Some(literal)
}

fn valid_linux_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[derive(Debug)]
struct Pair<'a> {
    start: &'a Event,
    end: &'a Event,
    latency_ns: u64,
}

#[derive(Debug)]
struct Outcome<'a> {
    pairs: Vec<Pair<'a>>,
    unmatched_start: u64,
    unmatched_end: u64,
    ambiguous: u64,
    /// Matched pairs beyond the samples limit; counted in the score only.
    beyond_limit: u64,
}

/// The capture and the endpoints selected from it.
struct Selected<'s, 'a> {
    events: &'a [Event],
    starts: &'s [&'a Event],
    ends: &'s [&'a Event],
    /// The end selector, when names in the ends came from one.
    end_selector: Option<&'s Selector>,
}

#[derive(Debug, Clone, Copy)]
struct LifecycleKinds {
    syscall: bool,
    nvtx: bool,
    python_gc: bool,
}

/// Correlate a bounded event capture and calculate latency statistics.
///
/// # Errors
///
/// Returns [`MeasureError`] for invalid selectors or limits, unsupported match
/// policies, unaligned clock domains, excessive input, or no matched pairs.
pub fn measure(
    events: &[Event],
    options: &MeasureOptions,
) -> Result<MeasurementResult, MeasureError> {
    validate_options(options)?;
    if events.len() > options.max_events {
        return Err(MeasureError::EventLimitExceeded {
            actual: events.len(),
            maximum: options.max_events,
        });
    }
    if options.dropped_events != 0 {
        return Err(MeasureError::EventsDropped {
            count: options.dropped_events,
        });
    }
    let start_selector = Selector::parse(&options.start_selector)?;
    let end_selector = Selector::parse(&options.end_selector)?;
    validate_policy(&start_selector, &end_selector, options.match_policy)?;
    let (starts, ends, clock_domain) =
        select_endpoints(events, &start_selector, &end_selector, options.duration)?;

    let lifecycles = LifecycleKinds {
        syscall: start_selector.is_syscall_lifecycle(&end_selector),
        nvtx: start_selector.is_nvtx_lifecycle(&end_selector),
        python_gc: start_selector.is_python_gc_lifecycle(&end_selector),
    };
    let outcome = correlate_selected(
        &Selected {
            events,
            starts: &starts,
            ends: &ends,
            end_selector: Some(&end_selector),
        },
        options.match_policy,
        options.samples,
        lifecycles,
    );
    if outcome.pairs.is_empty() {
        return Err(MeasureError::NoMatchedSamples);
    }

    let matched = outcome.pairs.len() as u64;
    let latencies = outcome
        .pairs
        .iter()
        .map(|pair| pair.latency_ns)
        .collect::<Vec<_>>();
    let denominator = matched
        + outcome.beyond_limit
        + outcome.unmatched_start
        + outcome.unmatched_end
        + outcome.ambiguous;
    let (method, confidence) = correlation_metadata(options.match_policy, lifecycles);
    let warnings = measurement_warnings(options, &starts, &ends);

    let (host_events, cuda_events) = collection_event_counts(events);
    let estimated_error_ns = maximum_timestamp_error(&outcome.pairs);
    let pairs = matched_pairs(outcome.pairs);
    let mut result = MeasurementResult {
        schema_version: SchemaVersion3::current(),
        ok: true,
        session_id: options.session_id.clone(),
        status: SessionStatus::Completed,
        measurement: Measurement {
            name: options.name.clone(),
            samples: SampleSummary {
                matched,
                unmatched_start: outcome.unmatched_start,
                unmatched_end: outcome.unmatched_end,
                ambiguous: outcome.ambiguous,
                dropped: options.dropped_events,
            },
            latency_ns: statistics(&latencies),
        },
        quality: ResultQuality {
            verdict: QualityVerdict::Good,
            issues: Vec::new(),
        },
        correlation: CorrelationSummary {
            method: method.to_owned(),
            confidence,
            score: ratio(matched + outcome.beyond_limit, denominator),
        },
        clock: ClockQuality {
            alignment: clock_alignment(&clock_domain).to_owned(),
            estimated_error_ns,
        },
        collection: CollectionSummary {
            completeness: CaptureCompleteness::Complete,
            // The caller knows how the events were collected and replaces this.
            coverage: CaptureCoverage {
                source: CoverageSource::Unverified,
                all_gpu_activity: false,
            },
            host_events,
            cuda_events,
            dropped_events: options.dropped_events,
            cupti: None,
        },
        evidence: quality::full_evidence(pairs),
        warnings,
    };
    result.quality = assess_quality(&result);
    Ok(result)
}

/// The start and end events each selector picks, in time order and within
/// the duration window, with the clock domain they share.
fn select_endpoints<'a>(
    events: &'a [Event],
    start_selector: &Selector,
    end_selector: &Selector,
    duration: Option<Duration>,
) -> Result<(Vec<&'a Event>, Vec<&'a Event>, ClockDomain), MeasureError> {
    let select = |selector: &Selector| {
        let mut selected = events
            .iter()
            .filter(|event| selector.matches(event))
            .collect::<Vec<_>>();
        if matches!(selector, Selector::LaunchApi { .. }) {
            drop_nested_driver_launches(&mut selected);
        }
        selected.sort_by_key(|event| event.timestamp_ns);
        selected
    };
    let mut starts = select(start_selector);
    let mut ends = select(end_selector);
    let clock_domain = common_clock_domain(&starts, &ends)?;
    apply_duration_window(&mut starts, &mut ends, duration)?;
    Ok((starts, ends, clock_domain))
}

fn matched_pairs(pairs: Vec<Pair<'_>>) -> Vec<MatchedEventPair> {
    pairs
        .into_iter()
        .map(|pair| MatchedEventPair {
            start: pair.start.clone(),
            end: pair.end.clone(),
            latency_ns: pair.latency_ns,
        })
        .collect()
}

const fn clock_alignment(domain: &ClockDomain) -> &'static str {
    match domain {
        ClockDomain::HostMonotonic => "host_monotonic",
        ClockDomain::Cupti => "cupti_same_domain",
        ClockDomain::CuptiNormalizedToHostMonotonic => "cupti_normalized_to_host_monotonic",
    }
}

fn collection_event_counts(events: &[Event]) -> (u64, u64) {
    let host = events
        .iter()
        .filter(|event| event.source == EventSource::Ebpf)
        .count() as u64;
    (host, events.len() as u64 - host)
}

/// Correlate the whole window, then keep the earliest `limit` pairs so the
/// unmatched counts and the score describe the same window for every policy.
fn correlate_selected<'a>(
    selected: &Selected<'_, 'a>,
    policy: MatchPolicy,
    limit: Option<usize>,
    lifecycles: LifecycleKinds,
) -> Outcome<'a> {
    let (starts, ends) = (selected.starts, selected.ends);
    let mut outcome = match policy {
        MatchPolicy::Exact if lifecycles.syscall || lifecycles.python_gc => {
            correlate_thread_lifecycle(starts, ends)
        }
        MatchPolicy::Exact if lifecycles.nvtx => correlate_nvtx_lifecycle(starts, ends),
        MatchPolicy::Exact => correlate_exact(starts, ends),
        MatchPolicy::FirstAfter => correlate_first_after(starts, ends),
        MatchPolicy::Nearest => correlate_nearest(starts, ends),
        MatchPolicy::StackNested => correlate_stack_nested(starts, ends),
        MatchPolicy::StreamOrder => correlate_stream_order(selected),
    };
    outcome.pairs.sort_by_key(|pair| pair.start.timestamp_ns);
    if let Some(limit) = limit.filter(|limit| outcome.pairs.len() > *limit) {
        outcome.beyond_limit = (outcome.pairs.len() - limit) as u64;
        outcome.pairs.truncate(limit);
    }
    outcome
}

fn validate_policy(
    start: &Selector,
    end: &Selector,
    policy: MatchPolicy,
) -> Result<(), MeasureError> {
    let message = match policy {
        MatchPolicy::Exact if !start.supports_exact(end) => {
            Some("exact matching requires endpoints with a deterministic correlation key")
        }
        MatchPolicy::StackNested if !start.supports_stack_nested(end) => {
            Some("stack-nested requires entry and return selectors for the same host function")
        }
        MatchPolicy::StreamOrder
            if start.activity_boundary() != Some(ActivityBoundary::End)
                || end.activity_boundary() != Some(ActivityBoundary::Start) =>
        {
            Some(
                "stream-order pairs a GPU activity end with the next activity start on its stream; use exact for an activity's own duration",
            )
        }
        _ => None,
    };
    if let Some(message) = message {
        return Err(MeasureError::InvalidPolicy(message.to_owned()));
    }
    Ok(())
}

const fn correlation_metadata(
    policy: MatchPolicy,
    lifecycles: LifecycleKinds,
) -> (&'static str, CorrelationConfidence) {
    match policy {
        MatchPolicy::Exact if lifecycles.syscall => {
            ("exact_syscall_tid_lifecycle", CorrelationConfidence::Exact)
        }
        MatchPolicy::Exact if lifecycles.nvtx => {
            ("exact_nvtx_range_id", CorrelationConfidence::Exact)
        }
        MatchPolicy::Exact if lifecycles.python_gc => (
            "exact_python_gc_tid_lifecycle",
            CorrelationConfidence::Exact,
        ),
        MatchPolicy::Exact => ("exact_cupti_correlation_id", CorrelationConfidence::Exact),
        MatchPolicy::FirstAfter => ("first_after", CorrelationConfidence::Heuristic),
        MatchPolicy::Nearest => ("nearest", CorrelationConfidence::Heuristic),
        MatchPolicy::StackNested => ("stack_nested_tid_lifo", CorrelationConfidence::High),
        MatchPolicy::StreamOrder => (quality::STREAM_ORDER_METHOD, CorrelationConfidence::High),
    }
}

fn correlate_thread_lifecycle<'a>(starts: &[&'a Event], ends: &[&'a Event]) -> Outcome<'a> {
    let mut timeline = starts
        .iter()
        .map(|event| (event.timestamp_ns, 0_u8, *event))
        .chain(ends.iter().map(|event| (event.timestamp_ns, 1_u8, *event)))
        .collect::<Vec<_>>();
    timeline.sort_by_key(|(timestamp, boundary, event)| (*timestamp, *boundary, event.sequence));

    let mut pending = BTreeMap::<(u32, u32, Option<u64>), &Event>::new();
    let mut pairs = Vec::new();
    let mut unmatched_end = 0_u64;
    let mut ambiguous = 0_u64;
    for (_, boundary, event) in timeline {
        let key = (event.pid, event.tid, event.process_start_time);
        if boundary == 0 {
            if pending.insert(key, event).is_some() {
                ambiguous += 1;
            }
        } else if let Some(start) = pending.remove(&key) {
            if let Some(latency_ns) = event.timestamp_ns.checked_sub(start.timestamp_ns) {
                pairs.push(Pair {
                    start,
                    end: event,
                    latency_ns,
                });
            } else {
                ambiguous += 1;
            }
        } else {
            unmatched_end += 1;
        }
    }
    pairs.sort_by_key(|pair| pair.start.timestamp_ns);
    Outcome {
        pairs,
        unmatched_start: pending.len() as u64,
        unmatched_end,
        ambiguous,
        beyond_limit: 0,
    }
}

fn correlate_nvtx_lifecycle<'a>(starts: &[&'a Event], ends: &[&'a Event]) -> Outcome<'a> {
    let mut timeline = starts
        .iter()
        .map(|event| (event.timestamp_ns, 0_u8, *event))
        .chain(ends.iter().map(|event| (event.timestamp_ns, 1_u8, *event)))
        .collect::<Vec<_>>();
    timeline.sort_by_key(|(timestamp, boundary, event)| (*timestamp, *boundary, event.sequence));

    let mut pending = BTreeMap::<CorrelationKey, &Event>::new();
    let mut pairs = Vec::new();
    let mut unmatched_start = 0_u64;
    let mut unmatched_end = 0_u64;
    let mut ambiguous = 0_u64;
    for (_, boundary, event) in timeline {
        let Some(key) = correlation_key(event) else {
            if boundary == 0 {
                unmatched_start += 1;
            } else {
                unmatched_end += 1;
            }
            continue;
        };
        if boundary == 0 {
            if pending.insert(key, event).is_some() {
                ambiguous += 1;
            }
        } else if let Some(start) = pending.remove(&key) {
            if let Some(latency_ns) = event.timestamp_ns.checked_sub(start.timestamp_ns) {
                pairs.push(Pair {
                    start,
                    end: event,
                    latency_ns,
                });
            } else {
                ambiguous += 1;
            }
        } else {
            unmatched_end += 1;
        }
    }
    unmatched_start += pending.len() as u64;
    pairs.sort_by_key(|pair| pair.start.timestamp_ns);
    Outcome {
        pairs,
        unmatched_start,
        unmatched_end,
        ambiguous,
        beyond_limit: 0,
    }
}

/// Completed captures are already bounded, so samples and duration are
/// optional here; live collection requires one of them before capturing.
fn validate_options(options: &MeasureOptions) -> Result<(), MeasureError> {
    if options.samples == Some(0) {
        return Err(MeasureError::InvalidLimit(
            "samples must be greater than zero".to_owned(),
        ));
    }
    if options.duration.is_some_and(|duration| duration.is_zero()) {
        return Err(MeasureError::InvalidLimit(
            "duration must be greater than zero".to_owned(),
        ));
    }
    if options.max_events == 0 {
        return Err(MeasureError::InvalidLimit(
            "max-events must be greater than zero".to_owned(),
        ));
    }
    if options.session_id.is_empty() {
        return Err(MeasureError::InvalidLimit(
            "session ID must not be empty".to_owned(),
        ));
    }
    Ok(())
}

fn measurement_warnings(
    options: &MeasureOptions,
    starts: &[&Event],
    ends: &[&Event],
) -> Vec<Warning> {
    let mut warnings = Vec::new();
    if matches!(
        options.match_policy,
        MatchPolicy::FirstAfter | MatchPolicy::Nearest
    ) {
        warnings.push(warning(
            "HEURISTIC_CORRELATION",
            "temporal matching does not prove request-level causality",
        ));
    }
    if starts.iter().chain(ends).any(|event| {
        event.clock_domain == ClockDomain::CuptiNormalizedToHostMonotonic
            && event.timestamp_error_ns.is_none()
    }) {
        warnings.push(warning(
            "CLOCK_ERROR_UNAVAILABLE",
            "CUPTI does not report an error bound for GPU-to-host timestamp interpolation",
        ));
    }
    warnings
}

fn apply_duration_window<'a>(
    starts: &mut Vec<&'a Event>,
    ends: &mut Vec<&'a Event>,
    duration: Option<Duration>,
) -> Result<(), MeasureError> {
    let Some(duration) = duration else {
        return Ok(());
    };
    let Some(first_timestamp) = starts
        .first()
        .into_iter()
        .chain(ends.first())
        .map(|event| event.timestamp_ns)
        .min()
    else {
        return Ok(());
    };
    let duration_ns = u64::try_from(duration.as_nanos())
        .map_err(|_| MeasureError::InvalidLimit("duration exceeds nanosecond range".to_owned()))?;
    let end_timestamp = first_timestamp.checked_add(duration_ns).ok_or_else(|| {
        MeasureError::InvalidLimit("duration window overflows timestamp range".to_owned())
    })?;
    starts.retain(|event| event.timestamp_ns <= end_timestamp);
    ends.retain(|event| event.timestamp_ns <= end_timestamp);
    Ok(())
}

fn common_clock_domain(starts: &[&Event], ends: &[&Event]) -> Result<ClockDomain, MeasureError> {
    let mut events = starts.iter().chain(ends);
    let Some(first) = events.next() else {
        return Err(MeasureError::NoMatchedSamples);
    };
    let first_group = clock_group(&first.clock_domain);
    let mut has_normalized_cupti =
        first.clock_domain == ClockDomain::CuptiNormalizedToHostMonotonic;
    for event in events {
        if clock_group(&event.clock_domain) != first_group {
            return Err(MeasureError::ClockDomainsDiffer {
                start: first.clock_domain.clone(),
                end: event.clock_domain.clone(),
            });
        }
        has_normalized_cupti |= event.clock_domain == ClockDomain::CuptiNormalizedToHostMonotonic;
    }
    if first_group == 1 {
        Ok(ClockDomain::Cupti)
    } else if has_normalized_cupti {
        Ok(ClockDomain::CuptiNormalizedToHostMonotonic)
    } else {
        Ok(ClockDomain::HostMonotonic)
    }
}

const fn clock_group(domain: &ClockDomain) -> u8 {
    match domain {
        ClockDomain::HostMonotonic | ClockDomain::CuptiNormalizedToHostMonotonic => 0,
        ClockDomain::Cupti => 1,
    }
}

fn correlate_exact<'a>(starts: &[&'a Event], ends: &[&'a Event]) -> Outcome<'a> {
    let mut start_groups: BTreeMap<CorrelationKey, Vec<&Event>> = BTreeMap::new();
    let mut end_groups: BTreeMap<CorrelationKey, Vec<&Event>> = BTreeMap::new();
    let mut unmatched_start = 0_u64;
    let mut unmatched_end = 0_u64;
    for event in starts {
        if let Some(key) = correlation_key(event) {
            start_groups.entry(key).or_default().push(event);
        } else {
            unmatched_start += 1;
        }
    }
    for event in ends {
        if let Some(key) = correlation_key(event) {
            end_groups.entry(key).or_default().push(event);
        } else {
            unmatched_end += 1;
        }
    }

    let mut pairs = Vec::new();
    let mut ambiguous = 0_u64;
    for (key, group) in &start_groups {
        let Some(end_group) = end_groups.remove(key) else {
            unmatched_start += group.len() as u64;
            continue;
        };
        if group.len() != end_group.len() {
            ambiguous += group.len().max(end_group.len()) as u64;
            continue;
        }
        for (start, end) in group.iter().zip(end_group) {
            if let Some(latency) = end.timestamp_ns.checked_sub(start.timestamp_ns) {
                pairs.push(Pair {
                    start,
                    end,
                    latency_ns: latency,
                });
            } else {
                unmatched_start += 1;
                unmatched_end += 1;
            }
        }
    }
    unmatched_end += end_groups.values().map(Vec::len).sum::<usize>() as u64;
    pairs.sort_by_key(|pair| pair.start.timestamp_ns);
    Outcome {
        pairs,
        unmatched_start,
        unmatched_end,
        ambiguous,
        beyond_limit: 0,
    }
}

fn correlate_first_after<'a>(starts: &[&'a Event], ends: &[&'a Event]) -> Outcome<'a> {
    let mut pairs = Vec::new();
    let mut unmatched_start = 0_u64;
    let mut unmatched_end = 0_u64;
    let mut end_index = 0;
    for (start_index, start) in starts.iter().enumerate() {
        while end_index < ends.len() && ends[end_index].timestamp_ns < start.timestamp_ns {
            unmatched_end += 1;
            end_index += 1;
        }
        if let Some(end) = ends.get(end_index) {
            pairs.push(Pair {
                start,
                end,
                latency_ns: end.timestamp_ns - start.timestamp_ns,
            });
            end_index += 1;
        } else {
            unmatched_start += (starts.len() - start_index) as u64;
            break;
        }
    }
    unmatched_end += (ends.len() - end_index) as u64;
    Outcome {
        pairs,
        unmatched_start,
        unmatched_end,
        ambiguous: 0,
        beyond_limit: 0,
    }
}

fn correlate_nearest<'a>(starts: &[&'a Event], ends: &[&'a Event]) -> Outcome<'a> {
    let mut available = BTreeMap::<u64, Vec<&Event>>::new();
    for end in ends {
        available.entry(end.timestamp_ns).or_default().push(end);
    }
    let mut pairs = Vec::new();
    let mut unmatched_start = 0_u64;
    for (index, start) in starts.iter().enumerate() {
        let before = available
            .range(..=start.timestamp_ns)
            .next_back()
            .map(|(timestamp, _)| *timestamp);
        let after = available
            .range(start.timestamp_ns..)
            .next()
            .map(|(timestamp, _)| *timestamp);
        let selected = match (before, after) {
            (Some(before), Some(after)) => {
                if start.timestamp_ns - before < after - start.timestamp_ns {
                    before
                } else {
                    after
                }
            }
            (Some(timestamp), None) | (None, Some(timestamp)) => timestamp,
            (None, None) => {
                unmatched_start += (starts.len() - index) as u64;
                break;
            }
        };
        let bucket = available
            .get_mut(&selected)
            .expect("selected timestamp must remain available");
        let end = bucket.pop().expect("timestamp bucket must be nonempty");
        pairs.push(Pair {
            start,
            end,
            latency_ns: selected.abs_diff(start.timestamp_ns),
        });
        if bucket.is_empty() {
            available.remove(&selected);
        }
    }
    Outcome {
        pairs,
        unmatched_start,
        unmatched_end: available.values().map(Vec::len).sum::<usize>() as u64,
        ambiguous: 0,
        beyond_limit: 0,
    }
}

fn correlate_stack_nested<'a>(starts: &[&'a Event], ends: &[&'a Event]) -> Outcome<'a> {
    let mut timeline = starts
        .iter()
        .map(|event| (event.timestamp_ns, 0_u8, *event))
        .chain(ends.iter().map(|event| (event.timestamp_ns, 1_u8, *event)))
        .collect::<Vec<_>>();
    timeline.sort_by_key(|(timestamp, boundary, _)| (*timestamp, *boundary));
    let mut stacks = BTreeMap::<(u32, u32), Vec<&Event>>::new();
    let mut pairs = Vec::new();
    let mut unmatched_end = 0_u64;
    for (_, boundary, event) in timeline {
        let key = (event.pid, event.tid);
        if boundary == 0 {
            stacks.entry(key).or_default().push(event);
        } else if let Some(start) = stacks.get_mut(&key).and_then(Vec::pop) {
            pairs.push(Pair {
                start,
                end: event,
                latency_ns: event.timestamp_ns - start.timestamp_ns,
            });
        } else {
            unmatched_end += 1;
        }
    }
    pairs.sort_by_key(|pair| pair.start.timestamp_ns);
    Outcome {
        pairs,
        unmatched_start: stacks.values().map(Vec::len).sum::<usize>() as u64,
        unmatched_end,
        ambiguous: 0,
        beyond_limit: 0,
    }
}

type StreamKey = (u32, u32, u32, u64);

/// Pair an activity end with the start of the next activity on its stream.
///
/// Successors come from every kernel, copy, and memset on the stream in the
/// capture, not only the selected endpoints, so a narrower end selector never
/// skips over activity that ran in between. An end that overlaps other
/// activity on its stream (CUDA Graph nodes or programmatic dependent launch),
/// whose successor ties with another start, or whose successor's truncated
/// kernel name cannot decide the end selector is ambiguous. An end whose
/// successor is not selected, or that has no successor in the capture, is an
/// unmatched start.
fn correlate_stream_order<'a>(selected: &Selected<'_, 'a>) -> Outcome<'a> {
    let chosen = |events: &[&Event]| {
        events
            .iter()
            .map(|event| ptr::from_ref(*event))
            .collect::<BTreeSet<_>>()
    };
    let from = chosen(selected.starts);
    let to = chosen(selected.ends);
    let mut timelines = BTreeMap::<StreamKey, Vec<&Event>>::new();
    for event in selected.events {
        if activity_boundary(&event.event_type).is_some()
            && let Some(key) = stream_key(event)
        {
            timelines.entry(key).or_default().push(event);
        }
    }
    let mut pairs = Vec::new();
    let mut unmatched_start = selected
        .starts
        .iter()
        .filter(|event| stream_key(event).is_none())
        .count() as u64;
    let mut ambiguous = 0_u64;
    for timeline in timelines.values_mut() {
        sort_timeline(timeline);
        // Track running activity by identity. An end whose start is not in
        // the capture began earlier and ran until then, so no gap before the
        // latest such end can be shown idle.
        let mut open = BTreeMap::<ActivityKey, u64>::new();
        let mut orphan_horizon = None::<u64>;
        for event in timeline.iter() {
            let key = activity_key(event);
            if activity_boundary(&event.event_type) == Some(ActivityBoundary::Start) {
                *open.entry(key).or_default() += 1;
            } else if let Some(count) = open.get_mut(&key).filter(|count| **count > 0) {
                *count -= 1;
            } else {
                orphan_horizon = orphan_horizon.max(Some(event.timestamp_ns));
            }
        }
        open.clear();
        let mut running = 0_u64;
        for (index, event) in timeline.iter().enumerate() {
            let key = activity_key(event);
            if activity_boundary(&event.event_type) == Some(ActivityBoundary::Start) {
                *open.entry(key).or_default() += 1;
                running += 1;
                continue;
            }
            let started = open.get_mut(&key).filter(|count| **count > 0).map(|count| {
                *count -= 1;
                running -= 1;
            });
            if !from.contains(&ptr::from_ref(*event)) {
                continue;
            }
            let overlapped = orphan_horizon.is_some_and(|horizon| event.timestamp_ns < horizon);
            let alone = started.is_some() && running == 0 && !overlapped;
            match stream_successor(timeline, index, alone) {
                Successor::Next(next) if to.contains(&ptr::from_ref(next)) => pairs.push(Pair {
                    start: event,
                    end: next,
                    latency_ns: next.timestamp_ns - event.timestamp_ns,
                }),
                Successor::Next(next) if name_undecidable(selected.end_selector, next) => {
                    ambiguous += 1;
                }
                Successor::Next(_) | Successor::None => unmatched_start += 1,
                Successor::Ambiguous => ambiguous += 1,
            }
        }
    }
    let paired = pairs
        .iter()
        .map(|pair| ptr::from_ref(pair.end))
        .collect::<BTreeSet<_>>();
    Outcome {
        unmatched_end: to.difference(&paired).count() as u64,
        pairs,
        unmatched_start,
        ambiguous,
        beyond_limit: 0,
    }
}

/// Order one stream's boundaries in time. At one timestamp, ends come before
/// starts, so A.end == B.start is a valid zero gap rather than an overlap. A
/// zero-duration activity's own start and end sit together between them: the
/// Agent records an activity's start before its end, so a start that shares
/// an end's timestamp and key and precedes it in sequence is that end's own.
fn sort_timeline(timeline: &mut [&Event]) {
    let is_start =
        |event: &Event| activity_boundary(&event.event_type) == Some(ActivityBoundary::Start);
    // Per timestamp and key: the earliest start and the latest end sequence.
    let mut boundaries = BTreeMap::<(u64, ActivityKey<'_>), (u64, u64)>::new();
    for event in timeline.iter() {
        let seen = boundaries
            .entry((event.timestamp_ns, activity_key(event)))
            .or_insert((u64::MAX, 0));
        if is_start(event) {
            seen.0 = seen.0.min(event.sequence);
        } else {
            seen.1 = seen.1.max(event.sequence);
        }
    }
    timeline.sort_by_cached_key(|event| {
        let key = activity_key(event);
        let (first_start, last_end) = boundaries[&(event.timestamp_ns, key)];
        let instant = if is_start(event) {
            last_end > event.sequence
        } else {
            first_start < event.sequence
        };
        let rank = match (instant, is_start(event)) {
            (false, false) => 0_u8,
            (true, _) => 1,
            (false, true) => 2,
        };
        (
            event.timestamp_ns,
            rank,
            instant.then_some(key),
            event.sequence,
        )
    });
}

/// An activity's family, correlation ID, and kernel name. Graph nodes can
/// share one correlation ID, so running activity is counted per key.
type ActivityKey<'a> = (u8, u32, Option<&'a str>);

fn activity_key(event: &Event) -> ActivityKey<'_> {
    let family = match event.event_type {
        EventType::GpuKernelStart | EventType::GpuKernelEnd => 0,
        EventType::GpuMemcpyStart | EventType::GpuMemcpyEnd => 1,
        _ => 2,
    };
    let correlation = event
        .cuda
        .as_ref()
        .and_then(|cuda| cuda.correlation_id)
        .unwrap_or(0);
    let name = event
        .cuda
        .as_ref()
        .and_then(|cuda| cuda.kernel_name.as_deref());
    (family, correlation, name)
}

enum Successor<'a> {
    Next(&'a Event),
    None,
    Ambiguous,
}

/// The activity start that follows the end at `index` on one stream timeline.
fn stream_successor<'a>(timeline: &[&'a Event], index: usize, alone: bool) -> Successor<'a> {
    if !alone {
        return Successor::Ambiguous;
    }
    let Some(next) = timeline.get(index + 1) else {
        return Successor::None;
    };
    let is_start =
        |event: &Event| activity_boundary(&event.event_type) == Some(ActivityBoundary::Start);
    if !is_start(next) {
        return Successor::Ambiguous;
    }
    // A zero-duration activity's start is followed by its own end at the
    // same instant. Two zero-duration activities at one instant, or two
    // starts that are not, could be in either order; a zero-duration one
    // still precedes an activity that starts then and runs on.
    let same_instant = timeline[index + 2..]
        .iter()
        .take_while(|after| after.timestamp_ns == next.timestamp_ns)
        .collect::<Vec<_>>();
    let instant = |start: &Event, rest: &[&&Event]| {
        rest.iter().any(|after| {
            !is_start(after)
                && activity_key(after) == activity_key(start)
                && after.sequence > start.sequence
        })
    };
    let next_instant = instant(next, &same_instant);
    let rival = same_instant.iter().enumerate().any(|(offset, after)| {
        is_start(after) && instant(after, &same_instant[offset + 1..]) == next_instant
    });
    if rival {
        return Successor::Ambiguous;
    }
    Successor::Next(next)
}

/// Whether a kernel's name may have been truncated past what the selector's
/// regex needs, so a non-match does not prove the kernel is not selected.
fn name_undecidable(selector: Option<&Selector>, event: &Event) -> bool {
    let Some(Selector::Kernel {
        event_type,
        name: Some(pattern),
    }) = selector
    else {
        return false;
    };
    event.event_type == *event_type
        && event
            .cuda
            .as_ref()
            .and_then(|cuda| cuda.kernel_name.as_deref())
            .is_some_and(|name| name.len() >= CUDA_RECORD_NAME_MAX_BYTES && !pattern.is_match(name))
}

fn stream_key(event: &Event) -> Option<StreamKey> {
    let cuda = event.cuda.as_ref()?;
    Some((
        event.pid,
        cuda.device_id?,
        cuda.context_id?,
        cuda.stream_id?,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CorrelationKey {
    Cuda {
        pid: u32,
        context_id: u32,
        correlation_id: u32,
    },
    Nvtx {
        pid: u32,
        range_kind: NvtxRangeKind,
        range_id: u64,
    },
}

fn correlation_key(event: &Event) -> Option<CorrelationKey> {
    if let Some(nvtx) = event.nvtx.as_ref() {
        return Some(CorrelationKey::Nvtx {
            pid: event.pid,
            range_kind: nvtx.range_kind,
            range_id: nvtx.range_id,
        });
    }
    let cuda = event.cuda.as_ref()?;
    Some(CorrelationKey::Cuda {
        pid: event.pid,
        context_id: cuda.context_id?,
        correlation_id: cuda.correlation_id?,
    })
}

fn statistics(values: &[u64]) -> LatencyStatistics {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let sum = sorted.iter().map(|value| u128::from(*value)).sum::<u128>();
    LatencyStatistics {
        min: sorted[0],
        mean: mean(sum, sorted.len()),
        p50: percentile(&sorted, 50),
        p90: percentile(&sorted, 90),
        p95: percentile(&sorted, 95),
        p99: percentile(&sorted, 99),
        max: *sorted.last().expect("latency list is nonempty"),
    }
}

#[allow(clippy::cast_precision_loss)]
fn ratio(numerator: u64, denominator: u64) -> f64 {
    numerator as f64 / denominator as f64
}

#[allow(clippy::cast_precision_loss)]
fn mean(sum: u128, count: usize) -> f64 {
    sum as f64 / count as f64
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    sorted[quality::rank_index(sorted.len(), percentile)]
}

fn maximum_timestamp_error(pairs: &[Pair<'_>]) -> Option<u64> {
    pairs
        .iter()
        .flat_map(|pair| [pair.start, pair.end])
        .map(|event| {
            if event.clock_domain == ClockDomain::CuptiNormalizedToHostMonotonic {
                event.timestamp_error_ns
            } else {
                Some(event.timestamp_error_ns.unwrap_or(0))
            }
        })
        .try_fold(0_u64, |maximum, error| {
            error.map(|error| maximum.max(error))
        })
}

fn warning(code: &str, message: &str) -> Warning {
    Warning {
        code: code.to_owned(),
        message: message.to_owned(),
        details: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use xprobe_protocol::{
        ClockDomain, CorrelationConfidence, CudaEvent, Event, EventSource, EventType, HostEvent,
        HostProbeKind, MatchPolicy, MemcpyKind, NvtxEvent, NvtxRangeKind, SchemaVersion,
    };

    use super::{MeasureError, MeasureOptions, measure};

    fn event(kind: EventType, timestamp: u64, correlation_id: u32) -> Event {
        Event {
            schema_version: SchemaVersion::current(),
            session_id: "capture".to_owned(),
            event_id: format!("evt_{timestamp}"),
            sequence: timestamp,
            source: EventSource::CuptiActivity,
            event_type: kind,
            pid: 1234,
            tid: 1234,
            cpu: None,
            timestamp_raw: timestamp,
            timestamp_ns: timestamp,
            clock_domain: ClockDomain::Cupti,
            timestamp_error_ns: None,
            process_start_time: None,
            host: None,
            cuda: Some(CudaEvent {
                device_id: Some(0),
                context_id: Some(1),
                stream_id: Some(2),
                correlation_id: Some(correlation_id),
                runtime_correlation_id: None,
                callback_domain: None,
                callback_id: None,
                kernel_name: Some("test_kernel".to_owned()),
                kernel_name_mangled: None,
                start_ns: None,
                end_ns: None,
                grid: None,
                block: None,
                bytes: None,
                memcpy_kind: None,
            }),
            nvtx: None,
            attributes: BTreeMap::new(),
        }
    }

    fn nvtx_event(
        event_type: EventType,
        timestamp: u64,
        tid: u32,
        range_kind: NvtxRangeKind,
        range_id: u64,
        start_tid: u32,
    ) -> Event {
        let mut event = event(event_type, timestamp, 0);
        event.source = EventSource::CuptiCallback;
        event.clock_domain = ClockDomain::HostMonotonic;
        event.tid = tid;
        event.cuda = None;
        event.nvtx = Some(NvtxEvent {
            name: "forward".to_owned(),
            name_complete: true,
            range_kind,
            range_id,
            start_tid,
        });
        event
    }

    fn options(policy: MatchPolicy) -> MeasureOptions {
        MeasureOptions {
            session_id: "xp_test".to_owned(),
            name: Some("kernel_duration".to_owned()),
            start_selector: "cuda:kernel_start:name~test.*".to_owned(),
            end_selector: "cuda:kernel_end:name~test.*".to_owned(),
            match_policy: policy,
            samples: Some(2),
            duration: None,
            max_events: 100,
            dropped_events: 0,
        }
    }

    fn memcpy_event(
        event_type: EventType,
        timestamp: u64,
        correlation_id: u32,
        kind: MemcpyKind,
    ) -> Event {
        let mut event = event(event_type, timestamp, correlation_id);
        let cuda = event.cuda.as_mut().expect("CUDA payload");
        cuda.kernel_name = None;
        cuda.bytes = Some(4096);
        cuda.memcpy_kind = Some(kind);
        event
    }

    fn host_event(timestamp: u64) -> Event {
        let mut event = event(EventType::HostFunctionEntry, timestamp, 0);
        event.source = EventSource::Ebpf;
        event.clock_domain = ClockDomain::HostMonotonic;
        event.cuda = None;
        event.host = Some(HostEvent {
            probe_kind: HostProbeKind::Uprobe,
            binary_path: Some("/srv/libserver.so".to_owned()),
            build_id: None,
            symbol: Some("handle_request".to_owned()),
            symbol_demangled: None,
            offset: None,
            return_value: None,
            arguments: Vec::new(),
        });
        event
    }

    fn syscall_event(event_type: EventType, timestamp: u64, tid: u32, name: &str) -> Event {
        let mut event = event(event_type, timestamp, 0);
        event.source = EventSource::Ebpf;
        event.clock_domain = ClockDomain::HostMonotonic;
        event.tid = tid;
        event.process_start_time = Some(42);
        event.cuda = None;
        event.host = Some(HostEvent {
            probe_kind: HostProbeKind::Syscall,
            binary_path: None,
            build_id: None,
            symbol: Some(name.to_owned()),
            symbol_demangled: None,
            offset: None,
            return_value: (event.event_type == EventType::SyscallExit).then_some(0),
            arguments: Vec::new(),
        });
        event
    }

    fn python_gc_event(event_type: EventType, timestamp: u64, tid: u32) -> Event {
        let marker = match event_type {
            EventType::PythonGcStart => "gc__start",
            EventType::PythonGcEnd => "gc__done",
            _ => panic!("Python GC fixture requires a GC boundary"),
        };
        let mut event = syscall_event(event_type, timestamp, tid, marker);
        event.host.as_mut().unwrap().probe_kind = HostProbeKind::Usdt;
        event.host.as_mut().unwrap().binary_path = Some("/usr/bin/python3".to_owned());
        event.attributes.insert(
            "usdt_provider".to_owned(),
            serde_json::Value::String("python".to_owned()),
        );
        event
    }

    #[test]
    fn exact_matching_uses_cupti_correlation_ids() {
        let events = vec![
            event(EventType::GpuKernelEnd, 280, 2),
            event(EventType::GpuKernelStart, 100, 1),
            event(EventType::GpuKernelEnd, 150, 1),
            event(EventType::GpuKernelStart, 200, 2),
        ];
        let result = measure(&events, &options(MatchPolicy::Exact)).unwrap();
        assert_eq!(result.measurement.samples.matched, 2);
        assert_eq!(result.measurement.latency_ns.min, 50);
        assert_eq!(result.measurement.latency_ns.max, 80);
        assert_eq!(result.correlation.method, "exact_cupti_correlation_id");
    }

    #[test]
    fn exact_matching_pairs_reused_ids_in_timestamp_order() {
        let events = vec![
            event(EventType::GpuKernelStart, 100, 7),
            event(EventType::GpuKernelEnd, 150, 7),
            event(EventType::GpuKernelStart, 200, 7),
            event(EventType::GpuKernelEnd, 280, 7),
        ];

        let result = measure(&events, &options(MatchPolicy::Exact)).unwrap();
        assert_eq!(result.measurement.samples.matched, 2);
        assert_eq!(result.measurement.latency_ns.min, 50);
        assert_eq!(result.measurement.latency_ns.max, 80);
    }

    #[test]
    fn exact_syscall_matching_follows_thread_lifecycle() {
        let events = vec![
            syscall_event(EventType::SyscallEntry, 100, 10, "mmap"),
            syscall_event(EventType::SyscallEntry, 110, 20, "mmap"),
            syscall_event(EventType::SyscallExit, 150, 20, "mmap"),
            syscall_event(EventType::SyscallExit, 180, 10, "mmap"),
        ];
        let options = MeasureOptions {
            session_id: "xp_syscall".to_owned(),
            name: Some("mmap".to_owned()),
            start_selector: "syscall:mmap:entry".to_owned(),
            end_selector: "syscall:mmap:exit".to_owned(),
            match_policy: MatchPolicy::Exact,
            samples: Some(2),
            duration: None,
            max_events: 100,
            dropped_events: 0,
        };

        let result = measure(&events, &options).unwrap();
        assert_eq!(result.measurement.samples.matched, 2);
        assert_eq!(result.measurement.latency_ns.min, 40);
        assert_eq!(result.measurement.latency_ns.max, 80);
        assert_eq!(result.correlation.method, "exact_syscall_tid_lifecycle");
        assert_eq!(result.correlation.confidence, CorrelationConfidence::Exact);
        assert_eq!(result.evidence.pairs.as_ref().unwrap()[0].start.tid, 10);
        assert_eq!(result.evidence.pairs.as_ref().unwrap()[0].end.tid, 10);
    }

    #[test]
    fn exact_python_gc_matching_follows_thread_lifecycle() {
        let events = vec![
            python_gc_event(EventType::PythonGcStart, 100, 10),
            python_gc_event(EventType::PythonGcStart, 110, 20),
            python_gc_event(EventType::PythonGcEnd, 160, 20),
            python_gc_event(EventType::PythonGcEnd, 190, 10),
        ];
        let options = MeasureOptions {
            session_id: "xp_python_gc".to_owned(),
            name: Some("python_gc".to_owned()),
            start_selector: "python:gc_start".to_owned(),
            end_selector: "python:gc_end".to_owned(),
            match_policy: MatchPolicy::Exact,
            samples: Some(2),
            duration: None,
            max_events: 100,
            dropped_events: 0,
        };

        let result = measure(&events, &options).unwrap();
        assert_eq!(result.measurement.samples.matched, 2);
        assert_eq!(result.measurement.latency_ns.min, 50);
        assert_eq!(result.measurement.latency_ns.max, 90);
        assert_eq!(result.correlation.method, "exact_python_gc_tid_lifecycle");
        assert_eq!(result.correlation.confidence, CorrelationConfidence::Exact);
    }

    #[test]
    fn exact_nvtx_matching_uses_kind_and_range_id() {
        let events = vec![
            nvtx_event(
                EventType::NvtxRangeStart,
                100,
                10,
                NvtxRangeKind::Thread,
                7,
                10,
            ),
            nvtx_event(
                EventType::NvtxRangeStart,
                110,
                20,
                NvtxRangeKind::Process,
                7,
                20,
            ),
            nvtx_event(
                EventType::NvtxRangeEnd,
                160,
                30,
                NvtxRangeKind::Process,
                7,
                20,
            ),
            nvtx_event(
                EventType::NvtxRangeEnd,
                180,
                10,
                NvtxRangeKind::Thread,
                7,
                10,
            ),
            nvtx_event(
                EventType::NvtxRangeStart,
                200,
                10,
                NvtxRangeKind::Thread,
                7,
                10,
            ),
        ];
        let options = MeasureOptions {
            session_id: "xp_nvtx".to_owned(),
            name: Some("forward".to_owned()),
            start_selector: "cuda:nvtx_range_start:name~^forward$".to_owned(),
            end_selector: "cuda:nvtx_range_end:name~^forward$".to_owned(),
            match_policy: MatchPolicy::Exact,
            samples: Some(2),
            duration: None,
            max_events: 100,
            dropped_events: 0,
        };

        let result = measure(&events, &options).unwrap();
        assert_eq!(result.measurement.samples.matched, 2);
        assert_eq!(result.measurement.samples.unmatched_start, 1);
        assert_eq!(result.measurement.latency_ns.min, 50);
        assert_eq!(result.measurement.latency_ns.max, 80);
        assert_eq!(result.correlation.method, "exact_nvtx_range_id");
        assert_eq!(result.evidence.pairs.as_ref().unwrap()[0].end.tid, 10);
        assert_eq!(result.evidence.pairs.as_ref().unwrap()[1].end.tid, 30);
    }

    #[test]
    fn exact_syscall_matching_does_not_cross_process_identity() {
        let mut exit = syscall_event(EventType::SyscallExit, 150, 10, "munmap");
        exit.process_start_time = Some(43);
        let events = vec![
            syscall_event(EventType::SyscallEntry, 100, 10, "munmap"),
            exit,
        ];
        let options = MeasureOptions {
            session_id: "xp_syscall".to_owned(),
            name: None,
            start_selector: "syscall:munmap:entry".to_owned(),
            end_selector: "syscall:munmap:exit".to_owned(),
            match_policy: MatchPolicy::Exact,
            samples: Some(1),
            duration: None,
            max_events: 100,
            dropped_events: 0,
        };

        assert_eq!(
            measure(&events, &options).unwrap_err(),
            MeasureError::NoMatchedSamples
        );
    }

    #[test]
    fn exact_matching_never_pairs_across_cuda_contexts() {
        let mut events = vec![
            event(EventType::GpuKernelStart, 100, 7),
            event(EventType::GpuKernelEnd, 150, 7),
            event(EventType::GpuKernelStart, 200, 7),
            event(EventType::GpuKernelEnd, 280, 7),
        ];
        events[2].cuda.as_mut().unwrap().context_id = Some(2);
        events[3].cuda.as_mut().unwrap().context_id = Some(2);

        let result = measure(&events, &options(MatchPolicy::Exact)).unwrap();
        assert_eq!(result.measurement.samples.matched, 2);
        assert_eq!(result.measurement.latency_ns.min, 50);
        assert_eq!(result.measurement.latency_ns.max, 80);
    }

    #[test]
    fn launch_api_pairs_runtime_and_driver_launches_with_their_kernels() {
        let api = |timestamp, correlation_id, domain: &str, name: &str| {
            let mut event = event(EventType::CudaApiExit, timestamp, correlation_id);
            event.source = EventSource::CuptiCallback;
            event.clock_domain = ClockDomain::HostMonotonic;
            event.attributes.insert(
                "cuda_api_domain".to_owned(),
                serde_json::Value::String(domain.to_owned()),
            );
            event.attributes.insert(
                "cuda_api_name".to_owned(),
                serde_json::Value::String(name.to_owned()),
            );
            event
        };
        let kernel = |timestamp, correlation_id| {
            let mut event = event(EventType::GpuKernelStart, timestamp, correlation_id);
            event.clock_domain = ClockDomain::CuptiNormalizedToHostMonotonic;
            event
        };
        let events = vec![
            api(95, 1, "driver_api", "cuLaunchKernel"),
            api(100, 1, "runtime_api", "cudaLaunchKernel"),
            kernel(130, 1),
            api(200, 2, "driver_api", "cuLaunchKernelEx"),
            kernel(260, 2),
            api(300, 3, "driver_api", "cuLaunchKernel_ptsz"),
            kernel(390, 3),
            api(400, 4, "driver_api", "cuLaunchHostFunc"),
            api(410, 4, "runtime_api", "cuLaunchKernel"),
            kernel(450, 4),
        ];
        let mut options = options(MatchPolicy::Exact);
        options.start_selector = "cuda:launch_api:exit".to_owned();
        options.samples = None;
        options.duration = Some(Duration::from_secs(1));
        options.end_selector = "cuda:kernel_start:name~test.*".to_owned();

        let result = measure(&events, &options).unwrap();
        assert_eq!(result.measurement.samples.matched, 3);
        assert_eq!(result.measurement.samples.ambiguous, 0);
        assert_eq!(result.measurement.latency_ns.min, 30);
        assert_eq!(result.measurement.latency_ns.max, 90);
        assert_eq!(
            result.evidence.pairs.as_ref().unwrap()[0].start.attributes["cuda_api_name"],
            "cudaLaunchKernel"
        );

        options.start_selector = "cuda:launch_api:cuLaunchKernel:exit".to_owned();
        assert!(matches!(
            measure(&events, &options),
            Err(MeasureError::InvalidSelector(_))
        ));
    }

    #[test]
    fn exact_matching_filters_memcpy_kind() {
        let events = vec![
            memcpy_event(EventType::GpuMemcpyStart, 100, 1, MemcpyKind::HostToDevice),
            memcpy_event(EventType::GpuMemcpyEnd, 160, 1, MemcpyKind::HostToDevice),
            memcpy_event(EventType::GpuMemcpyStart, 200, 2, MemcpyKind::DeviceToHost),
            memcpy_event(EventType::GpuMemcpyEnd, 290, 2, MemcpyKind::DeviceToHost),
        ];
        let mut options = options(MatchPolicy::Exact);
        options.start_selector = "cuda:memcpy_start:kind=HtoD".to_owned();
        options.end_selector = "cuda:memcpy_end:kind=HtoD".to_owned();
        options.samples = Some(1);

        let result = measure(&events, &options).unwrap();
        assert_eq!(result.measurement.samples.matched, 1);
        assert_eq!(result.measurement.latency_ns.min, 60);
    }

    #[test]
    fn first_after_is_greedy_bounded_and_heuristic() {
        let events = vec![
            event(EventType::GpuKernelStart, 100, 1),
            event(EventType::GpuKernelStart, 200, 2),
            event(EventType::GpuKernelEnd, 150, 9),
            event(EventType::GpuKernelEnd, 260, 8),
        ];
        let mut options = options(MatchPolicy::FirstAfter);
        options.samples = Some(1);
        let result = measure(&events, &options).unwrap();
        assert_eq!(result.measurement.samples.matched, 1);
        assert_eq!(result.measurement.latency_ns.min, 50);
        assert_eq!(
            result.correlation.confidence,
            xprobe_protocol::CorrelationConfidence::Heuristic
        );
        assert_eq!(result.warnings[0].code, "HEURISTIC_CORRELATION");
    }

    #[test]
    fn rejects_cross_domain_subtraction() {
        let mut events = vec![
            event(EventType::GpuKernelStart, 100, 1),
            event(EventType::GpuKernelEnd, 150, 1),
        ];
        events[1].clock_domain = ClockDomain::HostMonotonic;
        assert!(matches!(
            measure(&events, &options(MatchPolicy::Exact)),
            Err(MeasureError::ClockDomainsDiffer { .. })
        ));
    }

    #[test]
    fn accepts_cupti_timestamps_normalized_to_host_monotonic() {
        let mut events = vec![
            event(EventType::GpuKernelStart, 100, 1),
            event(EventType::GpuKernelEnd, 150, 1),
        ];
        events[0].clock_domain = ClockDomain::HostMonotonic;
        events[1].clock_domain = ClockDomain::CuptiNormalizedToHostMonotonic;
        events[1].timestamp_error_ns = Some(7);

        let result = measure(&events, &options(MatchPolicy::Exact)).unwrap();
        assert_eq!(result.clock.alignment, "cupti_normalized_to_host_monotonic");
        assert_eq!(result.clock.estimated_error_ns, Some(7));
        assert_eq!(result.warnings, Vec::<xprobe_protocol::Warning>::new());
    }

    #[test]
    fn first_after_measures_host_to_normalized_gpu_latency() {
        let mut kernel = event(EventType::GpuKernelStart, 175, 1);
        kernel.clock_domain = ClockDomain::CuptiNormalizedToHostMonotonic;
        let events = vec![host_event(100), kernel];
        let mut options = options(MatchPolicy::FirstAfter);
        options.start_selector = "uprobe:/srv/libserver.so:handle_request:entry".to_owned();
        options.end_selector = "cuda:kernel_start:name~test.*".to_owned();
        options.samples = Some(1);

        let result = measure(&events, &options).unwrap();
        assert_eq!(result.measurement.latency_ns.min, 75);
        assert_eq!(result.collection.host_events, 1);
        assert_eq!(result.collection.cuda_events, 1);
        assert_eq!(
            result.correlation.confidence,
            CorrelationConfidence::Heuristic
        );
    }

    #[test]
    fn exact_rejects_host_selectors_without_a_correlation_key() {
        let events = vec![host_event(100), event(EventType::GpuKernelStart, 175, 1)];
        let mut options = options(MatchPolicy::Exact);
        options.start_selector = "uprobe:/srv/libserver.so:handle_request:entry".to_owned();
        options.end_selector = "cuda:kernel_start:name~test.*".to_owned();
        assert!(matches!(
            measure(&events, &options),
            Err(MeasureError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn duration_window_is_required_when_samples_are_absent() {
        let events = vec![
            event(EventType::GpuKernelStart, 100, 1),
            event(EventType::GpuKernelEnd, 150, 1),
        ];
        let mut options = options(MatchPolicy::Exact);
        options.samples = None;
        options.duration = Some(Duration::from_nanos(100));
        assert_eq!(
            measure(&events, &options)
                .unwrap()
                .measurement
                .samples
                .matched,
            1
        );
    }

    #[test]
    fn nearest_consumes_each_end_once() {
        let events = vec![
            event(EventType::GpuKernelStart, 100, 1),
            event(EventType::GpuKernelStart, 210, 2),
            event(EventType::GpuKernelEnd, 90, 9),
            event(EventType::GpuKernelEnd, 230, 8),
        ];
        let result = measure(&events, &options(MatchPolicy::Nearest)).unwrap();
        assert_eq!(result.measurement.samples.matched, 2);
        assert_eq!(result.measurement.latency_ns.min, 10);
        assert_eq!(result.measurement.latency_ns.max, 20);
        assert_eq!(result.correlation.method, "nearest");
        assert_eq!(result.warnings[0].code, "HEURISTIC_CORRELATION");
    }

    #[test]
    fn stack_nested_pairs_host_returns_lifo_per_thread() {
        let entries = [host_event(100), host_event(120)];
        let mut first_exit = host_event(150);
        first_exit.event_type = EventType::HostFunctionExit;
        first_exit.host.as_mut().expect("host payload").probe_kind = HostProbeKind::Uretprobe;
        let mut second_exit = host_event(200);
        second_exit.event_type = EventType::HostFunctionExit;
        second_exit.host.as_mut().expect("host payload").probe_kind = HostProbeKind::Uretprobe;
        let events = vec![
            entries[0].clone(),
            entries[1].clone(),
            first_exit,
            second_exit,
        ];
        let mut options = options(MatchPolicy::StackNested);
        options.start_selector = "uprobe:/srv/libserver.so:handle_request:entry".to_owned();
        options.end_selector = "uprobe:/srv/libserver.so:handle_request:return".to_owned();

        let result = measure(&events, &options).unwrap();
        assert_eq!(result.measurement.samples.matched, 2);
        assert_eq!(result.measurement.latency_ns.min, 30);
        assert_eq!(result.measurement.latency_ns.max, 100);
        assert_eq!(result.correlation.method, "stack_nested_tid_lifo");
        assert_eq!(result.correlation.confidence, CorrelationConfidence::High);
    }

    #[test]
    fn demangled_cpp_selectors_match_mangled_host_events() {
        let mut entry = host_event(100);
        entry.host.as_mut().unwrap().symbol =
            Some("_ZN14xprobe_fixture15native_operatorEl".to_owned());
        entry.host.as_mut().unwrap().symbol_demangled =
            Some("xprobe_fixture::native_operator(long)".to_owned());
        let mut exit = entry.clone();
        exit.timestamp_raw = 160;
        exit.timestamp_ns = 160;
        exit.event_type = EventType::HostFunctionExit;
        exit.host.as_mut().unwrap().probe_kind = HostProbeKind::Uretprobe;
        let mut options = options(MatchPolicy::StackNested);
        options.start_selector =
            "uprobe:/srv/libserver.so:symbol=xprobe_fixture::native_operator(long):entry"
                .to_owned();
        options.end_selector =
            "uprobe:/srv/libserver.so:symbol=xprobe_fixture::native_operator(long):return"
                .to_owned();
        options.samples = Some(1);

        let result = measure(&[entry, exit], &options).unwrap();
        assert_eq!(result.measurement.samples.matched, 1);
        assert_eq!(result.measurement.latency_ns.min, 60);
    }

    /// One activity's start and end on `stream`, as the Agent records them.
    fn activity(
        kinds: (EventType, EventType),
        span: (u64, u64),
        stream: u64,
        name: &str,
        correlation_id: u32,
    ) -> [Event; 2] {
        [(kinds.0, span.0), (kinds.1, span.1)].map(|(kind, timestamp)| {
            let mut event = event(kind, timestamp, correlation_id);
            let cuda = event.cuda.as_mut().expect("CUDA payload");
            cuda.stream_id = Some(stream);
            cuda.kernel_name = Some(name.to_owned());
            event
        })
    }

    fn kernel(start: u64, end: u64, stream: u64, name: &str, correlation_id: u32) -> [Event; 2] {
        activity(
            (EventType::GpuKernelStart, EventType::GpuKernelEnd),
            (start, end),
            stream,
            name,
            correlation_id,
        )
    }

    fn stream_order(from: &str, to: &str) -> MeasureOptions {
        let mut options = options(MatchPolicy::StreamOrder);
        options.start_selector = from.to_owned();
        options.end_selector = to.to_owned();
        options.samples = None;
        options.duration = Some(Duration::from_secs(1));
        options
    }

    fn gaps(result: &xprobe_protocol::MeasurementResult) -> Vec<(String, String, u64)> {
        let name = |event: &Event| {
            event
                .cuda
                .as_ref()
                .and_then(|cuda| cuda.kernel_name.clone())
                .unwrap_or_default()
        };
        result
            .evidence
            .pairs
            .as_ref()
            .expect("full evidence")
            .iter()
            .map(|pair| (name(&pair.start), name(&pair.end), pair.latency_ns))
            .collect()
    }

    #[test]
    fn stream_order_pairs_each_end_with_the_next_activity_on_its_stream() {
        // A B flash1 C D flash2 on one stream, 2 ns apart: a narrower end
        // selector must not skip over the kernels in between.
        let events = [
            kernel(0, 10, 2, "A", 1),
            kernel(12, 20, 2, "B", 2),
            kernel(22, 30, 2, "flash1", 3),
            kernel(32, 40, 2, "C", 4),
            kernel(42, 50, 2, "D", 5),
            kernel(52, 60, 2, "flash2", 6),
        ]
        .concat();
        let result = measure(
            &events,
            &stream_order("cuda:kernel_end", "cuda:kernel_start:name~^flash"),
        )
        .unwrap();

        assert_eq!(
            gaps(&result),
            [
                ("B".to_owned(), "flash1".to_owned(), 2),
                ("D".to_owned(), "flash2".to_owned(), 2)
            ]
        );
        assert_eq!(result.measurement.samples.unmatched_start, 4);
        assert_eq!(result.measurement.samples.unmatched_end, 0);
        assert_eq!(result.correlation.method, "cuda_stream_order");
        assert_eq!(result.correlation.confidence, CorrelationConfidence::High);
    }

    #[test]
    fn stream_order_keeps_zero_duration_activity_between_its_neighbours() {
        // B starts and ends at 10 ns, exactly when A ends and C starts.
        let events = [
            kernel(0, 10, 2, "A", 1),
            kernel(10, 10, 2, "B", 2),
            kernel(10, 20, 2, "C", 3),
            kernel(30, 40, 2, "D", 4),
        ]
        .concat();
        // Sequences follow the Agent's write order: each start, then its end.
        let events = events
            .into_iter()
            .zip(0..)
            .map(|(event, sequence)| Event { sequence, ..event })
            .collect::<Vec<_>>();
        let result = measure(
            &events,
            &stream_order("cuda:kernel_end", "cuda:kernel_start"),
        )
        .unwrap();

        assert_eq!(
            gaps(&result),
            [
                ("A".to_owned(), "B".to_owned(), 0),
                ("B".to_owned(), "C".to_owned(), 0),
                ("C".to_owned(), "D".to_owned(), 10)
            ]
        );
        assert_eq!(result.measurement.samples.ambiguous, 0);
    }

    #[test]
    fn stream_order_keeps_back_to_back_runs_of_one_graph_kernel() {
        // One graph node runs twice back to back under one correlation ID.
        let events = [
            kernel(0, 10, 2, "node", 7),
            kernel(10, 20, 2, "node", 7),
            kernel(25, 30, 2, "node", 7),
        ]
        .concat();
        let result = measure(
            &events,
            &stream_order("cuda:kernel_end", "cuda:kernel_start"),
        )
        .unwrap();
        assert_eq!(
            gaps(&result),
            [
                ("node".to_owned(), "node".to_owned(), 0),
                ("node".to_owned(), "node".to_owned(), 5)
            ]
        );
    }

    #[test]
    fn stream_order_successors_include_unselected_copies_but_not_other_streams() {
        let mut events = [
            kernel(0, 10, 2, "A", 1),
            activity(
                (EventType::GpuMemcpyStart, EventType::GpuMemcpyEnd),
                (12, 20),
                2,
                "",
                2,
            ),
            kernel(22, 30, 2, "B", 3),
            // A kernel on another stream between A and the copy is not A's
            // successor.
            kernel(11, 11, 3, "other", 4),
        ]
        .concat();
        events.sort_by_key(|event| event.timestamp_ns);

        // A is followed by the copy, not by B.
        assert!(matches!(
            measure(
                &events,
                &stream_order("cuda:kernel_end", "cuda:kernel_start")
            ),
            Err(MeasureError::NoMatchedSamples)
        ));
        let to_copy = measure(
            &events,
            &stream_order("cuda:kernel_end", "cuda:memcpy_start"),
        )
        .unwrap();
        assert_eq!(to_copy.measurement.samples.matched, 1);
        assert_eq!(to_copy.measurement.latency_ns.min, 2);
        let from_copy = measure(
            &events,
            &stream_order("cuda:memcpy_end", "cuda:kernel_start"),
        )
        .unwrap();
        assert_eq!(gaps(&from_copy), [(String::new(), "B".to_owned(), 2)]);
    }

    #[test]
    fn stream_order_counts_overlap_ties_and_truncated_names() {
        let long = "k".repeat(xprobe_protocol::CUDA_RECORD_NAME_MAX_BYTES);
        let events = [
            kernel(0, 10, 2, "A", 1),
            kernel(5, 15, 2, "B", 2),
            kernel(20, 30, 2, "C", 3),
            kernel(20, 25, 2, "D", 4),
            kernel(40, 50, 2, "E", 5),
            kernel(50, 60, 2, "flash", 6),
            kernel(70, 80, 2, "F", 7),
            kernel(85, 90, 2, &long, 8),
        ]
        .concat();
        let result = measure(
            &events,
            &stream_order("cuda:kernel_end", "cuda:kernel_start:name~flash$"),
        )
        .unwrap();
        // E.end == flash.start is a valid zero gap.
        assert_eq!(gaps(&result), [("E".to_owned(), "flash".to_owned(), 0)]);
        let samples = &result.measurement.samples;
        // A and D end while another kernel runs, B is followed by tied C and
        // D, and F's successor name is truncated and may still end in "flash".
        assert_eq!(samples.ambiguous, 4);
        // C and flash are followed by unselected kernels; the long kernel
        // ends the capture.
        assert_eq!(samples.unmatched_start, 3);
    }

    #[test]
    fn activity_without_a_captured_start_hides_the_gaps_it_overlaps() {
        let boundary = |kind, timestamp, correlation_id| {
            let mut event = event(kind, timestamp, correlation_id);
            event.cuda.as_mut().expect("CUDA payload").stream_id = Some(2);
            event
        };
        // B runs 5-30; A's start was trimmed, so A.end at 10 is no gap.
        let trimmed = [
            boundary(EventType::GpuKernelStart, 5, 2),
            boundary(EventType::GpuKernelEnd, 10, 1),
            boundary(EventType::GpuKernelStart, 15, 3),
            boundary(EventType::GpuKernelEnd, 30, 2),
        ];
        assert_eq!(super::spans::stream_gaps(&trimmed).len(), 0);

        // B started before the capture and ended at 30: every gap before 30
        // may overlap it; only the 35-40 gap after it is idle.
        let started_earlier = [
            boundary(EventType::GpuKernelStart, 0, 1),
            boundary(EventType::GpuKernelEnd, 10, 1),
            boundary(EventType::GpuKernelStart, 15, 3),
            boundary(EventType::GpuKernelEnd, 20, 3),
            boundary(EventType::GpuKernelEnd, 30, 2),
            boundary(EventType::GpuKernelStart, 32, 4),
            boundary(EventType::GpuKernelEnd, 35, 4),
            boundary(EventType::GpuKernelStart, 40, 5),
        ];
        let gaps = super::spans::stream_gaps(&started_earlier)
            .iter()
            .map(|span| (span.start.timestamp_ns, span.end.timestamp_ns))
            .collect::<Vec<_>>();
        assert_eq!(gaps, [(35, 40)]);
    }

    #[test]
    fn stream_order_rejects_anything_but_an_end_followed_by_a_start() {
        let events = kernel(0, 10, 2, "A", 1);
        for (from, to) in [
            ("cuda:kernel_start", "cuda:kernel_end"),
            ("cuda:kernel_start", "cuda:kernel_start"),
            ("cuda:kernel_end", "cuda:kernel_end"),
        ] {
            assert!(
                matches!(
                    measure(&events, &stream_order(from, to)),
                    Err(MeasureError::InvalidPolicy(_))
                ),
                "{from} -> {to}"
            );
        }
    }

    #[test]
    fn samples_limit_keeps_the_earliest_pairs_and_scores_the_whole_window() {
        let events = (0_u32..4)
            .flat_map(|index| {
                let start = u64::from(index) * 20;
                kernel(start, start + 10, 2, "k", index + 1)
            })
            .collect::<Vec<_>>();
        let mut options = stream_order("cuda:kernel_end", "cuda:kernel_start");
        options.samples = Some(2);
        let result = measure(&events, &options).unwrap();

        assert_eq!(result.measurement.samples.matched, 2);
        // Three gaps matched in the window; the last end has no successor
        // and the first start no predecessor.
        assert_eq!(result.measurement.samples.unmatched_start, 1);
        assert_eq!(result.measurement.samples.unmatched_end, 1);
        assert!((result.correlation.score - 3.0 / 5.0).abs() < f64::EPSILON);
        assert_eq!(
            result.evidence.pairs.as_ref().unwrap()[0]
                .start
                .timestamp_ns,
            10
        );
    }
}
