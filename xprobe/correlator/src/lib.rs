//! Cross-domain event correlation and latency statistics.

use std::{collections::BTreeMap, error::Error, fmt, time::Duration};

use regex::Regex;
use xprobe_protocol::{
    ClockDomain, ClockQuality, CollectionSummary, CorrelationConfidence, CorrelationSummary,
    ErrorCode, Event, EventSource, EventType, HostProbeKind, LatencyStatistics, MatchPolicy,
    Measurement, MeasurementResult, MemcpyKind, SampleSummary, SchemaVersion, SessionStatus,
    Warning,
};

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
    Api {
        event_type: EventType,
        domain: String,
        name: String,
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
        let fields: Vec<&str> = text.splitn(3, ':').collect();
        if fields.first() != Some(&"cuda") || fields.len() < 2 {
            return Err(MeasureError::InvalidSelector(
                "completed captures require a uprobe: or cuda: selector".to_owned(),
            ));
        }
        match fields[1] {
            "runtime_api" | "driver_api" => Self::parse_api(text),
            "kernel_start" | "kernel_end" => Self::parse_kernel(&fields),
            "memcpy_start" | "memcpy_end" => Self::parse_memcpy(&fields),
            "memset_start" | "memset_end" => Self::parse_memset(text, &fields),
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
        let (binary_path, target) = binary_and_target.rsplit_once(':').ok_or_else(|| {
            MeasureError::InvalidSelector(
                "uprobe selector requires a binary path and symbol or offset".to_owned(),
            )
        })?;
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
                    && event
                        .attributes
                        .get("cuda_api_name")
                        .and_then(serde_json::Value::as_str)
                        == Some(name)
                    && event
                        .attributes
                        .get("cuda_api_domain")
                        .and_then(serde_json::Value::as_str)
                        == Some(domain)
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
        }
    }

    const fn supports_exact(&self) -> bool {
        !matches!(self, Self::Host { .. })
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

    const fn is_gpu_activity(&self) -> bool {
        matches!(
            self,
            Self::Kernel { .. } | Self::Memcpy { .. } | Self::Memset { .. }
        )
    }
}

#[derive(Debug)]
struct Outcome {
    latencies: Vec<u64>,
    unmatched_start: u64,
    unmatched_end: u64,
    ambiguous: u64,
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
    let start_selector = Selector::parse(&options.start_selector)?;
    let end_selector = Selector::parse(&options.end_selector)?;
    validate_policy(&start_selector, &end_selector, options.match_policy)?;
    let mut starts: Vec<&Event> = events
        .iter()
        .filter(|event| start_selector.matches(event))
        .collect();
    let mut ends: Vec<&Event> = events
        .iter()
        .filter(|event| end_selector.matches(event))
        .collect();
    starts.sort_by_key(|event| event.timestamp_ns);
    ends.sort_by_key(|event| event.timestamp_ns);
    let clock_domain = common_clock_domain(&starts, &ends)?;
    apply_duration_window(&mut starts, &mut ends, options.duration)?;

    let outcome = match options.match_policy {
        MatchPolicy::Exact => correlate_exact(&starts, &ends, options.samples),
        MatchPolicy::FirstAfter => correlate_first_after(&starts, &ends, options.samples),
        MatchPolicy::Nearest => correlate_nearest(&starts, &ends, options.samples),
        MatchPolicy::StackNested => correlate_stack_nested(&starts, &ends, options.samples),
        MatchPolicy::StreamOrder => correlate_stream_order(&starts, &ends, options.samples),
    };
    if outcome.latencies.is_empty() {
        return Err(MeasureError::NoMatchedSamples);
    }

    let matched = outcome.latencies.len() as u64;
    let denominator = matched + outcome.unmatched_start + outcome.unmatched_end + outcome.ambiguous;
    let (method, confidence) = correlation_metadata(options.match_policy);
    let warnings = measurement_warnings(options, &starts, &ends);

    let host_events = events
        .iter()
        .filter(|event| event.source == EventSource::Ebpf)
        .count() as u64;
    let cuda_events = events.len() as u64 - host_events;
    Ok(MeasurementResult {
        schema_version: SchemaVersion::current(),
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
            latency_ns: statistics(&outcome.latencies),
        },
        correlation: CorrelationSummary {
            method: method.to_owned(),
            confidence,
            score: ratio(matched, denominator),
        },
        clock: ClockQuality {
            alignment: match clock_domain {
                ClockDomain::HostMonotonic => "host_monotonic",
                ClockDomain::Cupti => "cupti_same_domain",
                ClockDomain::CuptiNormalizedToHostMonotonic => "cupti_normalized_to_host_monotonic",
            }
            .to_owned(),
            estimated_error_ns: maximum_timestamp_error(&starts, &ends),
        },
        collection: CollectionSummary {
            host_events,
            cuda_events,
            dropped_events: options.dropped_events,
        },
        warnings,
    })
}

fn validate_policy(
    start: &Selector,
    end: &Selector,
    policy: MatchPolicy,
) -> Result<(), MeasureError> {
    let message = match policy {
        MatchPolicy::Exact if !start.supports_exact() || !end.supports_exact() => {
            Some("exact matching requires CUDA endpoints with a deterministic correlation ID")
        }
        MatchPolicy::StackNested if !start.supports_stack_nested(end) => {
            Some("stack-nested requires entry and return selectors for the same host function")
        }
        MatchPolicy::StreamOrder if !start.is_gpu_activity() || !end.is_gpu_activity() => {
            Some("stream-order requires two GPU activity selectors")
        }
        _ => None,
    };
    if let Some(message) = message {
        return Err(MeasureError::InvalidPolicy(message.to_owned()));
    }
    Ok(())
}

const fn correlation_metadata(policy: MatchPolicy) -> (&'static str, CorrelationConfidence) {
    match policy {
        MatchPolicy::Exact => ("exact_cupti_correlation_id", CorrelationConfidence::Exact),
        MatchPolicy::FirstAfter => ("first_after", CorrelationConfidence::Heuristic),
        MatchPolicy::Nearest => ("nearest", CorrelationConfidence::Heuristic),
        MatchPolicy::StackNested => ("stack_nested_tid_lifo", CorrelationConfidence::High),
        MatchPolicy::StreamOrder => ("cuda_stream_order", CorrelationConfidence::High),
    }
}

fn validate_options(options: &MeasureOptions) -> Result<(), MeasureError> {
    if options.samples.is_none() && options.duration.is_none() {
        return Err(MeasureError::InvalidLimit(
            "at least one of samples or duration must be set".to_owned(),
        ));
    }
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
    if options.dropped_events != 0 {
        warnings.push(warning(
            "EVENTS_DROPPED",
            "the source capture dropped events before correlation",
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

fn correlate_exact(starts: &[&Event], ends: &[&Event], limit: Option<usize>) -> Outcome {
    let mut start_groups: BTreeMap<u32, Vec<&Event>> = BTreeMap::new();
    let mut end_groups: BTreeMap<u32, Vec<&Event>> = BTreeMap::new();
    let mut unmatched_start = 0_u64;
    let mut unmatched_end = 0_u64;
    for event in starts {
        if let Some(key) = correlation_id(event) {
            start_groups.entry(key).or_default().push(event);
        } else {
            unmatched_start += 1;
        }
    }
    for event in ends {
        if let Some(key) = correlation_id(event) {
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
        if group.len() != 1 || end_group.len() != 1 {
            ambiguous += group.len().max(end_group.len()) as u64;
            continue;
        }
        let start = group[0];
        let end = end_group[0];
        if let Some(latency) = end.timestamp_ns.checked_sub(start.timestamp_ns) {
            pairs.push((start.timestamp_ns, latency));
        } else {
            unmatched_start += 1;
            unmatched_end += 1;
        }
    }
    unmatched_end += end_groups.values().map(Vec::len).sum::<usize>() as u64;
    pairs.sort_by_key(|(timestamp, _)| *timestamp);
    if let Some(limit) = limit {
        pairs.truncate(limit);
    }
    Outcome {
        latencies: pairs.into_iter().map(|(_, latency)| latency).collect(),
        unmatched_start,
        unmatched_end,
        ambiguous,
    }
}

fn correlate_first_after(starts: &[&Event], ends: &[&Event], limit: Option<usize>) -> Outcome {
    let limit = limit.unwrap_or(usize::MAX);
    let mut latencies = Vec::new();
    let mut unmatched_start = 0_u64;
    let mut unmatched_end = 0_u64;
    let mut end_index = 0;
    for (start_index, start) in starts.iter().enumerate() {
        if latencies.len() == limit {
            break;
        }
        while end_index < ends.len() && ends[end_index].timestamp_ns < start.timestamp_ns {
            unmatched_end += 1;
            end_index += 1;
        }
        if let Some(end) = ends.get(end_index) {
            latencies.push(end.timestamp_ns - start.timestamp_ns);
            end_index += 1;
        } else {
            unmatched_start += (starts.len() - start_index) as u64;
            break;
        }
    }
    if latencies.len() < limit {
        unmatched_end += (ends.len() - end_index) as u64;
    }
    Outcome {
        latencies,
        unmatched_start,
        unmatched_end,
        ambiguous: 0,
    }
}

fn correlate_nearest(starts: &[&Event], ends: &[&Event], limit: Option<usize>) -> Outcome {
    let limit = limit.unwrap_or(usize::MAX);
    let mut available = BTreeMap::<u64, Vec<&Event>>::new();
    for end in ends {
        available.entry(end.timestamp_ns).or_default().push(end);
    }
    let mut latencies = Vec::new();
    let mut unmatched_start = 0_u64;
    let mut reached_limit = false;
    for (index, start) in starts.iter().enumerate() {
        if latencies.len() == limit {
            reached_limit = true;
            break;
        }
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
        latencies.push(selected.abs_diff(start.timestamp_ns));
        let bucket = available
            .get_mut(&selected)
            .expect("selected timestamp must remain available");
        bucket.pop().expect("timestamp bucket must be nonempty");
        if bucket.is_empty() {
            available.remove(&selected);
        }
    }
    Outcome {
        latencies,
        unmatched_start,
        unmatched_end: if reached_limit {
            0
        } else {
            available.values().map(Vec::len).sum::<usize>() as u64
        },
        ambiguous: 0,
    }
}

fn correlate_stack_nested(starts: &[&Event], ends: &[&Event], limit: Option<usize>) -> Outcome {
    let limit = limit.unwrap_or(usize::MAX);
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
            if pairs.len() < limit {
                pairs.push((start.timestamp_ns, event.timestamp_ns - start.timestamp_ns));
            }
        } else {
            unmatched_end += 1;
        }
    }
    pairs.sort_by_key(|(timestamp, _)| *timestamp);
    Outcome {
        latencies: pairs.into_iter().map(|(_, latency)| latency).collect(),
        unmatched_start: stacks.values().map(Vec::len).sum::<usize>() as u64,
        unmatched_end,
        ambiguous: 0,
    }
}

type StreamKey = (u32, u32, u32, u64);

fn correlate_stream_order(starts: &[&Event], ends: &[&Event], limit: Option<usize>) -> Outcome {
    let mut start_groups = BTreeMap::<StreamKey, Vec<&Event>>::new();
    let mut end_groups = BTreeMap::<StreamKey, Vec<&Event>>::new();
    let mut unmatched_start = group_by_stream(starts, &mut start_groups);
    let mut unmatched_end = group_by_stream(ends, &mut end_groups);
    let mut pairs = Vec::new();
    for (key, group) in start_groups {
        let Some(end_group) = end_groups.remove(&key) else {
            unmatched_start += group.len() as u64;
            continue;
        };
        let mut end_index = 0;
        for start in group {
            while end_index < end_group.len()
                && end_group[end_index].timestamp_ns < start.timestamp_ns
            {
                unmatched_end += 1;
                end_index += 1;
            }
            if let Some(end) = end_group.get(end_index) {
                pairs.push((start.timestamp_ns, end.timestamp_ns - start.timestamp_ns));
                end_index += 1;
            } else {
                unmatched_start += 1;
            }
        }
        unmatched_end += (end_group.len() - end_index) as u64;
    }
    unmatched_end += end_groups.values().map(Vec::len).sum::<usize>() as u64;
    pairs.sort_by_key(|(timestamp, _)| *timestamp);
    if let Some(limit) = limit {
        pairs.truncate(limit);
    }
    Outcome {
        latencies: pairs.into_iter().map(|(_, latency)| latency).collect(),
        unmatched_start,
        unmatched_end,
        ambiguous: 0,
    }
}

fn group_by_stream<'a>(
    events: &[&'a Event],
    groups: &mut BTreeMap<StreamKey, Vec<&'a Event>>,
) -> u64 {
    let mut unmatched = 0;
    for event in events {
        let Some(cuda) = event.cuda.as_ref() else {
            unmatched += 1;
            continue;
        };
        let (Some(device), Some(context), Some(stream)) =
            (cuda.device_id, cuda.context_id, cuda.stream_id)
        else {
            unmatched += 1;
            continue;
        };
        groups
            .entry((event.pid, device, context, stream))
            .or_default()
            .push(event);
    }
    unmatched
}

fn correlation_id(event: &Event) -> Option<u32> {
    event.cuda.as_ref()?.correlation_id
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
    let rank = (percentile * sorted.len()).div_ceil(100);
    sorted[rank.saturating_sub(1)]
}

fn maximum_timestamp_error(starts: &[&Event], ends: &[&Event]) -> u64 {
    starts
        .iter()
        .chain(ends)
        .filter_map(|event| event.timestamp_error_ns)
        .max()
        .unwrap_or(0)
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
        HostProbeKind, MatchPolicy, MemcpyKind, SchemaVersion,
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
            attributes: BTreeMap::new(),
        }
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
            offset: None,
            return_value: None,
            arguments: Vec::new(),
        });
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
        assert_eq!(result.clock.estimated_error_ns, 7);
        assert!(result.warnings.is_empty());
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
    fn stream_order_never_pairs_across_cuda_streams() {
        let mut events = vec![
            event(EventType::GpuKernelStart, 100, 1),
            event(EventType::GpuKernelStart, 110, 2),
            event(EventType::GpuKernelEnd, 150, 9),
            event(EventType::GpuKernelEnd, 170, 8),
        ];
        events[1].cuda.as_mut().expect("CUDA payload").stream_id = Some(3);
        events[2].cuda.as_mut().expect("CUDA payload").stream_id = Some(3);

        let result = measure(&events, &options(MatchPolicy::StreamOrder)).unwrap();
        assert_eq!(result.measurement.samples.matched, 2);
        assert_eq!(result.measurement.latency_ns.min, 40);
        assert_eq!(result.measurement.latency_ns.max, 70);
        assert_eq!(result.correlation.method, "cuda_stream_order");
        assert_eq!(result.correlation.confidence, CorrelationConfidence::High);
    }
}
