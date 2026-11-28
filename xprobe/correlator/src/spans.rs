//! Spans between events of one capture, for thresholds such as triggers.
//!
//! Each span uses the same pairing rules as `measure`: stream gaps follow
//! stream-order adjacency, activity durations follow exact correlation, and
//! edge spans follow the requested policy.

use std::collections::{BTreeMap, BTreeSet};
use std::ptr;

use xprobe_protocol::{ActivityBoundary, Event, EventType, MatchPolicy, activity_boundary};

use super::{
    LifecycleKinds, MeasureError, Pair, Selected, Selector, correlate_exact, correlate_selected,
    correlate_stream_order, select_endpoints, validate_policy,
};

/// Two events of one capture and the time between them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Span<'a> {
    pub start: &'a Event,
    pub end: &'a Event,
    pub latency_ns: u64,
}

impl<'a> From<Pair<'a>> for Span<'a> {
    fn from(pair: Pair<'a>) -> Self {
        Self {
            start: pair.start,
            end: pair.end,
            latency_ns: pair.latency_ns,
        }
    }
}

/// Gaps on each stream: every activity end paired with the start of the
/// next kernel, copy, or memset on its stream. Overlapping activity and tied
/// starts give no gap. Another stream may keep the device busy meanwhile;
/// [`device_idle`] is the time a device had nothing to run.
#[must_use]
pub fn stream_gaps(events: &[Event]) -> Vec<Span<'_>> {
    let boundary = |wanted| {
        events
            .iter()
            .filter(|event| activity_boundary(&event.event_type) == Some(wanted))
            .collect::<Vec<_>>()
    };
    let ends = boundary(ActivityBoundary::End);
    let starts = boundary(ActivityBoundary::Start);
    correlate_stream_order(&Selected {
        events,
        starts: &ends,
        ends: &starts,
        end_selector: None,
    })
    .pairs
    .into_iter()
    .map(Span::from)
    .collect()
}

/// Idle time on each device: from the end of the activity that ended last to
/// the start of the next kernel, copy, or memset on any stream of that device
/// in the same process. An activity whose start the capture missed may have
/// run since before it, so no idle time is claimed before its end; one still
/// running at the end keeps the device busy from its start on.
#[must_use]
pub fn device_idle(events: &[Event]) -> Vec<Span<'_>> {
    let durations = activity_durations(events);
    let paired = durations
        .iter()
        .flat_map(|span| [ptr::from_ref(span.start), ptr::from_ref(span.end)])
        .collect::<BTreeSet<_>>();
    // Per process and device: activity intervals. A missing start began
    // before the capture; a missing end ran past it.
    let mut devices = BTreeMap::<(u32, u32), Vec<(Option<&Event>, Option<&Event>)>>::new();
    let device = |event: &Event| {
        event
            .cuda
            .as_ref()
            .and_then(|cuda| cuda.device_id)
            .map(|id| (event.pid, id))
    };
    for span in &durations {
        if let Some(key) = device(span.start) {
            devices
                .entry(key)
                .or_default()
                .push((Some(span.start), Some(span.end)));
        }
    }
    for event in events {
        let Some(boundary) = activity_boundary(&event.event_type) else {
            continue;
        };
        if paired.contains(&ptr::from_ref(event)) {
            continue;
        }
        let Some(key) = device(event) else {
            continue;
        };
        devices.entry(key).or_default().push(match boundary {
            ActivityBoundary::Start => (Some(event), None),
            ActivityBoundary::End => (None, Some(event)),
        });
    }
    let mut idle = Vec::new();
    for mut intervals in devices.into_values() {
        intervals.sort_by_key(|(start, end)| {
            (
                start.map_or(0, |start| start.timestamp_ns),
                end.map_or(u64::MAX, |end| end.timestamp_ns),
            )
        });
        // The end that keeps the device busy longest so far; `None` once an
        // activity runs past the capture.
        let mut busy: Option<Option<&Event>> = None;
        for (start, end) in intervals {
            if let (Some(Some(until)), Some(start)) = (busy, start)
                && start.timestamp_ns > until.timestamp_ns
            {
                idle.push(Span {
                    start: until,
                    end: start,
                    latency_ns: start.timestamp_ns - until.timestamp_ns,
                });
            }
            busy = Some(match (busy, end) {
                (Some(None), _) | (_, None) => None,
                (Some(Some(until)), Some(end)) if until.timestamp_ns >= end.timestamp_ns => {
                    Some(until)
                }
                (_, Some(end)) => Some(end),
            });
        }
    }
    idle.sort_by_key(|span| (span.start.timestamp_ns, span.end.timestamp_ns));
    idle
}

/// The duration of every kernel, copy, and memset, paired by correlation ID.
#[must_use]
pub fn activity_durations(events: &[Event]) -> Vec<Span<'_>> {
    [
        (EventType::GpuKernelStart, EventType::GpuKernelEnd),
        (EventType::GpuMemcpyStart, EventType::GpuMemcpyEnd),
        (EventType::GpuMemsetStart, EventType::GpuMemsetEnd),
    ]
    .iter()
    .flat_map(|(start, end)| {
        let pick = |kind: &EventType| {
            let mut picked = events
                .iter()
                .filter(|event| event.event_type == *kind)
                .collect::<Vec<_>>();
            picked.sort_by_key(|event| event.timestamp_ns);
            picked
        };
        correlate_exact(&pick(start), &pick(end)).pairs
    })
    .map(Span::from)
    .collect()
}

/// Every pair of one edge under `policy`, without samples or duration bounds.
///
/// # Errors
///
/// Returns [`MeasureError`] for invalid selectors, a policy the selectors do
/// not support, or events in clocks that cannot be subtracted.
pub fn edge_spans<'a>(
    events: &'a [Event],
    start_selector: &str,
    end_selector: &str,
    policy: MatchPolicy,
) -> Result<Vec<Span<'a>>, MeasureError> {
    let start = Selector::parse(start_selector)?;
    let end = Selector::parse(end_selector)?;
    validate_policy(&start, &end, policy)?;
    let (starts, ends, _) = select_endpoints(events, &start, &end, None)?;
    let lifecycles = LifecycleKinds {
        syscall: start.is_syscall_lifecycle(&end),
        nvtx: start.is_nvtx_lifecycle(&end),
        python_gc: start.is_python_gc_lifecycle(&end),
    };
    Ok(correlate_selected(
        &Selected {
            events,
            starts: &starts,
            ends: &ends,
            end_selector: Some(&end),
        },
        policy,
        None,
        lifecycles,
    )
    .pairs
    .into_iter()
    .map(Span::from)
    .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use xprobe_protocol::{ClockDomain, CudaEvent, Event, EventSource, EventType, SchemaVersion};

    use super::{device_idle, stream_gaps};

    /// A kernel's start and end on `stream` of device 0, numbered from
    /// `sequence`; `None` leaves out that boundary.
    fn kernel(span: (Option<u64>, Option<u64>), stream: u64, correlation: u32) -> Vec<Event> {
        [
            (EventType::GpuKernelStart, span.0),
            (EventType::GpuKernelEnd, span.1),
        ]
        .into_iter()
        .filter_map(|(event_type, timestamp)| Some((event_type, timestamp?)))
        .map(|(event_type, timestamp)| Event {
            schema_version: SchemaVersion::current(),
            session_id: "idle".to_owned(),
            event_id: format!("evt_{correlation}_{timestamp}"),
            sequence: u64::from(correlation) * 2 + u64::from(event_type == EventType::GpuKernelEnd),
            source: EventSource::CuptiActivity,
            event_type,
            pid: 1,
            tid: 1,
            cpu: None,
            timestamp_raw: timestamp,
            timestamp_ns: timestamp,
            clock_domain: ClockDomain::CuptiNormalizedToHostMonotonic,
            timestamp_error_ns: None,
            process_start_time: None,
            host: None,
            cuda: Some(CudaEvent {
                device_id: Some(0),
                context_id: Some(1),
                stream_id: Some(stream),
                correlation_id: Some(correlation),
                runtime_correlation_id: None,
                callback_domain: None,
                callback_id: None,
                kernel_name: Some("k".to_owned()),
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
        })
        .collect()
    }

    fn latencies(spans: &[super::Span<'_>]) -> Vec<u64> {
        spans.iter().map(|span| span.latency_ns).collect()
    }

    #[test]
    fn a_stream_gap_is_not_idle_while_another_stream_runs() {
        // Stream 1: 0-10 and 40-50. Stream 2 runs 5-30 in between.
        let events = [
            kernel((Some(0), Some(10)), 1, 1),
            kernel((Some(5), Some(30)), 2, 2),
            kernel((Some(40), Some(50)), 1, 3),
        ]
        .concat();
        assert_eq!(latencies(&stream_gaps(&events)), [30]);
        assert_eq!(latencies(&device_idle(&events)), [10]);
    }

    #[test]
    fn activity_across_the_capture_bounds_hides_idle_time() {
        // A kernel that started before the capture ends at 30, so the 10-20
        // gap before it cannot be shown idle; 30-40 can.
        let before = [
            kernel((Some(0), Some(10)), 1, 1),
            kernel((Some(20), Some(25)), 1, 2),
            kernel((None, Some(30)), 2, 3),
            kernel((Some(40), Some(50)), 1, 4),
        ]
        .concat();
        assert_eq!(latencies(&device_idle(&before)), [10]);
        // A kernel still running at the end keeps the device busy after 15.
        let after = [
            kernel((Some(0), Some(10)), 1, 1),
            kernel((Some(15), None), 2, 2),
            kernel((Some(40), Some(50)), 1, 3),
        ]
        .concat();
        assert_eq!(latencies(&device_idle(&after)), [5]);
    }
}
