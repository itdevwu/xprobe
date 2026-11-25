//! Spans between events of one capture, for thresholds such as triggers.
//!
//! Each span uses the same pairing rules as `measure`: stream gaps follow
//! stream-order adjacency, activity durations follow exact correlation, and
//! edge spans follow the requested policy.

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

/// Idle time on each stream: every activity end paired with the start of the
/// next kernel, copy, or memset on its stream. Overlapping activity and tied
/// starts give no gap.
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
