//! Triggered capture: keep a ring of recent GPU activity and write a window
//! around each span that crosses a threshold.
//!
//! The CUPTI Agent only keeps the newest records in a ring. Deciding when to
//! fire stays here, on the same span rules `measure` uses, so the hot path is
//! unchanged and every trigger rule is deterministic Rust.

use std::collections::BTreeSet;
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use xprobe_correlator::{MeasureError, MeasureOptions, spans};
use xprobe_protocol::{
    CaptureWindow, ClockDomain, ErrorCode, Event, EvidenceArtifact, ExportFormat, MatchPolicy,
    MatchedEventPair, MeasurementMode, SchemaVersion3, SessionStatus, TriggerCollection,
    TriggerCondition, TriggerKind, TriggerObservation, TriggerResult, TriggerWindow, Warning,
};

use crate::coverage::CaptureRecord;
use crate::failure::{CommandFailure, emit_command_failure};
use crate::live::{
    LiveCollection, LiveMeasureRequest, SNAPSHOT_QUIET_PERIOD, injection_warning,
    match_policy_name, refresh_live_sources, single_edge_plan, start_live_collection,
    stop_cupti_agent,
};
use crate::{ExportFormatArg, export_measurement_capture, private_artifact_dir};

/// Longest spans of the trigger's kind listed per window.
const WINDOW_LONGEST: usize = 5;

/// A span that crossed the threshold and the window kept around it.
struct Pending {
    fired: MatchedEventPair,
    start_ns: u64,
    end_ns: u64,
    fired_at: Instant,
}

/// One window cut from the retained events.
pub(crate) struct CutWindow {
    pub(crate) fired: MatchedEventPair,
    pub(crate) start_ns: u64,
    pub(crate) end_ns: u64,
    pub(crate) truncated: bool,
    pub(crate) events: Vec<Event>,
    pub(crate) longest: Vec<MatchedEventPair>,
}

/// Trigger state over the records read so far. It performs no I/O.
pub(crate) struct TriggerEngine {
    condition: TriggerCondition,
    capacity: usize,
    retained: Vec<Event>,
    /// Spans already evaluated, by the sequence numbers of their events.
    seen: BTreeSet<(u64, u64)>,
    /// Timestamp intervals in which records were overwritten or dropped.
    losses: Vec<(u64, u64)>,
    /// Latest timestamp of a record trimmed from retention.
    trimmed_through_ns: Option<u64>,
    last_batch_min_ns: Option<u64>,
    last_dropped: u64,
    observation: TriggerObservation,
    pending: Option<Pending>,
    cooldown_until_ns: u64,
    written: u32,
    lost_windows: u32,
    /// `CLOCK_MONOTONIC` time just before the Agent was armed.
    armed_ns: u64,
    /// Earliest and latest timestamps ever read.
    observed: Option<(u64, u64)>,
    /// New records arrived since the last evaluation.
    dirty: bool,
}

impl TriggerEngine {
    pub(crate) fn new(condition: TriggerCondition, capacity: usize, armed_ns: u64) -> Self {
        Self {
            armed_ns,
            observed: None,
            dirty: false,
            condition,
            capacity,
            retained: Vec::new(),
            seen: BTreeSet::new(),
            losses: Vec::new(),
            trimmed_through_ns: None,
            last_batch_min_ns: None,
            last_dropped: 0,
            observation: TriggerObservation {
                spans: 0,
                over_threshold: 0,
                longest: None,
            },
            pending: None,
            cooldown_until_ns: 0,
            written: 0,
            lost_windows: 0,
        }
    }

    /// Add newly read records. `overwritten` records were lost before this
    /// read and `dropped_total` is the capture's cumulative drop count; either
    /// marks the time this read covers as lost.
    pub(crate) fn ingest(&mut self, events: Vec<Event>, overwritten: u64, dropped_total: u64) {
        let batch_min = events.iter().map(|event| event.timestamp_ns).min();
        let batch_max = events.iter().map(|event| event.timestamp_ns).max();
        if overwritten != 0 || dropped_total > self.last_dropped {
            // Lost records were delivered between the previous read and this
            // one; delivery is not time-ordered across streams, so the loss
            // covers both reads' events.
            let retained_max = self.retained.iter().map(|event| event.timestamp_ns).max();
            let from = [self.last_batch_min_ns, batch_min, retained_max]
                .into_iter()
                .flatten()
                .min();
            let to = [batch_max, retained_max].into_iter().flatten().max();
            if let (Some(from), Some(to)) = (from, to) {
                self.losses.push((from, to));
            } else {
                // Nothing was ever read: everything up to now is suspect.
                self.losses.push((0, u64::MAX));
            }
        }
        self.last_dropped = self.last_dropped.max(dropped_total);
        if let (Some(low), Some(high)) = (batch_min, batch_max) {
            self.last_batch_min_ns = Some(low);
            self.observed = Some(
                self.observed
                    .map_or((low, high), |(min, max)| (min.min(low), max.max(high))),
            );
            self.dirty = true;
        }
        self.retained.extend(events);
        self.trim();
    }

    /// Keep at most `capacity` records, never dropping a pending window's.
    fn trim(&mut self) {
        let Some(excess) = self.retained.len().checked_sub(self.capacity) else {
            return;
        };
        if excess == 0 {
            return;
        }
        self.retained.sort_by_key(|event| event.timestamp_ns);
        let removed = self.retained.drain(..excess).collect::<Vec<_>>();
        let through = removed.iter().map(|event| event.timestamp_ns).max();
        self.trimmed_through_ns = self.trimmed_through_ns.max(through);
        let oldest = self
            .retained
            .iter()
            .map(|event| event.sequence)
            .min()
            .unwrap_or(u64::MAX);
        self.seen.retain(|(start, _)| *start >= oldest);
    }

    /// Evaluate spans not seen before and arm a window on the first one
    /// that crosses the threshold.
    ///
    /// # Errors
    ///
    /// Returns [`MeasureError`] when a latency trigger's selectors or policy
    /// cannot correlate the records.
    pub(crate) fn evaluate(&mut self, now: Instant) -> Result<(), MeasureError> {
        if !std::mem::take(&mut self.dirty) {
            return Ok(());
        }
        let Self {
            condition,
            retained,
            seen,
            observation,
            pending,
            cooldown_until_ns,
            written,
            lost_windows,
            ..
        } = self;
        let mut found = trigger_spans(condition, retained)?;
        found.sort_by_key(|span| (span.start.timestamp_ns, span.end.timestamp_ns));
        for span in found {
            if !seen.insert((span.start.sequence, span.end.sequence)) {
                continue;
            }
            observation.spans += 1;
            if observation
                .longest
                .as_ref()
                .is_none_or(|longest| span.latency_ns > longest.latency_ns)
            {
                observation.longest = Some(pair(&span));
            }
            if span.latency_ns < condition.threshold_ns {
                continue;
            }
            observation.over_threshold += 1;
            if pending.is_none()
                && *written + *lost_windows < condition.windows
                && span.start.timestamp_ns >= *cooldown_until_ns
            {
                *pending = Some(Pending {
                    start_ns: span.start.timestamp_ns.saturating_sub(condition.pre_ns),
                    end_ns: span.end.timestamp_ns.saturating_add(condition.post_ns),
                    fired: pair(&span),
                    fired_at: now,
                });
            }
        }
        Ok(())
    }

    /// Cut the pending window once its post-roll has had time to arrive, or
    /// at once when the capture `stopped` at that `CLOCK_MONOTONIC` time. The
    /// window is clipped to what the capture covered; one that lost records
    /// is discarded.
    pub(crate) fn take_window(
        &mut self,
        now: Instant,
        settle: Duration,
        stopped: Option<u64>,
    ) -> Option<CutWindow> {
        let pending = self.pending.as_ref()?;
        let post = Duration::from_nanos(self.condition.post_ns);
        if stopped.is_none() && now < pending.fired_at + post + settle {
            return None;
        }
        let pending = self.pending.take().expect("pending window was checked");
        self.cooldown_until_ns = pending.end_ns;
        // Host-clock events compare with the ARM and STOP times; raw CUPTI
        // time only with the records read.
        let host_clock = pending.fired.start.clock_domain != ClockDomain::Cupti;
        let (first_seen, last_seen) = self.observed.unwrap_or((pending.start_ns, pending.end_ns));
        let covered_from = if host_clock {
            self.armed_ns
        } else {
            first_seen
        };
        let covered_to = match stopped {
            Some(stopped_ns) if host_clock => stopped_ns,
            Some(_) => last_seen,
            None => pending.end_ns,
        };
        let start_ns = pending.start_ns.max(covered_from);
        let end_ns = pending.end_ns.min(covered_to);
        let truncated = start_ns > pending.start_ns || end_ns < pending.end_ns;
        let pending = Pending {
            start_ns,
            end_ns,
            ..pending
        };
        let lost = self
            .losses
            .iter()
            .any(|(from, to)| *from <= pending.end_ns && pending.start_ns <= *to)
            || self
                .trimmed_through_ns
                .is_some_and(|through| through >= pending.start_ns);
        if lost {
            self.lost_windows += 1;
            return None;
        }
        let mut events = self
            .retained
            .iter()
            .filter(|event| (pending.start_ns..=pending.end_ns).contains(&event.timestamp_ns))
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by_key(|event| (event.timestamp_ns, event.sequence));
        // The window's events already passed evaluation, so this cannot fail.
        let mut longest = trigger_spans(&self.condition, &events)
            .unwrap_or_default()
            .iter()
            .map(pair)
            .collect::<Vec<_>>();
        longest.sort_by_key(|span| std::cmp::Reverse(span.latency_ns));
        longest.truncate(WINDOW_LONGEST);
        self.written += 1;
        Some(CutWindow {
            fired: pending.fired,
            start_ns: pending.start_ns,
            end_ns: pending.end_ns,
            truncated,
            events,
            longest,
        })
    }

    pub(crate) fn done(&self) -> bool {
        self.pending.is_none() && self.written + self.lost_windows >= self.condition.windows
    }

    pub(crate) const fn lost_windows(&self) -> u32 {
        self.lost_windows
    }

    pub(crate) fn observation(&self) -> TriggerObservation {
        self.observation.clone()
    }
}

/// The trigger's spans over `events`.
fn trigger_spans<'a>(
    condition: &TriggerCondition,
    events: &'a [Event],
) -> Result<Vec<spans::Span<'a>>, MeasureError> {
    Ok(match condition.kind {
        TriggerKind::Gap => spans::stream_gaps(events),
        TriggerKind::Duration => spans::activity_durations(events),
        TriggerKind::Latency => spans::edge_spans(
            events,
            condition.start_selector.as_deref().unwrap_or_default(),
            condition.end_selector.as_deref().unwrap_or_default(),
            condition.match_policy.unwrap_or(MatchPolicy::Exact),
        )?,
    })
}

fn pair(span: &spans::Span<'_>) -> MatchedEventPair {
    MatchedEventPair {
        start: span.start.clone(),
        end: span.end.clone(),
        latency_ns: span.latency_ns,
    }
}

/// Milliseconds from the command line as nanoseconds.
pub(crate) fn milliseconds_ns(
    name: &str,
    value: f64,
    allow_zero: bool,
) -> Result<u64, CommandFailure> {
    let nanoseconds = (value * 1_000_000.0).round();
    if !nanoseconds.is_finite() || nanoseconds < 0.0 || (!allow_zero && nanoseconds == 0.0) {
        return Err(CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            format!(
                "--{name} must be a finite {} number of milliseconds",
                if allow_zero {
                    "non-negative"
                } else {
                    "positive"
                }
            ),
            true,
        ));
    }
    // A finite value this large is not a usable duration anyway.
    if nanoseconds >= 1.8e19 {
        return Err(CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            format!("--{name} exceeds the nanosecond range"),
            true,
        ));
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "checked non-negative, finite, and below u64::MAX above"
    )]
    Ok(nanoseconds as u64)
}

/// A request for one triggered capture.
pub(crate) struct TriggerRequest<'a> {
    pub(crate) live: LiveMeasureRequest,
    pub(crate) condition: TriggerCondition,
    pub(crate) events_out: Option<&'a Path>,
}

pub(crate) fn run_trigger(request: &TriggerRequest<'_>, json: bool) -> ExitCode {
    match collect_trigger(request) {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).expect("trigger result must serialize")
                );
            } else {
                print_trigger_result(&result);
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_command_failure(error, json),
    }
}

fn print_trigger_result(result: &TriggerResult) {
    println!(
        "Trigger {:?} >= {} ns: {} window(s), {} span(s) evaluated, {} over threshold",
        result.trigger.kind,
        result.trigger.threshold_ns,
        result.windows.len(),
        result.observed.spans,
        result.observed.over_threshold
    );
    for window in &result.windows {
        println!(
            "  window {}: fired at {} ns for {} ns; {} events in {}",
            window.index,
            window.fired.start.timestamp_ns,
            window.fired.latency_ns,
            window.artifact.events,
            window.artifact.path
        );
    }
}

fn collect_trigger(request: &TriggerRequest<'_>) -> Result<TriggerResult, CommandFailure> {
    let condition = &request.condition;
    let mut plan = single_edge_plan(&request.live)?;
    if plan.requirements.needs_ebpf || !plan.requirements.needs_cupti {
        return Err(CommandFailure::new(
            ErrorCode::InvalidEventSelector,
            "triggered capture supports CUDA endpoints only",
            true,
        )
        .with_hint("measure host endpoints with a bounded --samples or --duration-ms capture"));
    }
    // Gap and duration triggers read every activity; a latency trigger reads
    // every activity only when its policy needs it.
    plan.stream_order = condition.kind != TriggerKind::Latency
        || condition.match_policy == Some(MatchPolicy::StreamOrder);
    let directory = window_directory(request.events_out)?;
    let mut collection = start_live_collection(plan, &request.live)?;
    let mut engine = TriggerEngine::new(
        condition.clone(),
        request.live.options.max_events,
        collection.capture_plan.start_ns,
    );
    let mut windows = Vec::new();
    let outcome = watch(
        &mut collection,
        request,
        &mut engine,
        &directory,
        &mut windows,
    );
    let stopped = stop_cupti_agent(&mut collection, &request.live);
    let result = outcome.and_then(|()| {
        stopped?;
        let stopped_ns = crate::live::monotonic_now()?;
        check_capture(&collection)?;
        // The final forced flush may complete a pending window.
        drain_into(&mut collection, &mut engine);
        engine
            .evaluate(Instant::now())
            .map_err(|error| trigger_failure(&error))?;
        if let Some(window) = engine.take_window(Instant::now(), Duration::ZERO, Some(stopped_ns)) {
            windows.push(write_window(
                &collection,
                &directory,
                window,
                windows.len(),
            )?);
        }
        Ok(())
    });
    result?;
    let observation = engine.observation();
    if windows.is_empty() {
        return Err(no_window_failure(&engine, condition, &collection));
    }
    let warnings = trigger_warnings(&engine, &collection);
    let cuda = collection.latest_cuda.as_ref();
    Ok(TriggerResult {
        schema_version: SchemaVersion3::current(),
        ok: true,
        session_id: request.live.options.session_id.clone(),
        status: if u32::try_from(windows.len()).is_ok_and(|written| written == condition.windows) {
            SessionStatus::Completed
        } else {
            SessionStatus::TimedOut
        },
        target: collection.report.target.clone(),
        trigger: condition.clone(),
        observed: observation,
        windows,
        collection: TriggerCollection {
            ring_capacity: request.live.options.max_events as u64,
            observed_records: cuda.map_or(0, |cuda| cuda.observed_records),
            overwritten_records: collection.ring_overwritten,
            dropped_records: cuda.map_or(0, |cuda| cuda.dropped_records),
            lost_windows: engine.lost_windows(),
        },
        warnings,
    })
}

fn trigger_warnings(engine: &TriggerEngine, collection: &LiveCollection) -> Vec<Warning> {
    let mut warnings = Vec::new();
    if collection.agent_injected {
        warnings.push(injection_warning(collection));
    }
    if engine.lost_windows() != 0 {
        warnings.push(Warning {
            code: "TRIGGER_WINDOWS_LOST".to_owned(),
            message: format!(
                "{} triggered window(s) lost records to ring overwrites or drops and were not written; raise --max-events",
                engine.lost_windows()
            ),
            details: std::collections::BTreeMap::new(),
        });
    }
    warnings
}

/// Why no window was written: nothing fired, or every fired window lost
/// records. A lost window is a loss, not an absence.
fn no_window_failure(
    engine: &TriggerEngine,
    condition: &TriggerCondition,
    collection: &LiveCollection,
) -> CommandFailure {
    let observation = engine.observation();
    let lost = engine.lost_windows() != 0;
    let mut failure = if lost {
        CommandFailure::new(
            ErrorCode::EventsDropped,
            format!(
                "{} span(s) reached {} ns, but their windows lost records to ring overwrites or drops",
                observation.over_threshold, condition.threshold_ns
            ),
            true,
        )
        .with_hint("raise --max-events so the ring holds the records between snapshots")
    } else {
        CommandFailure::new(
            ErrorCode::TriggerNotObserved,
            format!(
                "no span reached {} ns before the timeout; {} span(s) evaluated",
                condition.threshold_ns, observation.spans
            ),
            true,
        )
        .with_hint(
            "the longest span is the observed bound; lower the threshold or wait longer with --timeout-ms",
        )
    }
    .with_detail("spans", observation.spans)
    .with_detail("over_threshold", observation.over_threshold)
    .with_detail("lost_windows", engine.lost_windows())
    .with_detail("overwritten_records", collection.ring_overwritten);
    if let Some(longest) = observation.longest.as_ref() {
        failure = failure
            .with_detail("longest_ns", longest.latency_ns)
            .with_detail("longest_start_ns", longest.start.timestamp_ns);
    }
    failure
}

/// Read snapshots until every window is written or the timeout passes.
fn watch(
    collection: &mut LiveCollection,
    request: &TriggerRequest<'_>,
    engine: &mut TriggerEngine,
    directory: &Path,
    windows: &mut Vec<TriggerWindow>,
) -> Result<(), CommandFailure> {
    // Two snapshot periods let the post-roll's records reach the ring.
    let settle = SNAPSHOT_QUIET_PERIOD * 2;
    loop {
        refresh_live_sources(collection, &request.live)?;
        check_capture(collection)?;
        drain_into(collection, engine);
        let now = Instant::now();
        engine
            .evaluate(now)
            .map_err(|error| trigger_failure(&error))?;
        if let Some(window) = engine.take_window(now, settle, None) {
            windows.push(write_window(collection, directory, window, windows.len())?);
        }
        if engine.done() || now >= collection.deadline {
            return Ok(());
        }
        thread::sleep(SNAPSHOT_QUIET_PERIOD);
    }
}

/// A failed capture or unknown records invalidate every window.
fn check_capture(collection: &LiveCollection) -> Result<(), CommandFailure> {
    let Some(cuda) = collection.latest_cuda.as_ref() else {
        return Ok(());
    };
    if matches!(
        cuda.state,
        xprobe_collector::cupti::CuptiCaptureState::Failed
            | xprobe_collector::cupti::CuptiCaptureState::Idle
    ) {
        return Err(CommandFailure::new(
            ErrorCode::CuptiNotAvailable,
            "CUPTI capture entered a failed state during triggered capture",
            true,
        ));
    }
    let unknown = cuda
        .unknown_records
        .saturating_sub(collection.baseline_unknown);
    if unknown != 0 {
        return Err(CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!("triggered capture holds {unknown} unknown CUPTI activity records"),
            false,
        )
        .with_hint("rebuild xprobe and the CUPTI Agent from the same release"));
    }
    Ok(())
}

/// Move newly appended CUDA events from the collection into the engine.
fn drain_into(collection: &mut LiveCollection, engine: &mut TriggerEngine) {
    let overwritten = collection.ring_overwritten;
    let Some(cuda) = collection.latest_cuda.as_mut() else {
        return;
    };
    let events = std::mem::take(&mut cuda.events);
    let dropped = cuda
        .dropped_records
        .saturating_sub(collection.baseline_dropped);
    let new_overwrites = overwritten - collection.ring_overwritten_seen;
    collection.ring_overwritten_seen = overwritten;
    engine.ingest(events, new_overwrites, dropped);
}

fn trigger_failure(error: &MeasureError) -> CommandFailure {
    CommandFailure::new(error.code(), error.to_string(), error.recoverable())
}

fn window_directory(events_out: Option<&Path>) -> Result<PathBuf, CommandFailure> {
    let Some(directory) = events_out else {
        return private_artifact_dir();
    };
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .map_err(|error| {
            CommandFailure::new(
                ErrorCode::TraceExportFailed,
                format!(
                    "failed to create window directory {}: {error}",
                    directory.display()
                ),
                true,
            )
        })?;
    Ok(directory.to_path_buf())
}

/// Write one window's events and manifest and describe it.
fn write_window(
    collection: &LiveCollection,
    directory: &Path,
    window: CutWindow,
    written: usize,
) -> Result<TriggerWindow, CommandFailure> {
    let index = u32::try_from(written + 1).unwrap_or(u32::MAX);
    let path = directory.join(format!("window-{index}.events.jsonl"));
    let clock_domain = window.fired.start.clock_domain.clone();
    let peer_copies = collection
        .latest_cuda
        .as_ref()
        .is_some_and(|cuda| cuda.peer_memcpy_captured);
    // The manifest window is CLOCK_MONOTONIC; GPU timestamps qualify only
    // when CUPTI normalized them to it.
    let window_bounds = match clock_domain {
        ClockDomain::Cupti => CaptureWindow {
            start_ns: collection.capture_plan.start_ns,
            end_ns: crate::live::monotonic_now()?,
        },
        ClockDomain::HostMonotonic | ClockDomain::CuptiNormalizedToHostMonotonic => CaptureWindow {
            start_ns: window.start_ns,
            end_ns: window.end_ns,
        },
    };
    let record = CaptureRecord {
        target: collection.report.target.clone(),
        window: window_bounds,
        selectors: collection.capture_plan.selectors.clone(),
        all_gpu_activity: collection.capture_plan.stream_order && peer_copies,
        peer_copies,
        // A window that lost records is never written.
        dropped_records: 0,
        unknown_records: 0,
        record_limit_reached: None,
        capture_failed: false,
    };
    export_measurement_capture(&window.events, &path, ExportFormatArg::Jsonl, Some(&record))?;
    Ok(TriggerWindow {
        index,
        fired: window.fired,
        start_ns: window.start_ns,
        end_ns: window.end_ns,
        clock_domain,
        truncated: window.truncated,
        longest: window.longest,
        artifact: EvidenceArtifact {
            path: path.display().to_string(),
            format: ExportFormat::Jsonl,
            events: window.events.len() as u64,
        },
    })
}

/// Build the request for `measure --pid ... --trigger-*`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn trigger_request(
    pid: u32,
    cupti_socket: Option<PathBuf>,
    agent_path: Option<PathBuf>,
    timeout_ms: u64,
    max_events: usize,
    session_id: String,
    condition: TriggerCondition,
    events_out: Option<&Path>,
) -> TriggerRequest<'_> {
    // Gap and duration triggers arm on activity endpoints; a latency trigger
    // arms on its own edge.
    let (start_selector, end_selector, match_policy) = match condition.kind {
        TriggerKind::Gap | TriggerKind::Duration => (
            "cuda:kernel_end".to_owned(),
            "cuda:kernel_start".to_owned(),
            MatchPolicy::StreamOrder,
        ),
        TriggerKind::Latency => (
            condition.start_selector.clone().unwrap_or_default(),
            condition.end_selector.clone().unwrap_or_default(),
            condition.match_policy.unwrap_or(MatchPolicy::Exact),
        ),
    };
    TriggerRequest {
        live: LiveMeasureRequest {
            pid,
            expected_target: None,
            cupti_socket,
            agent_path,
            timeout: Duration::from_millis(timeout_ms),
            match_policy_text: match_policy_name(match_policy),
            mode: MeasurementMode::Exact,
            ring: true,
            options: MeasureOptions {
                session_id,
                name: None,
                start_selector,
                end_selector,
                match_policy,
                samples: None,
                duration: None,
                max_events,
                dropped_events: 0,
            },
        },
        condition,
        events_out,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    use xprobe_protocol::{
        ClockDomain, CudaEvent, Event, EventSource, EventType, SchemaVersion, TriggerCondition,
        TriggerKind,
    };

    use super::{TriggerEngine, milliseconds_ns};

    const MS: u64 = 1_000_000;

    /// One kernel's start and end on stream 7, numbered from `sequence`.
    fn kernel(start: u64, end: u64, sequence: u64) -> Vec<Event> {
        [
            (EventType::GpuKernelStart, start),
            (EventType::GpuKernelEnd, end),
        ]
        .into_iter()
        .zip(sequence..)
        .map(|((event_type, timestamp), sequence)| Event {
            schema_version: SchemaVersion::current(),
            session_id: "trigger".to_owned(),
            event_id: format!("evt_{sequence}"),
            sequence,
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
                stream_id: Some(7),
                correlation_id: u32::try_from(sequence / 2 + 1).ok(),
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

    fn condition(kind: TriggerKind, threshold_ms: u64, windows: u32) -> TriggerCondition {
        TriggerCondition {
            kind,
            threshold_ns: threshold_ms * MS,
            start_selector: None,
            end_selector: None,
            match_policy: None,
            pre_ns: MS,
            post_ns: MS,
            windows,
        }
    }

    #[test]
    fn a_gap_over_the_threshold_writes_the_window_around_it() {
        let mut engine = TriggerEngine::new(condition(TriggerKind::Gap, 10, 1), 100, 0);
        // Kernels at 0–10, 10.5–11, and 30–31 ms: one 19 ms gap.
        let events = [kernel(0, 10 * MS, 0), kernel(10 * MS + MS / 2, 11 * MS, 2)].concat();
        engine.ingest(events, 0, 0);
        engine.evaluate(Instant::now()).unwrap();
        assert!(
            engine
                .take_window(Instant::now(), Duration::ZERO, Some(u64::MAX))
                .is_none()
        );

        engine.ingest(kernel(30 * MS, 31 * MS, 4), 0, 0);
        engine.evaluate(Instant::now()).unwrap();
        // The post-roll has not had time to arrive yet.
        assert!(
            engine
                .take_window(Instant::now(), Duration::from_secs(60), None)
                .is_none()
        );
        let window = engine
            .take_window(Instant::now(), Duration::ZERO, Some(u64::MAX))
            .expect("the 19 ms gap fires");
        assert_eq!(window.fired.latency_ns, 19 * MS);
        assert_eq!((window.start_ns, window.end_ns), (10 * MS, 31 * MS));
        // Every record from 10 ms through 31 ms: A's end, B, and C.
        assert_eq!(window.events.len(), 5);
        assert_eq!(window.longest[0].latency_ns, 19 * MS);
        assert!(engine.done());

        let observation = engine.observation();
        assert_eq!(observation.spans, 2);
        assert_eq!(observation.over_threshold, 1);
    }

    #[test]
    fn windows_are_clipped_to_what_the_capture_covered() {
        // Armed at 9.5 ms, stopped at 30.5 ms: the 1 ms pre- and post-roll
        // around the 10-30 ms gap are only partly captured.
        let mut engine =
            TriggerEngine::new(condition(TriggerKind::Gap, 10, 1), 100, 9 * MS + MS / 2);
        engine.ingest(
            [
                kernel(9 * MS + MS / 2, 10 * MS, 0),
                kernel(30 * MS, 30 * MS + MS / 4, 2),
            ]
            .concat(),
            0,
            0,
        );
        engine.evaluate(Instant::now()).unwrap();
        let window = engine
            .take_window(Instant::now(), Duration::ZERO, Some(30 * MS + MS / 2))
            .expect("the gap fires");
        assert!(window.truncated);
        assert_eq!(
            (window.start_ns, window.end_ns),
            (9 * MS + MS / 2, 30 * MS + MS / 2)
        );
    }

    #[test]
    fn spans_fire_once_and_later_windows_follow_the_previous_one() {
        let mut engine = TriggerEngine::new(condition(TriggerKind::Gap, 10, 2), 100, 0);
        engine.ingest(
            [kernel(0, MS, 0), kernel(20 * MS, 21 * MS, 2)].concat(),
            0,
            0,
        );
        engine.evaluate(Instant::now()).unwrap();
        assert!(
            engine
                .take_window(Instant::now(), Duration::ZERO, Some(u64::MAX))
                .is_some()
        );
        // Re-evaluating the same records does not fire again.
        engine.evaluate(Instant::now()).unwrap();
        assert!(
            engine
                .take_window(Instant::now(), Duration::ZERO, Some(u64::MAX))
                .is_none()
        );
        assert!(!engine.done());

        engine.ingest(kernel(40 * MS, 41 * MS, 4), 0, 0);
        engine.evaluate(Instant::now()).unwrap();
        let second = engine
            .take_window(Instant::now(), Duration::ZERO, Some(u64::MAX))
            .expect("a later gap fires the second window");
        assert_eq!(second.fired.start.timestamp_ns, 21 * MS);
        assert!(engine.done());
    }

    #[test]
    fn a_window_that_lost_records_is_not_written() {
        let mut engine = TriggerEngine::new(condition(TriggerKind::Gap, 10, 1), 100, 0);
        engine.ingest(kernel(0, MS, 0), 0, 0);
        // The ring overwrote records between the two reads.
        engine.ingest(kernel(20 * MS, 21 * MS, 10), 3, 0);
        engine.evaluate(Instant::now()).unwrap();
        assert!(
            engine
                .take_window(Instant::now(), Duration::ZERO, Some(u64::MAX))
                .is_none()
        );
        assert_eq!(engine.lost_windows(), 1);
        assert!(engine.done());

        // Drops count the same way.
        let mut dropped = TriggerEngine::new(condition(TriggerKind::Gap, 10, 1), 100, 0);
        dropped.ingest(kernel(0, MS, 0), 0, 0);
        dropped.ingest(kernel(20 * MS, 21 * MS, 2), 0, 1);
        dropped.evaluate(Instant::now()).unwrap();
        assert!(
            dropped
                .take_window(Instant::now(), Duration::ZERO, Some(u64::MAX))
                .is_none()
        );
        assert_eq!(dropped.lost_windows(), 1);
    }

    #[test]
    fn a_duration_trigger_fires_on_a_long_activity() {
        let mut engine = TriggerEngine::new(condition(TriggerKind::Duration, 5, 1), 100, 0);
        engine.ingest([kernel(0, MS, 0), kernel(2 * MS, 9 * MS, 2)].concat(), 0, 0);
        engine.evaluate(Instant::now()).unwrap();
        let window = engine
            .take_window(Instant::now(), Duration::ZERO, Some(u64::MAX))
            .expect("the 7 ms kernel fires");
        assert_eq!(window.fired.latency_ns, 7 * MS);
        assert_eq!(window.fired.start.timestamp_ns, 2 * MS);
    }

    #[test]
    fn millisecond_bounds_are_finite_and_positive() {
        assert_eq!(milliseconds_ns("x", 0.5, false).unwrap(), 500_000);
        assert_eq!(milliseconds_ns("x", 0.0, true).unwrap(), 0);
        for invalid in [0.0, -1.0, f64::NAN, f64::INFINITY, 1e30] {
            assert!(milliseconds_ns("x", invalid, false).is_err(), "{invalid}");
        }
    }
}
