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
    /// Records the window may hold were lost: trimmed before it fired,
    /// reported lost after it fired, or beyond the retention bound.
    lost: bool,
    /// The window's records trimmed from retention after it closed.
    kept: Vec<Event>,
}

/// What became of a closed window once the capture stopped.
enum Cut {
    Written(Box<CutWindow>),
    Lost,
    Revoked,
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
    /// Windows whose post-roll has arrived. They are cut only after the
    /// capture stopped, once late records and losses are known.
    closed: Vec<Pending>,
    cooldown_until_ns: u64,
    lost_windows: u32,
    revoked_windows: u32,
    /// `CLOCK_MONOTONIC` time once the Agent acknowledged ARM.
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
            closed: Vec::new(),
            cooldown_until_ns: 0,
            lost_windows: 0,
            revoked_windows: 0,
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
            // A loss cannot be placed in time, so one reported after a window
            // fired may belong to it.
            for window in self.closed.iter_mut().chain(&mut self.pending) {
                window.lost = true;
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

    /// Keep at most `capacity` records. The open window's records stay
    /// retained until it closes; a closed window keeps its trimmed records,
    /// including late ones, until it is cut.
    fn trim(&mut self) {
        let Some(excess) = self.retained.len().checked_sub(self.capacity) else {
            return;
        };
        if excess == 0 {
            return;
        }
        // The open window holds retention up to twice the bound; beyond
        // that it is lost rather than grow without limit.
        if self.retained.len() > self.capacity.saturating_mul(2)
            && let Some(open) = self.pending.as_mut()
        {
            open.lost = true;
        }
        let protected_from = self
            .pending
            .as_ref()
            .filter(|open| !open.lost)
            .map_or(u64::MAX, |open| open.start_ns);
        self.retained.sort_by_key(|event| event.timestamp_ns);
        let removable = self
            .retained
            .iter()
            .take(excess)
            .take_while(|event| event.timestamp_ns < protected_from)
            .count();
        let removed = self.retained.drain(..removable).collect::<Vec<_>>();
        for window in self.closed.iter_mut().filter(|window| !window.lost) {
            window.kept.extend(
                removed
                    .iter()
                    .filter(|event| (window.start_ns..=window.end_ns).contains(&event.timestamp_ns))
                    .cloned(),
            );
            // A window keeps at most the retention bound of its own records.
            if window.kept.len() > self.capacity {
                window.lost = true;
                window.kept = Vec::new();
            }
        }
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
            closed,
            cooldown_until_ns,
            armed_ns,
            trimmed_through_ns,
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
            // A span that began before ARM has no captured pre-roll.
            let before_arm = span.start.clock_domain != ClockDomain::Cupti
                && span.start.timestamp_ns < *armed_ns;
            if pending.is_none()
                && !before_arm
                && (closed.len() as u64) < u64::from(condition.windows)
                && span.start.timestamp_ns >= *cooldown_until_ns
            {
                let start_ns = span.start.timestamp_ns.saturating_sub(condition.pre_ns);
                *pending = Some(Pending {
                    start_ns,
                    end_ns: span.end.timestamp_ns.saturating_add(condition.post_ns),
                    fired: pair(&span),
                    fired_at: now,
                    lost: trimmed_through_ns.is_some_and(|through| through >= start_ns),
                    kept: Vec::new(),
                });
            }
        }
        Ok(())
    }

    /// Close the pending window once its post-roll has had time to arrive.
    pub(crate) fn close_window(&mut self, now: Instant, settle: Duration) {
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        if now < pending.fired_at + Duration::from_nanos(self.condition.post_ns) + settle {
            return;
        }
        let pending = self.pending.take().expect("pending window was checked");
        self.cooldown_until_ns = pending.end_ns;
        self.closed.push(pending);
    }

    /// Cut every window once the capture stopped at `stopped_ns`
    /// (`CLOCK_MONOTONIC`). Windows are clipped to what the capture covered.
    /// One that lost records is lost; one whose firing span no longer
    /// crosses the threshold with every record in is revoked.
    pub(crate) fn finish(&mut self, stopped_ns: u64) -> Vec<CutWindow> {
        let windows = std::mem::take(&mut self.closed)
            .into_iter()
            .chain(self.pending.take())
            .collect::<Vec<_>>();
        let mut cut = Vec::new();
        for window in windows {
            match self.cut(window, stopped_ns) {
                Cut::Written(window) => cut.push(*window),
                Cut::Lost => self.lost_windows += 1,
                Cut::Revoked => self.revoked_windows += 1,
            }
        }
        cut
    }

    fn cut(&self, window: Pending, stopped_ns: u64) -> Cut {
        // Host-clock events compare with the ARM and STOP times; raw CUPTI
        // time only with the records read.
        let host_clock = window.fired.start.clock_domain != ClockDomain::Cupti;
        let (first_seen, last_seen) = self.observed.unwrap_or((window.start_ns, window.end_ns));
        let (covered_from, covered_to) = if host_clock {
            (self.armed_ns, stopped_ns)
        } else {
            (first_seen, last_seen)
        };
        let start_ns = window.start_ns.max(covered_from);
        let end_ns = window.end_ns.min(covered_to);
        let truncated = start_ns > window.start_ns || end_ns < window.end_ns;
        let lost = window.lost
            || self
                .losses
                .iter()
                .any(|(from, to)| *from <= end_ns && start_ns <= *to);
        if lost {
            return Cut::Lost;
        }
        // Each record is either still retained or kept by the window. Spans
        // are re-evaluated on all of them, so boundaries outside the window
        // keep their context; only the export is cut to the window.
        let mut context = window
            .kept
            .into_iter()
            .chain(self.retained.iter().cloned())
            .collect::<Vec<_>>();
        context.sort_by_key(|event| (event.timestamp_ns, event.sequence));
        let inside = |event: &Event| (start_ns..=end_ns).contains(&event.timestamp_ns);
        // These records already passed evaluation, so this cannot fail.
        let spans = trigger_spans(&self.condition, &context).unwrap_or_default();
        let fired = (window.fired.start.sequence, window.fired.end.sequence);
        let holds = spans.iter().any(|span| {
            (span.start.sequence, span.end.sequence) == fired
                && span.latency_ns >= self.condition.threshold_ns
        });
        if !holds {
            return Cut::Revoked;
        }
        let mut longest = spans
            .iter()
            .filter(|span| inside(span.start) && inside(span.end))
            .map(pair)
            .collect::<Vec<_>>();
        longest.sort_by_key(|span| std::cmp::Reverse(span.latency_ns));
        longest.truncate(WINDOW_LONGEST);
        drop(spans);
        context.retain(|event| inside(event));
        let events = context;
        Cut::Written(Box::new(CutWindow {
            fired: window.fired,
            start_ns,
            end_ns,
            truncated,
            events,
            longest,
        }))
    }

    pub(crate) fn done(&self) -> bool {
        self.pending.is_none() && self.closed.len() as u64 >= u64::from(self.condition.windows)
    }

    pub(crate) const fn lost_windows(&self) -> u32 {
        self.lost_windows
    }

    pub(crate) const fn revoked_windows(&self) -> u32 {
        self.revoked_windows
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
    let outcome = watch(&mut collection, request, &mut engine);
    let timed_out = Instant::now() >= collection.deadline;
    // Activity after this instant may miss the capture.
    let stopped_ns = crate::live::monotonic_now();
    let stopped = stop_cupti_agent(&mut collection, &request.live);
    let mut windows = Vec::new();
    outcome.and_then(|()| {
        stopped?;
        let stopped_ns = stopped_ns?;
        check_capture(&collection)?;
        // The final drain may complete windows; cut them only now.
        drain_into(&mut collection, &mut engine);
        engine
            .evaluate(Instant::now())
            .map_err(|error| trigger_failure(&error))?;
        for window in engine.finish(stopped_ns) {
            windows.push(write_window(
                &collection,
                &directory,
                window,
                windows.len(),
            )?);
        }
        Ok(())
    })?;
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
        // Fewer windows than asked for is a timeout only if the deadline
        // passed; otherwise windows were lost or revoked after closing.
        status: if timed_out
            && u32::try_from(windows.len()).is_ok_and(|written| written < condition.windows)
        {
            SessionStatus::TimedOut
        } else {
            SessionStatus::Completed
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
            revoked_windows: engine.revoked_windows(),
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
    if engine.revoked_windows() != 0 {
        warnings.push(Warning {
            code: "TRIGGER_WINDOWS_REVOKED".to_owned(),
            message: format!(
                "{} triggered window(s) were not written because their firing span fell below the threshold once late records arrived",
                engine.revoked_windows()
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
    } else if engine.revoked_windows() != 0 {
        CommandFailure::new(
            ErrorCode::TriggerNotObserved,
            format!(
                "{} window(s) fired at {} ns but their spans fell below it once every record arrived",
                engine.revoked_windows(),
                condition.threshold_ns
            ),
            true,
        )
        .with_hint("the longest span is the observed bound; lower the threshold or wait longer with --timeout-ms")
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
    .with_detail("revoked_windows", engine.revoked_windows())
    .with_detail("overwritten_records", collection.ring_overwritten);
    if let Some(longest) = observation.longest.as_ref() {
        failure = failure
            .with_detail("longest_ns", longest.latency_ns)
            .with_detail("longest_start_ns", longest.start.timestamp_ns);
    }
    failure
}

/// Read snapshots until every window is closed or the timeout passes.
fn watch(
    collection: &mut LiveCollection,
    request: &TriggerRequest<'_>,
    engine: &mut TriggerEngine,
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
        engine.close_window(now, settle);
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
    // ARM resets the Agent's counters, so every unknown record, including
    // any in the ARM reply, belongs to this capture.
    let unknown = cuda.unknown_records;
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
    // Counters restart at ARM; a drop reported with ARM is a loss too.
    let dropped = cuda.dropped_records;
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

    /// Close the open window as if its post-roll had arrived.
    fn close(engine: &mut TriggerEngine) {
        engine.close_window(Instant::now() + Duration::from_secs(3600), Duration::ZERO);
    }

    #[test]
    fn a_gap_over_the_threshold_writes_the_window_around_it() {
        let mut engine = TriggerEngine::new(condition(TriggerKind::Gap, 10, 1), 100, 0);
        // Kernels at 0–10, 10.5–11, and 30–31 ms: one 19 ms gap.
        let events = [kernel(0, 10 * MS, 0), kernel(10 * MS + MS / 2, 11 * MS, 2)].concat();
        engine.ingest(events, 0, 0);
        engine.evaluate(Instant::now()).unwrap();
        close(&mut engine);
        assert!(!engine.done());

        engine.ingest(kernel(30 * MS, 31 * MS, 4), 0, 0);
        engine.evaluate(Instant::now()).unwrap();
        // The post-roll has not had time to arrive yet.
        engine.close_window(Instant::now(), Duration::from_secs(60));
        assert!(!engine.done());
        close(&mut engine);
        assert!(engine.done());
        let windows = engine.finish(u64::MAX);
        assert_eq!(windows.len(), 1);
        let window = &windows[0];
        assert_eq!(window.fired.latency_ns, 19 * MS);
        assert_eq!((window.start_ns, window.end_ns), (10 * MS, 31 * MS));
        // Every record from 10 ms through 31 ms: A's end, B, and C.
        assert_eq!(window.events.len(), 5);
        assert_eq!(window.longest[0].latency_ns, 19 * MS);

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
        let windows = engine.finish(30 * MS + MS / 2);
        assert!(windows[0].truncated);
        assert_eq!(
            (windows[0].start_ns, windows[0].end_ns),
            (9 * MS + MS / 2, 30 * MS + MS / 2)
        );
    }

    #[test]
    fn a_span_that_began_before_arm_does_not_fire() {
        // A 19 ms gap from 1 ms, but the Agent acknowledged ARM at 5 ms.
        let mut engine = TriggerEngine::new(condition(TriggerKind::Gap, 10, 1), 100, 5 * MS);
        engine.ingest(
            [kernel(0, MS, 0), kernel(20 * MS, 21 * MS, 2)].concat(),
            0,
            0,
        );
        engine.evaluate(Instant::now()).unwrap();
        assert_eq!(engine.observation().over_threshold, 1);
        assert_eq!(engine.finish(u64::MAX).len(), 0);
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
        close(&mut engine);
        // Re-evaluating the same records does not fire again.
        engine.evaluate(Instant::now()).unwrap();
        close(&mut engine);
        assert!(!engine.done());

        engine.ingest(kernel(40 * MS, 41 * MS, 4), 0, 0);
        engine.evaluate(Instant::now()).unwrap();
        close(&mut engine);
        assert!(engine.done());
        let windows = engine.finish(u64::MAX);
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[1].fired.start.timestamp_ns, 21 * MS);
    }

    #[test]
    fn a_window_that_lost_records_is_not_written() {
        let mut engine = TriggerEngine::new(condition(TriggerKind::Gap, 10, 1), 100, 0);
        engine.ingest(kernel(0, MS, 0), 0, 0);
        // The ring overwrote records between the two reads.
        engine.ingest(kernel(20 * MS, 21 * MS, 10), 3, 0);
        engine.evaluate(Instant::now()).unwrap();
        close(&mut engine);
        assert!(engine.done());
        assert_eq!(engine.finish(u64::MAX).len(), 0);
        assert_eq!(engine.lost_windows(), 1);

        // Drops count the same way.
        let mut dropped = TriggerEngine::new(condition(TriggerKind::Gap, 10, 1), 100, 0);
        dropped.ingest(kernel(0, MS, 0), 0, 0);
        dropped.ingest(kernel(20 * MS, 21 * MS, 2), 0, 1);
        dropped.evaluate(Instant::now()).unwrap();
        assert_eq!(dropped.finish(u64::MAX).len(), 0);
        assert_eq!(dropped.lost_windows(), 1);

        // A loss reported after the window closed still invalidates it.
        let mut late = TriggerEngine::new(condition(TriggerKind::Gap, 10, 1), 100, 0);
        late.ingest(
            [kernel(0, MS, 0), kernel(20 * MS, 21 * MS, 2)].concat(),
            0,
            0,
        );
        late.evaluate(Instant::now()).unwrap();
        close(&mut late);
        late.ingest(kernel(10 * MS, 11 * MS, 4), 0, 1);
        assert_eq!(late.finish(u64::MAX).len(), 0);
        assert_eq!(late.lost_windows(), 1);
    }

    #[test]
    fn a_late_record_inside_the_gap_revokes_its_window() {
        let mut engine = TriggerEngine::new(condition(TriggerKind::Gap, 10, 1), 100, 0);
        engine.ingest(
            [kernel(0, MS, 0), kernel(20 * MS, 21 * MS, 2)].concat(),
            0,
            0,
        );
        engine.evaluate(Instant::now()).unwrap();
        close(&mut engine);
        // A kernel from 9 to 12 ms arrives after the window closed.
        engine.ingest(kernel(9 * MS, 12 * MS, 4), 0, 0);
        engine.evaluate(Instant::now()).unwrap();
        assert_eq!(engine.finish(u64::MAX).len(), 0);
        assert_eq!(engine.revoked_windows(), 1);
    }

    #[test]
    fn retention_keeps_the_records_of_windows_not_yet_cut() {
        // Room for four records: each kernel adds two.
        let mut engine = TriggerEngine::new(condition(TriggerKind::Gap, 10, 1), 4, 0);
        engine.ingest(
            [kernel(0, MS, 0), kernel(20 * MS, 21 * MS, 2)].concat(),
            0,
            0,
        );
        engine.evaluate(Instant::now()).unwrap();
        // While the window is open, later records exceed retention.
        engine.ingest(kernel(22 * MS, 23 * MS, 4), 0, 0);
        close(&mut engine);
        // After it closes, trimming moves its records aside.
        engine.ingest(
            [kernel(40 * MS, 41 * MS, 6), kernel(60 * MS, 61 * MS, 8)].concat(),
            0,
            0,
        );
        let windows = engine.finish(u64::MAX);
        assert_eq!(engine.lost_windows(), 0);
        assert_eq!(windows.len(), 1);
        // 0 to 21 ms: both records of A and of B.
        assert_eq!(windows[0].events.len(), 4);
    }

    #[test]
    fn a_window_without_pre_roll_keeps_its_span() {
        // With no pre-roll the window starts at A's end, so A's start lies
        // outside it; the gap is still re-checked in context.
        let mut gap = condition(TriggerKind::Gap, 10, 1);
        gap.pre_ns = 0;
        let mut engine = TriggerEngine::new(gap, 100, 0);
        engine.ingest(
            [kernel(0, MS, 0), kernel(20 * MS, 21 * MS, 2)].concat(),
            0,
            0,
        );
        engine.evaluate(Instant::now()).unwrap();
        let windows = engine.finish(u64::MAX);
        assert_eq!(engine.revoked_windows(), 0);
        assert_eq!(windows[0].start_ns, MS);
        assert_eq!(windows[0].longest[0].latency_ns, 19 * MS);
    }

    #[test]
    fn an_open_window_beyond_twice_retention_is_lost() {
        let mut engine = TriggerEngine::new(condition(TriggerKind::Gap, 10, 1), 4, 0);
        engine.ingest(
            [kernel(0, MS, 0), kernel(20 * MS, 21 * MS, 2)].concat(),
            0,
            0,
        );
        engine.evaluate(Instant::now()).unwrap();
        // Five more kernels arrive before the window closes.
        for index in 0..5 {
            engine.ingest(
                kernel(
                    22 * MS + index * MS,
                    22 * MS + index * MS + 1,
                    4 + index * 2,
                ),
                0,
                0,
            );
        }
        assert!(engine.retained.len() <= 2 * 4 + 2);
        assert_eq!(engine.finish(u64::MAX).len(), 0);
        assert_eq!(engine.lost_windows(), 1);
    }

    #[test]
    fn a_duration_trigger_fires_on_a_long_activity() {
        let mut engine = TriggerEngine::new(condition(TriggerKind::Duration, 5, 1), 100, 0);
        engine.ingest([kernel(0, MS, 0), kernel(2 * MS, 9 * MS, 2)].concat(), 0, 0);
        engine.evaluate(Instant::now()).unwrap();
        let windows = engine.finish(u64::MAX);
        assert_eq!(windows[0].fired.latency_ns, 7 * MS);
        assert_eq!(windows[0].fired.start.timestamp_ns, 2 * MS);
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
