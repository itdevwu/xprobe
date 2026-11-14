use crate::MeasurementExecution;
use crate::failure::CommandFailure;
use crate::failure::measurement_failure;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;
use xprobe_collector::completed;
use xprobe_collector::cupti;
use xprobe_collector::linux::LinuxCaptureRequest;
use xprobe_collector::uprobe::UprobeRequest;
use xprobe_collector::{linux, uprobe};
use xprobe_core::cupti_compat;
use xprobe_core::gpu_aggregate;
use xprobe_core::inject;
use xprobe_core::inspect;
use xprobe_core::validate;
use xprobe_correlator::MeasureOptions;
use xprobe_correlator::measure;
use xprobe_protocol::AggregateActivity;
use xprobe_protocol::AggregateInventoryResult;
use xprobe_protocol::CuptiCollectionSummary;
use xprobe_protocol::ErrorCode;
use xprobe_protocol::Event;
use xprobe_protocol::EventType;
use xprobe_protocol::HostCaptureResult;
use xprobe_protocol::MatchPolicy;
use xprobe_protocol::MeasurementMode;
use xprobe_protocol::MeasurementResult;
use xprobe_protocol::ProcessReport;
use xprobe_protocol::ResolvedLinuxSelector;
use xprobe_protocol::ResolvedProbe;
use xprobe_protocol::SessionStatus;
use xprobe_protocol::TargetIdentity;
use xprobe_protocol::ValidatedEndpoint;
use xprobe_protocol::ValidationRequirements;
use xprobe_protocol::ValidationResult;
use xprobe_protocol::Warning;

pub(crate) struct LiveMeasureRequest {
    pub(crate) pid: u32,
    pub(crate) expected_target: Option<TargetIdentity>,
    pub(crate) cupti_socket: Option<PathBuf>,
    pub(crate) agent_path: Option<PathBuf>,
    pub(crate) timeout: Duration,
    pub(crate) match_policy_text: &'static str,
    pub(crate) mode: MeasurementMode,
    pub(crate) options: MeasureOptions,
}

/// Resolved endpoints and merged requirements for one live capture.
pub(crate) struct LivePlan {
    pub(crate) report: ProcessReport,
    pub(crate) endpoints: Vec<ValidatedEndpoint>,
    pub(crate) requirements: ValidationRequirements,
}

/// A correlated view of the capture that the live loop can finish with.
pub(crate) trait LiveOutcome {
    fn set_status(&mut self, status: SessionStatus);
    fn push_warning(&mut self, warning: Warning);
    fn into_events(self) -> Vec<Event>;
}

/// How a live capture is correlated and when it is complete.
pub(crate) trait LiveEvaluator {
    type Outcome: LiveOutcome;

    /// Correlate the capture so far. With `require_complete` false, a
    /// `NO_MATCHED_SAMPLES` failure means "keep collecting".
    fn evaluate(
        &self,
        host_captures: &[HostCaptureResult],
        collection: &LiveCollection,
        require_complete: bool,
    ) -> Result<Self::Outcome, CommandFailure>;

    /// Whether every requested sample bound has been reached.
    fn reached_samples(&self, outcome: &Self::Outcome) -> bool;
}

impl LiveOutcome for MeasurementExecution {
    fn set_status(&mut self, status: SessionStatus) {
        self.result.status = status;
    }

    fn push_warning(&mut self, warning: Warning) {
        self.result.warnings.push(warning);
    }

    fn into_events(self) -> Vec<Event> {
        self.events
    }
}

/// The single start/end edge of `measure --from/--to` and `MeasurementSpec`.
struct SingleEdge<'a>(&'a MeasureOptions);

impl LiveEvaluator for SingleEdge<'_> {
    type Outcome = MeasurementExecution;

    fn evaluate(
        &self,
        host_captures: &[HostCaptureResult],
        collection: &LiveCollection,
        require_complete: bool,
    ) -> Result<MeasurementExecution, CommandFailure> {
        measure_live_capture(host_captures, collection, self.0, require_complete)
    }

    fn reached_samples(&self, outcome: &MeasurementExecution) -> bool {
        self.0.samples.is_some_and(|samples| {
            outcome.result.measurement.samples.matched
                >= u64::try_from(samples).expect("sample limit fits u64")
        })
    }
}

type HostCaptureHandle = JoinHandle<Result<HostCaptureResult, CommandFailure>>;
pub(crate) const SNAPSHOT_QUIET_PERIOD: Duration = Duration::from_millis(100);

pub(crate) struct HostCollectors {
    pub(crate) cancelled: Arc<AtomicBool>,
    pub(crate) handles: Vec<HostCaptureHandle>,
}

impl HostCollectors {
    pub(crate) fn finished(&self) -> bool {
        self.handles.iter().all(JoinHandle::is_finished)
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn join(&mut self) -> Result<Vec<HostCaptureResult>, CommandFailure> {
        let mut captures = Vec::with_capacity(self.handles.len());
        for handle in self.handles.drain(..) {
            let result = handle.join().map_err(|_| {
                CommandFailure::new(ErrorCode::Internal, "host collector thread panicked", false)
            })?;
            captures.push(result?);
        }
        Ok(captures)
    }
}

impl Drop for HostCollectors {
    fn drop(&mut self) {
        self.cancel();
        for handle in self.handles.drain(..) {
            if handle.join().is_err() {
                eprintln!("xprobe: host collector thread panicked during cleanup");
            }
        }
    }
}

pub(crate) struct LiveCollection {
    pub(crate) report: ProcessReport,
    pub(crate) socket: Option<PathBuf>,
    pub(crate) deadline: Instant,
    pub(crate) collection_end: Option<Instant>,
    pub(crate) baseline_timestamp: Option<u64>,
    pub(crate) baseline_dropped: u64,
    pub(crate) baseline_unknown: u64,
    pub(crate) baseline_observed: u64,
    pub(crate) collectors: HostCollectors,
    pub(crate) host_captures: Option<Vec<HostCaptureResult>>,
    pub(crate) latest_cuda: Option<cupti::CuptiCapture>,
    pub(crate) cuda_record_offset: u64,
    pub(crate) managed_agent: bool,
    pub(crate) cupti_armed: bool,
    pub(crate) agent_injected: bool,
    pub(crate) agent_major: Option<u32>,
    pub(crate) agent_path: Option<PathBuf>,
    pub(crate) cupti_path: Option<PathBuf>,
}

pub(crate) fn collect_live_measurement(
    request: &LiveMeasureRequest,
) -> Result<MeasurementExecution, CommandFailure> {
    assert_eq!(request.mode, MeasurementMode::Exact);
    validate_live_limits(request)?;
    let plan = single_edge_plan(request)?;
    collect_live(plan, request, &SingleEdge(&request.options))
}

/// Run one bounded exact capture of `plan` and correlate it with `evaluator`.
///
/// Attachment, polling, timeout, CUPTI shutdown, cleanup failures, and
/// artifact preservation are shared by every exact live measurement.
pub(crate) fn collect_live<E: LiveEvaluator>(
    plan: LivePlan,
    request: &LiveMeasureRequest,
    evaluator: &E,
) -> Result<E::Outcome, CommandFailure> {
    let mut collection = start_live_collection(plan, request)?;

    let outcome = (|| {
        loop {
            refresh_live_sources(&mut collection, request)?;
            let now = Instant::now();
            if let Some(result) = evaluate_live_result(&collection, evaluator, now)? {
                break Ok(result);
            }
            if now >= collection.deadline {
                break finish_live_timeout(&mut collection, evaluator);
            }
            if collection.socket.is_none() {
                thread::sleep(Duration::from_millis(10));
            }
        }
    })();
    let cuda_capture = collection.cupti_armed;
    let stop_result = stop_cupti_agent(&mut collection, request);
    let mut execution = match (outcome, stop_result) {
        (Ok(mut execution), Ok(())) => {
            if cuda_capture && collection.host_captures.is_some() {
                let status = execution.1;
                execution.0 = evaluator.evaluate(
                    collection.host_captures.as_deref().unwrap_or(&[]),
                    &collection,
                    true,
                )?;
                execution.0.set_status(status);
            }
            execution.0
        }
        (Err(error), Ok(())) => {
            if cuda_capture && collection.host_captures.is_some() {
                return match evaluator.evaluate(
                    collection.host_captures.as_deref().unwrap_or(&[]),
                    &collection,
                    true,
                ) {
                    Ok(_) => Err(error),
                    Err(final_error) => Err(final_error),
                };
            }
            return Err(error);
        }
        (Ok(execution), Err(cleanup)) => {
            return Err(cleanup.with_artifact_events(execution.0.into_events()));
        }
        (Err(mut error), Err(cleanup)) => {
            let artifact_events = error.artifact_events.take();
            let mut failure = CommandFailure::new(
                ErrorCode::CleanupFailed,
                format!(
                    "{}; original measurement error: {}",
                    cleanup.message, error.message
                ),
                cleanup.recoverable,
            )
            .with_detail("cleanup_phase", "stop_cupti")
            .with_detail("original_error_code", error.code.to_string())
            .with_detail("cleanup_error_code", cleanup.code.to_string())
            .with_hint("verify the target state before starting another measurement");
            if let Some(events) = artifact_events {
                failure = failure.with_artifact_events(events);
            }
            return Err(failure);
        }
    };
    if collection.agent_injected {
        let mut details = BTreeMap::new();
        if let Some(major) = collection.agent_major {
            details.insert("cuda_major".to_owned(), serde_json::Value::from(major));
        }
        if let Some(path) = collection.agent_path.as_deref() {
            details.insert(
                "agent_path".to_owned(),
                serde_json::Value::from(path.display().to_string()),
            );
        }
        if let Some(path) = collection.cupti_path.as_deref() {
            details.insert(
                "cupti_path".to_owned(),
                serde_json::Value::from(path.display().to_string()),
            );
        }
        execution.push_warning(Warning {
            code: "CUPTI_AGENT_INJECTED".to_owned(),
            message: "xprobe injected the CUPTI agent and left the shared object mapped".to_owned(),
            details,
        });
    }
    Ok(execution)
}

pub(crate) fn collect_live_aggregate(
    request: &LiveMeasureRequest,
) -> Result<AggregateInventoryResult, CommandFailure> {
    assert_eq!(request.mode, MeasurementMode::Aggregate);
    validate_live_limits(request)?;
    let mut collection = prepare_live_collection(request)?;
    let collection_end = collection
        .collection_end
        .expect("aggregate validation requires duration");
    if collection_end > collection.deadline {
        return Err(CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            "aggregate duration must not exceed timeout",
            true,
        ));
    }

    while Instant::now() < collection_end {
        let remaining = collection_end.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
    let target_result = inspect::verify_target(&collection.report.target)
        .map_err(|error| CommandFailure::new(error.code(), error.to_string(), error.recoverable()));
    let stop_result = stop_cupti_agent(&mut collection, request);
    match (target_result, stop_result) {
        (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
        (Err(target), Err(cleanup)) => {
            return Err(CommandFailure::new(
                ErrorCode::CleanupFailed,
                format!(
                    "{}; target verification also failed: {}",
                    cleanup.message, target.message
                ),
                cleanup.recoverable,
            )
            .with_detail("cleanup_phase", "stop_cupti")
            .with_detail("target_error_code", target.code.to_string())
            .with_hint("verify the target state before starting another measurement"));
        }
        (Ok(()), Ok(())) => {}
    }

    let capture = collection.latest_cuda.as_ref().ok_or_else(|| {
        CommandFailure::new(
            ErrorCode::CuptiNotAvailable,
            "CUPTI Agent returned no aggregate capture",
            false,
        )
    })?;
    let mut result = aggregate_inventory_result(capture, request)?;
    if collection.agent_injected {
        result.warnings.push(injection_warning(&collection));
    }
    Ok(result)
}

pub(crate) fn validate_live_limits(request: &LiveMeasureRequest) -> Result<(), CommandFailure> {
    if request.timeout.is_zero() {
        return Err(CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            "timeout must be greater than zero",
            true,
        ));
    }
    if request.options.samples == Some(0)
        || request
            .options
            .duration
            .is_some_and(|duration| duration.is_zero())
        || request.options.max_events == 0
        || (request.options.samples.is_none() && request.options.duration.is_none())
    {
        return Err(CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            "live measurement requires positive samples or duration and max-events limits",
            true,
        ));
    }
    if request.mode == MeasurementMode::Aggregate {
        if request.options.samples.is_some()
            || request.options.duration.is_none()
            || request.options.match_policy != MatchPolicy::Exact
        {
            return Err(CommandFailure::new(
                ErrorCode::InvalidCorrelationPolicy,
                "aggregate measurement requires duration, exact activity endpoints, and no samples limit",
                true,
            ));
        }
        if request.options.duration > Some(request.timeout) {
            return Err(CommandFailure::new(
                ErrorCode::SessionLimitExceeded,
                "aggregate duration must not exceed timeout",
                true,
            ));
        }
    }
    Ok(())
}

pub(crate) fn prepare_live_collection(
    request: &LiveMeasureRequest,
) -> Result<LiveCollection, CommandFailure> {
    start_live_collection(single_edge_plan(request)?, request)
}

/// Validate the request's start/end pair into a capture plan.
fn single_edge_plan(request: &LiveMeasureRequest) -> Result<LivePlan, CommandFailure> {
    let report = inspect::run(request.pid).map_err(|error| {
        CommandFailure::new(error.code(), error.to_string(), error.recoverable())
    })?;
    if request
        .expected_target
        .as_ref()
        .is_some_and(|expected| expected != &report.target)
    {
        return Err(CommandFailure::new(
            ErrorCode::TargetReused,
            "trace specification target identity no longer matches the process",
            true,
        ));
    }
    let validation = validate::run(
        &report,
        &request.options.start_selector,
        &request.options.end_selector,
        request.match_policy_text,
    )
    .map_err(|error| CommandFailure::new(error.code(), error.to_string(), error.recoverable()))?;
    if let Some(issue) = validation.issues.first() {
        return Err(CommandFailure::new(issue.code, issue.message.clone(), true)
            .with_detail(
                "recommended_policy",
                match_policy_name(validation.policy_recommendation.policy),
            )
            .with_detail(
                "compatible_policies",
                serde_json::to_value(&validation.policy_recommendation.compatible_policies)
                    .expect("match policies must serialize"),
            )
            .with_hint("rerun validate with an explicitly compatible policy"));
    }
    if request.mode == MeasurementMode::Aggregate {
        validate_aggregate_selection(&validation)?;
    }
    Ok(LivePlan {
        report,
        endpoints: vec![validation.start, validation.end],
        requirements: validation.requirements,
    })
}

/// Arm CUPTI and attach host collectors for a validated plan.
pub(crate) fn start_live_collection(
    plan: LivePlan,
    request: &LiveMeasureRequest,
) -> Result<LiveCollection, CommandFailure> {
    let LivePlan {
        report,
        endpoints,
        requirements,
    } = plan;

    let activation = prepare_cupti_activation(&report, &requirements, request)?;
    let arm_config = cupti_arm_config(
        &endpoints,
        &requirements,
        request.options.max_events,
        request.mode,
    )?;
    let baseline = arm_cupti_capture(
        &activation,
        arm_config.as_ref(),
        requirements.needs_nvtx,
        request,
    )?;
    let socket = activation.socket;
    let baseline_timestamp = baseline
        .as_ref()
        .and_then(|capture| capture.events.last())
        .map(|event| event.timestamp_ns);
    let baseline_dropped = baseline
        .as_ref()
        .map_or(0, |capture| capture.dropped_records);
    let baseline_unknown = baseline
        .as_ref()
        .map_or(0, |capture| capture.unknown_records);
    let baseline_observed = baseline
        .as_ref()
        .map_or(0, |capture| capture.observed_records);
    let started = Instant::now();
    let deadline = started.checked_add(request.timeout).ok_or_else(|| {
        CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            "timeout exceeds Instant range",
            true,
        )
    })?;
    let collection_end = request
        .options
        .duration
        .and_then(|duration| started.checked_add(duration));
    let collectors = start_host_collectors(&report, &endpoints, request)?;
    let host_captures = collectors.handles.is_empty().then(Vec::new);

    Ok(LiveCollection {
        report,
        socket,
        deadline,
        collection_end,
        baseline_timestamp,
        baseline_dropped,
        baseline_unknown,
        baseline_observed,
        collectors,
        host_captures,
        latest_cuda: None,
        cuda_record_offset: 0,
        managed_agent: activation.managed,
        cupti_armed: baseline.is_some(),
        agent_injected: activation.injected,
        agent_major: activation.major,
        agent_path: activation.agent_path,
        cupti_path: activation.cupti_path,
    })
}

pub(crate) fn validate_aggregate_selection(
    validation: &ValidationResult,
) -> Result<(), CommandFailure> {
    let (Some(start), Some(end)) = (validation.start.cuda.as_ref(), validation.end.cuda.as_ref())
    else {
        return Err(CommandFailure::new(
            ErrorCode::InvalidEventSelector,
            "aggregate measurement supports CUPTI activity endpoints only",
            true,
        ));
    };
    let paired = matches!(
        (&start.event_type, &end.event_type),
        (&EventType::GpuKernelStart, &EventType::GpuKernelEnd)
            | (&EventType::GpuMemcpyStart, &EventType::GpuMemcpyEnd)
            | (&EventType::GpuMemsetStart, &EventType::GpuMemsetEnd)
    );
    if !paired
        || start.api_domain != end.api_domain
        || start.api_name != end.api_name
        || start.kernel_name_regex != end.kernel_name_regex
        || start.memcpy_kind != end.memcpy_kind
    {
        return Err(CommandFailure::new(
            ErrorCode::InvalidEventSelector,
            "aggregate measurement requires matching kernel, memcpy, or memset start/end selectors",
            true,
        ));
    }
    if let Some(pattern) = start.kernel_name_regex.as_deref()
        && pattern != ".*"
        && matches!(
            cupti::bounded_name_filter(pattern),
            cupti::CuptiNameFilter::Any
        )
    {
        return Err(CommandFailure::new(
            ErrorCode::InvalidEventSelector,
            "aggregate kernel regex must be an exact, prefix, suffix, or contains pattern that the CUPTI Agent can apply",
            true,
        )
        .with_hint("use ^literal$, ^literal.*, .*literal$, or .*literal.*"));
    }
    Ok(())
}

pub(crate) fn arm_cupti_capture(
    activation: &CuptiActivation,
    config: Option<&cupti::CuptiArmConfig>,
    needs_nvtx: bool,
    request: &LiveMeasureRequest,
) -> Result<Option<cupti::CuptiCapture>, CommandFailure> {
    let (Some(path), Some(config)) = (activation.socket.as_deref(), config) else {
        assert!(activation.socket.is_none() && config.is_none());
        return Ok(None);
    };
    let capture = match cupti::arm(path, request.timeout, &request.options.session_id, config) {
        Ok(capture) => capture,
        Err(error) => {
            let failure =
                CommandFailure::new(ErrorCode::CuptiNotAvailable, error.to_string(), true);
            return cleanup_failed_arm(activation, request, failure);
        }
    };
    if needs_nvtx && !capture.nvtx_callbacks_active {
        let failure = CommandFailure::new(
            ErrorCode::CuptiNotAvailable,
            "the mapped CUPTI agent was not initialized through NVTX; restart the target with NVTX_INJECTION64_PATH set to the same agent before the first NVTX call",
            true,
        )
        .with_hint("online CUDA injection cannot retrofit an initialized NVTX dispatch table");
        return cleanup_failed_arm(activation, request, failure);
    }
    if capture.state != cupti::CuptiCaptureState::Active {
        let failure = CommandFailure::new(
            ErrorCode::CuptiNotAvailable,
            format!(
                "CUPTI Agent did not enter active state after ARM: {:?}",
                capture.state
            ),
            true,
        );
        return cleanup_failed_arm(activation, request, failure);
    }
    Ok(Some(capture))
}

pub(crate) fn cleanup_failed_arm(
    activation: &CuptiActivation,
    request: &LiveMeasureRequest,
    failure: CommandFailure,
) -> Result<Option<cupti::CuptiCapture>, CommandFailure> {
    if !activation.managed {
        return Err(failure);
    }
    let path = activation
        .socket
        .as_deref()
        .expect("managed activation has a socket");
    match cupti::close(path, request.timeout, &request.options.session_id, 0) {
        Ok(_) => Err(failure),
        Err(cleanup) => Err(CommandFailure::new(
            ErrorCode::CleanupFailed,
            format!(
                "failed to close CUPTI agent after ARM error: {cleanup}; original error: {}",
                failure.message
            ),
            true,
        )
        .with_detail("cleanup_phase", "close_after_arm_failure")
        .with_detail("original_error_code", failure.code.to_string())
        .with_hint("verify the target state before starting another measurement")),
    }
}

pub(crate) fn cupti_arm_config(
    endpoints: &[ValidatedEndpoint],
    requirements: &ValidationRequirements,
    max_events: usize,
    mode: MeasurementMode,
) -> Result<Option<cupti::CuptiArmConfig>, CommandFailure> {
    if !requirements.needs_cupti {
        return Ok(None);
    }
    let mut filters = endpoints
        .iter()
        .filter_map(|endpoint| endpoint.cuda.as_ref())
        .map(|selector| {
            cupti::event_filter(selector).map_err(|error| {
                CommandFailure::new(ErrorCode::InvalidEventSelector, error.to_string(), false)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if mode == MeasurementMode::Exact {
        let mut unique = Vec::with_capacity(filters.len());
        for filter in filters {
            if !unique.contains(&filter) {
                unique.push(filter);
            }
        }
        filters = unique;
    }
    let record_capacity = u64::try_from(max_events).map_err(|error| {
        CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            format!("max-events exceeds the CUPTI Agent range: {error}"),
            true,
        )
    })?;
    Ok(Some(cupti::CuptiArmConfig {
        record_capacity,
        capture_mode: match mode {
            MeasurementMode::Exact => cupti::CuptiCaptureMode::Exact,
            MeasurementMode::Aggregate => cupti::CuptiCaptureMode::Aggregate,
        },
        filters,
    }))
}

pub(crate) struct CuptiActivation {
    pub(crate) socket: Option<PathBuf>,
    pub(crate) managed: bool,
    pub(crate) injected: bool,
    pub(crate) major: Option<u32>,
    pub(crate) agent_path: Option<PathBuf>,
    pub(crate) cupti_path: Option<PathBuf>,
}

pub(crate) struct AgentSelection {
    pub(crate) path: PathBuf,
    pub(crate) major: Option<u32>,
    pub(crate) cupti_path: Option<PathBuf>,
}

pub(crate) fn prepare_cupti_activation(
    report: &ProcessReport,
    requirements: &ValidationRequirements,
    request: &LiveMeasureRequest,
) -> Result<CuptiActivation, CommandFailure> {
    if !requirements.needs_cupti {
        if request.cupti_socket.is_some() {
            return Err(CommandFailure::new(
                ErrorCode::InvalidEventSelector,
                "--cupti-socket is only valid when a CUDA endpoint is selected",
                true,
            ));
        }
        return Ok(CuptiActivation {
            socket: None,
            managed: false,
            injected: false,
            major: None,
            agent_path: None,
            cupti_path: None,
        });
    }
    if let Some(socket) = request.cupti_socket.clone() {
        return Ok(CuptiActivation {
            socket: Some(socket),
            managed: false,
            injected: false,
            major: None,
            agent_path: None,
            cupti_path: None,
        });
    }

    let socket = std::env::temp_dir().join(format!(
        "xprobe-{}-{}.sock",
        request.pid,
        std::process::id()
    ));
    let selection = if report.cuda.xprobe_cupti_loaded {
        AgentSelection {
            path: PathBuf::new(),
            major: cupti_compat::target_major(report)
                .map_err(|error| CommandFailure::new(error.code(), error.to_string(), true))?,
            cupti_path: None,
        }
    } else {
        resolve_agent_path(report, request.agent_path.as_deref())?
    };
    eprintln!(
        "xprobe: warning: activating the CUPTI agent modifies target PID {}{}{}",
        request.pid,
        selection
            .major
            .map_or_else(String::new, |major| format!(" with CUDA {major} Agent")),
        selection
            .cupti_path
            .as_deref()
            .map_or_else(String::new, |path| format!(" using {}", path.display()))
    );
    let record_capacity = u64::try_from(request.options.max_events).map_err(|error| {
        CommandFailure::new(
            ErrorCode::SessionLimitExceeded,
            format!("max-events exceeds the CUPTI Agent range: {error}"),
            true,
        )
    })?;
    let activation = inject::activate(
        report,
        &selection.path,
        &socket,
        record_capacity,
        request.timeout,
    )
    .map_err(|error| CommandFailure::new(error.code(), error.to_string(), error.recoverable()))?;
    Ok(CuptiActivation {
        socket: Some(activation.socket_path),
        managed: true,
        injected: activation.injected,
        major: selection.major,
        agent_path: activation.injected.then_some(selection.path),
        cupti_path: selection.cupti_path,
    })
}

pub(crate) fn resolve_agent_path(
    report: &ProcessReport,
    configured: Option<&Path>,
) -> Result<AgentSelection, CommandFailure> {
    if let Some(path) = configured {
        return Ok(AgentSelection {
            path: path.to_owned(),
            major: cupti_compat::target_major(report)
                .map_err(|error| CommandFailure::new(error.code(), error.to_string(), true))?,
            cupti_path: None,
        });
    }
    if let Some(path) = std::env::var_os("XPROBE_CUPTI_AGENT_PATH") {
        return Ok(AgentSelection {
            path: PathBuf::from(path),
            major: cupti_compat::target_major(report)
                .map_err(|error| CommandFailure::new(error.code(), error.to_string(), true))?,
            cupti_path: None,
        });
    }
    let cupti = cupti_compat::resolve_library(report)
        .map_err(|error| CommandFailure::new(error.code(), error.to_string(), true))?;
    let executable = std::env::current_exe().map_err(|error| {
        CommandFailure::new(
            ErrorCode::CuptiNotAvailable,
            format!("failed to locate xprobe executable: {error}"),
            true,
        )
    })?;
    let parent = executable
        .parent()
        .expect("executable has a parent directory");
    let candidates = [
        parent.join(format!(
            "../lib/xprobe/cuda{}/libxprobe-cupti.so",
            cupti.major
        )),
        parent.join(format!("cuda{}/libxprobe-cupti.so", cupti.major)),
        PathBuf::from(format!(
            "build/cupti/cuda{}/libxprobe-cupti.so",
            cupti.major
        )),
    ];
    let path = candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            CommandFailure::new(
                ErrorCode::CuptiNotAvailable,
                format!(
                    "CUDA {} CUPTI agent was not found; pass --agent or set XPROBE_CUPTI_AGENT_PATH",
                    cupti.major
                ),
                true,
            )
        })?;
    Ok(AgentSelection {
        path,
        major: Some(cupti.major),
        cupti_path: Some(cupti.path),
    })
}

pub(crate) fn stop_cupti_agent(
    collection: &mut LiveCollection,
    request: &LiveMeasureRequest,
) -> Result<(), CommandFailure> {
    if !collection.cupti_armed {
        return Ok(());
    }
    let socket = collection
        .socket
        .as_deref()
        .expect("armed CUPTI agent has a socket");
    collection.cupti_armed = false;
    let capture = if collection.managed_agent {
        cupti::close(
            socket,
            request.timeout,
            &request.options.session_id,
            collection.cuda_record_offset,
        )
    } else {
        cupti::stop(
            socket,
            request.timeout,
            &request.options.session_id,
            collection.cuda_record_offset,
        )
    }
    .map_err(|error| {
        CommandFailure::new(ErrorCode::CleanupFailed, error.to_string(), true)
            .with_detail("cleanup_phase", "stop_cupti")
            .with_hint("verify the target state before starting another measurement")
    })?;
    append_cuda_capture(collection, capture)?;
    collection.managed_agent = false;
    Ok(())
}

impl Drop for LiveCollection {
    fn drop(&mut self) {
        if self.cupti_armed {
            if let Some(socket) = self.socket.as_deref() {
                let result = if self.managed_agent {
                    cupti::close(
                        socket,
                        Duration::from_secs(2),
                        "xp_cleanup",
                        self.cuda_record_offset,
                    )
                } else {
                    cupti::stop(
                        socket,
                        Duration::from_secs(2),
                        "xp_cleanup",
                        self.cuda_record_offset,
                    )
                };
                if let Err(error) = result {
                    eprintln!("xprobe: failed to stop CUPTI agent during cleanup: {error}");
                }
            }
        }
    }
}

pub(crate) fn start_host_collectors(
    report: &ProcessReport,
    endpoints: &[ValidatedEndpoint],
    request: &LiveMeasureRequest,
) -> Result<HostCollectors, CommandFailure> {
    inspect::verify_target(&report.target).map_err(|error| {
        CommandFailure::new(error.code(), error.to_string(), error.recoverable())
    })?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut probes = Vec::new();
    let mut linux_probes = Vec::new();
    for endpoint in endpoints {
        if let Some(probe) = endpoint.host.as_ref()
            && !probes
                .iter()
                .any(|existing: &ResolvedProbe| existing.selector == probe.selector)
        {
            probes.push(probe.clone());
        }
        if let Some(probe) = endpoint.linux.as_ref()
            && !linux_probes
                .iter()
                .any(|existing: &ResolvedLinuxSelector| existing == probe)
        {
            linux_probes.push(probe.clone());
        }
    }
    let host_timeout = request
        .options
        .duration
        .map_or(request.timeout, |duration| duration.min(request.timeout));
    let host_samples = request
        .options
        .samples
        .unwrap_or(request.options.max_events);
    let mut receivers = Vec::with_capacity(probes.len() + usize::from(!linux_probes.is_empty()));
    let mut handles = probes
        .into_iter()
        .enumerate()
        .map(|(index, probe)| {
            let (ready, receiver) = mpsc::sync_channel(1);
            receivers.push(receiver);
            let offset = if probe.symbol.is_some() {
                0
            } else {
                probe.file_offset
            };
            let capture_request = UprobeRequest {
                target: report.target.clone(),
                binary: PathBuf::from(&probe.binary_path),
                symbol: probe.symbol,
                symbol_demangled: probe.symbol_demangled,
                offset,
                probe_kind: probe.probe_kind,
                probe_id: u32::try_from(index + 1).expect("bounded endpoints fit u32"),
                samples: host_samples,
                timeout: host_timeout,
                cancelled: Arc::clone(&cancelled),
                ready: Some(ready),
            };
            thread::spawn(move || {
                uprobe::capture(&capture_request).map_err(|error| {
                    CommandFailure::new(error.code(), error.to_string(), error.recoverable())
                })
            })
        })
        .collect::<Vec<_>>();
    if !linux_probes.is_empty() {
        let (ready, receiver) = mpsc::sync_channel(1);
        receivers.push(receiver);
        let endpoint_count = linux_probes.len();
        let event_limit = linux_capture_event_limit(&request.options, endpoint_count);
        let capture_request = LinuxCaptureRequest {
            target: report.target.clone(),
            probes: linux_probes,
            event_limit,
            capacity_limit: request.options.samples.is_none(),
            timeout: host_timeout,
            cancelled: Arc::clone(&cancelled),
            ready: Some(ready),
        };
        handles.push(thread::spawn(move || {
            linux::capture(&capture_request).map_err(|error| {
                CommandFailure::new(error.code(), error.to_string(), error.recoverable())
            })
        }));
    }
    let mut collectors = HostCollectors { cancelled, handles };
    wait_for_host_collectors(&mut collectors, receivers, request.timeout)?;
    if let Err(error) = inspect::verify_target(&report.target) {
        collectors.cancel();
        collectors.join()?;
        return Err(CommandFailure::new(
            error.code(),
            error.to_string(),
            error.recoverable(),
        ));
    }
    Ok(collectors)
}

pub(crate) fn linux_capture_event_limit(options: &MeasureOptions, endpoint_count: usize) -> usize {
    options
        .samples
        .and_then(|samples| {
            samples
                .checked_mul(endpoint_count)
                .and_then(|events| events.checked_add(endpoint_count))
        })
        .unwrap_or(options.max_events)
        .min(options.max_events)
}

pub(crate) fn wait_for_host_collectors(
    collectors: &mut HostCollectors,
    receivers: Vec<mpsc::Receiver<()>>,
    timeout: Duration,
) -> Result<(), CommandFailure> {
    for receiver in receivers {
        match receiver.recv_timeout(timeout) {
            Ok(()) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                collectors.cancel();
                return match collectors.join() {
                    Err(error) => Err(error),
                    Ok(_) => Err(CommandFailure::new(
                        ErrorCode::Internal,
                        "host collector exited before reporting readiness",
                        false,
                    )),
                };
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                collectors.cancel();
                collectors.join()?;
                return Err(CommandFailure::new(
                    ErrorCode::SessionLimitExceeded,
                    "timed out waiting for host collector readiness",
                    true,
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn refresh_live_sources(
    collection: &mut LiveCollection,
    request: &LiveMeasureRequest,
) -> Result<(), CommandFailure> {
    if collection.host_captures.is_none() && collection.collectors.finished() {
        collection.host_captures = Some(collection.collectors.join()?);
    }
    let Some(path) = collection.socket.as_deref() else {
        return Ok(());
    };
    let remaining = collection
        .deadline
        .saturating_duration_since(Instant::now());
    if remaining <= SNAPSHOT_QUIET_PERIOD {
        collection.collectors.cancel();
        return Ok(());
    }
    let capture = cupti::snapshot(
        path,
        remaining,
        &request.options.session_id,
        collection.cuda_record_offset,
    )
    .map_err(|error| CommandFailure::new(ErrorCode::CuptiNotAvailable, error.to_string(), true))?;
    append_cuda_capture(collection, capture)?;
    Ok(())
}

pub(crate) fn append_cuda_capture(
    collection: &mut LiveCollection,
    mut capture: cupti::CuptiCapture,
) -> Result<(), CommandFailure> {
    if capture.record_offset != collection.cuda_record_offset {
        return Err(CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!(
                "CUPTI incremental capture started at record {}, expected {}",
                capture.record_offset, collection.cuda_record_offset
            ),
            false,
        ));
    }
    let returned = u64::try_from(capture.events.len()).map_err(|error| {
        CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!("CUPTI incremental event count exceeds u64: {error}"),
            false,
        )
    })?;
    let next_offset = capture.record_offset.checked_add(returned).ok_or_else(|| {
        CommandFailure::new(
            ErrorCode::TraceExportFailed,
            "CUPTI incremental record offset overflowed",
            false,
        )
    })?;
    if let Some(accumulated) = collection.latest_cuda.as_mut() {
        if accumulated.record_capacity != capture.record_capacity {
            return Err(CommandFailure::new(
                ErrorCode::TraceExportFailed,
                format!(
                    "CUPTI record capacity changed from {} to {} during capture",
                    accumulated.record_capacity, capture.record_capacity
                ),
                false,
            ));
        }
        if capture.observed_records < accumulated.observed_records
            || capture.agent_dropped_records < accumulated.agent_dropped_records
            || capture.cupti_dropped_records < accumulated.cupti_dropped_records
            || capture.unknown_records < accumulated.unknown_records
        {
            return Err(CommandFailure::new(
                ErrorCode::TraceExportFailed,
                "CUPTI incremental counters moved backwards",
                false,
            ));
        }
        accumulated.state = capture.state;
        accumulated.stop_reason = capture.stop_reason;
        accumulated.observed_records = capture.observed_records;
        accumulated.agent_dropped_records = capture.agent_dropped_records;
        accumulated.cupti_dropped_records = capture.cupti_dropped_records;
        accumulated.dropped_records = capture.dropped_records;
        accumulated.unknown_records = capture.unknown_records;
        accumulated.events.append(&mut capture.events);
    } else {
        capture.record_offset = 0;
        collection.latest_cuda = Some(capture);
    }
    collection.cuda_record_offset = next_offset;
    Ok(())
}

pub(crate) fn aggregate_inventory_result(
    capture: &cupti::CuptiCapture,
    request: &LiveMeasureRequest,
) -> Result<AggregateInventoryResult, CommandFailure> {
    validate_aggregate_capture(capture)?;
    let capture = gpu_aggregate::GpuAggregateCapture {
        groups: capture
            .aggregate_groups
            .iter()
            .map(|group| gpu_aggregate::RawGpuAggregateGroup {
                activity: match group.activity {
                    cupti::CuptiAggregateActivity::Kernel => AggregateActivity::Kernel,
                    cupti::CuptiAggregateActivity::Memcpy => AggregateActivity::Memcpy,
                    cupti::CuptiAggregateActivity::Memset => AggregateActivity::Memset,
                },
                name: group.name.clone(),
                name_complete: group.name_complete,
                device_id: group.device_id,
                memcpy_kind: group.memcpy_kind.clone(),
                count: group.count,
                total_duration_ns: group.total_duration_ns,
                min_duration_ns: group.min_duration_ns,
                max_duration_ns: group.max_duration_ns,
                total_bytes: group.total_bytes,
            })
            .collect(),
        observed_activities: capture.observed_records,
        group_capacity: capture.record_capacity,
    };
    let options = &request.options;
    gpu_aggregate::analyze(
        gpu_aggregate::GpuAggregateRequest {
            session_id: options.session_id.clone(),
            name: options.name.clone(),
            start_selector: options.start_selector.clone(),
            end_selector: options.end_selector.clone(),
        },
        capture,
    )
    .map_err(|error| CommandFailure::new(error.code(), error.to_string(), error.recoverable()))
}

pub(crate) fn validate_aggregate_capture(
    capture: &cupti::CuptiCapture,
) -> Result<(), CommandFailure> {
    if capture.state == cupti::CuptiCaptureState::LimitReached {
        return Err(CommandFailure::new(
            ErrorCode::EventRateTooHigh,
            "aggregate group table reached its configured capacity",
            true,
        )
        .with_detail("group_capacity", capture.record_capacity)
        .with_detail("observed_activities", capture.observed_records)
        .with_hint("narrow the selector or explicitly increase max-groups"));
    }
    if capture.state != cupti::CuptiCaptureState::Stopped
        || capture.stop_reason != cupti::CuptiStopReason::Requested
    {
        return Err(CommandFailure::new(
            ErrorCode::CuptiNotAvailable,
            format!(
                "aggregate CUPTI capture ended in state {:?} with reason {:?}",
                capture.state, capture.stop_reason
            ),
            true,
        ));
    }
    if capture.dropped_records != 0 {
        return Err(CommandFailure::new(
            ErrorCode::EventsDropped,
            "aggregate CUPTI capture dropped activities",
            true,
        )
        .with_detail("dropped_activities", capture.dropped_records)
        .with_hint("reduce capture duration or narrow the activity selector"));
    }
    if capture.unknown_records != 0 {
        return Err(CommandFailure::new(
            ErrorCode::TraceExportFailed,
            "aggregate CUPTI capture contains unknown activities",
            false,
        )
        .with_detail("unknown_records", capture.unknown_records)
        .with_hint("rebuild xprobe and the CUPTI Agent from the same release"));
    }
    if !capture.events.is_empty() {
        return Err(CommandFailure::new(
            ErrorCode::TraceExportFailed,
            "aggregate CUPTI capture unexpectedly contains exact events",
            false,
        ));
    }
    Ok(())
}

pub(crate) fn injection_warning(collection: &LiveCollection) -> Warning {
    let mut details = BTreeMap::new();
    if let Some(major) = collection.agent_major {
        details.insert("cuda_major".to_owned(), serde_json::Value::from(major));
    }
    if let Some(path) = collection.agent_path.as_deref() {
        details.insert(
            "agent_path".to_owned(),
            serde_json::Value::from(path.display().to_string()),
        );
    }
    if let Some(path) = collection.cupti_path.as_deref() {
        details.insert(
            "cupti_path".to_owned(),
            serde_json::Value::from(path.display().to_string()),
        );
    }
    Warning {
        code: "CUPTI_AGENT_INJECTED".to_owned(),
        message: "xprobe injected the CUPTI agent and left the shared object mapped".to_owned(),
        details,
    }
}

pub(crate) fn evaluate_live_result<E: LiveEvaluator>(
    collection: &LiveCollection,
    evaluator: &E,
    now: Instant,
) -> Result<Option<(E::Outcome, SessionStatus)>, CommandFailure> {
    let Some(host) = collection.host_captures.as_ref() else {
        return Ok(None);
    };
    if collection.socket.is_some() && collection.latest_cuda.is_none() {
        return Ok(None);
    }
    let mut outcome = match evaluator.evaluate(host, collection, false) {
        Ok(outcome) => outcome,
        Err(error) if error.code == ErrorCode::NoMatchedSamples => return Ok(None),
        Err(error) => return Err(error),
    };
    let reached_duration = collection.collection_end.is_some_and(|end| now >= end);
    if evaluator.reached_samples(&outcome) || reached_duration {
        inspect::verify_target(&collection.report.target).map_err(|error| {
            CommandFailure::new(error.code(), error.to_string(), error.recoverable())
        })?;
        return Ok(Some((outcome, SessionStatus::Completed)));
    }
    if now >= collection.deadline {
        outcome.set_status(SessionStatus::TimedOut);
        return Ok(Some((outcome, SessionStatus::TimedOut)));
    }
    Ok(None)
}

pub(crate) fn finish_live_timeout<E: LiveEvaluator>(
    collection: &mut LiveCollection,
    evaluator: &E,
) -> Result<(E::Outcome, SessionStatus), CommandFailure> {
    collection.collectors.cancel();
    if collection.host_captures.is_none() {
        collection.host_captures = Some(collection.collectors.join()?);
    }
    let mut outcome = evaluator
        .evaluate(
            collection
                .host_captures
                .as_ref()
                .expect("host captures were assigned"),
            collection,
            true,
        )
        .map_err(|mut error| {
            if error.code == ErrorCode::NoMatchedSamples {
                let host_events = collection.host_captures.as_ref().map_or(0, |captures| {
                    captures.iter().map(|capture| capture.events.len()).sum()
                });
                let cuda_events = collection.latest_cuda.as_ref().map_or(0, |capture| {
                    capture
                        .events
                        .iter()
                        .filter(|event| {
                            collection
                                .baseline_timestamp
                                .is_none_or(|start| event.timestamp_ns > start)
                        })
                        .count()
                });
                error.message = format!(
                    "no event pairs matched before the live measurement timeout \
                 (host events: {host_events}, CUDA events: {cuda_events})"
                );
                error
                    .with_detail("timed_out", true)
                    .with_detail("host_events", host_events as u64)
                    .with_detail("cuda_events", cuda_events as u64)
            } else {
                error
            }
        })?;
    outcome.set_status(SessionStatus::TimedOut);
    Ok((outcome, SessionStatus::TimedOut))
}

pub(crate) fn measure_live_capture(
    host_captures: &[HostCaptureResult],
    collection: &LiveCollection,
    options: &MeasureOptions,
    require_complete: bool,
) -> Result<MeasurementExecution, CommandFailure> {
    let capture = checked_live_capture(
        host_captures,
        collection,
        &options.session_id,
        require_complete,
    )?;
    let options = MeasureOptions {
        dropped_events: capture.dropped_records,
        ..options.clone()
    };
    let mut result = measure(&capture.events, &options).map_err(|error| {
        measurement_failure(&error, &options, &capture.events, require_complete)
    })?;
    apply_collection_summary(&mut result, &capture);
    Ok(MeasurementExecution {
        result,
        events: capture.events,
    })
}

/// Merge the live sources into one capture and reject incomplete or unknown
/// records, preserving the events as an artifact on failure.
pub(crate) fn checked_live_capture(
    host_captures: &[HostCaptureResult],
    collection: &LiveCollection,
    session_id: &str,
    require_complete: bool,
) -> Result<completed::CompletedCapture, CommandFailure> {
    let capture = completed_live_capture(host_captures, collection, session_id)?;
    reject_incomplete_capture(&capture, true, require_complete)
        .map_err(|error| error.with_artifact_events(capture.events.clone()))?;
    if capture.unknown_records != 0 {
        return Err(CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!(
                "live capture contains {} unknown CUPTI activity records",
                capture.unknown_records
            ),
            false,
        )
        .with_detail("unknown_records", capture.unknown_records)
        .with_hint("rebuild xprobe and the CUPTI Agent from the same release")
        .with_artifact_events(capture.events));
    }
    Ok(capture)
}

pub(crate) fn completed_live_capture(
    host_captures: &[HostCaptureResult],
    collection: &LiveCollection,
    session_id: &str,
) -> Result<completed::CompletedCapture, CommandFailure> {
    let mut captures = host_captures
        .iter()
        .map(|capture| completed::CompletedCapture {
            dropped_records: capture.dropped,
            unknown_records: 0,
            record_limit_reached: capture.record_limit_reached.then_some(capture.captured),
            capture_failed: false,
            cupti: None,
            events: capture.events.clone(),
        })
        .collect::<Vec<_>>();
    if let Some(cuda) = collection.latest_cuda.as_ref() {
        let dropped_records = cuda
            .dropped_records
            .checked_sub(collection.baseline_dropped)
            .ok_or_else(|| {
                CommandFailure::new(
                    ErrorCode::TraceExportFailed,
                    "CUPTI dropped-record counter moved backwards",
                    false,
                )
            })?;
        let unknown_records = cuda
            .unknown_records
            .checked_sub(collection.baseline_unknown)
            .ok_or_else(|| {
                CommandFailure::new(
                    ErrorCode::TraceExportFailed,
                    "CUPTI unknown-record counter moved backwards",
                    false,
                )
            })?;
        let observed_records = cuda
            .observed_records
            .checked_sub(collection.baseline_observed)
            .ok_or_else(|| {
                CommandFailure::new(
                    ErrorCode::TraceExportFailed,
                    "CUPTI observed-record counter moved backwards",
                    false,
                )
            })?;
        captures.push(completed::CompletedCapture {
            dropped_records,
            unknown_records,
            record_limit_reached: (cuda.state == cupti::CuptiCaptureState::LimitReached)
                .then_some(cuda.record_capacity),
            capture_failed: matches!(
                cuda.state,
                cupti::CuptiCaptureState::Idle | cupti::CuptiCaptureState::Failed
            ),
            cupti: Some(completed::CompletedCuptiStatistics {
                complete: cuda.state == cupti::CuptiCaptureState::Stopped,
                record_capacity: cuda.record_capacity,
                observed_records,
                dropped_records,
            }),
            events: cuda
                .events
                .iter()
                .filter(|event| {
                    collection
                        .baseline_timestamp
                        .is_none_or(|start| event.timestamp_ns > start)
                })
                .cloned()
                .collect(),
        });
    }
    completed::merge(captures, session_id).map_err(|error| {
        CommandFailure::new(ErrorCode::TraceExportFailed, error.to_string(), false)
    })
}

pub(crate) fn reject_incomplete_capture(
    capture: &completed::CompletedCapture,
    live: bool,
    require_complete: bool,
) -> Result<(), CommandFailure> {
    if capture.capture_failed {
        return Err(CommandFailure::new(
            ErrorCode::CuptiNotAvailable,
            format!(
                "{}CUPTI capture entered a failed state",
                if live { "live " } else { "" }
            ),
            true,
        )
        .with_detail("capture_state", "failed")
        .with_hint("inspect target CUDA/CUPTI compatibility and retry a fresh bounded capture"));
    }
    if let Some(capacity) = capture.record_limit_reached {
        let mut failure = CommandFailure::new(
            ErrorCode::EventRateTooHigh,
            format!("capture reached its configured limit of {capacity} records"),
            true,
        )
        .with_detail("record_capacity", capacity)
        .with_hint("narrow the selectors or explicitly increase max-events");
        if let Some(cupti) = capture.cupti.as_ref() {
            failure = failure
                .with_detail("observed_records", cupti.observed_records)
                .with_detail("retained_records", capture.events.len() as u64)
                .with_detail("dropped_records", cupti.dropped_records);
        }
        return Err(failure);
    }
    if require_complete && capture.cupti.as_ref().is_some_and(|cupti| !cupti.complete) {
        return Err(CommandFailure::new(
            ErrorCode::CuptiNotAvailable,
            format!(
                "{}CUPTI capture was not stopped before measurement",
                if live { "live " } else { "" }
            ),
            true,
        )
        .with_detail("capture_state", "active")
        .with_hint("stop the CUPTI capture before using it as completed input"));
    }
    Ok(())
}

pub(crate) fn apply_collection_summary(
    result: &mut MeasurementResult,
    capture: &completed::CompletedCapture,
) {
    let Some(cupti) = capture.cupti.as_ref() else {
        return;
    };
    let retained_records = result.collection.cuda_events;
    let buffer_utilization = utilization(retained_records, cupti.record_capacity);
    result.collection.cupti = Some(CuptiCollectionSummary {
        record_capacity: cupti.record_capacity,
        observed_records: cupti.observed_records,
        retained_records,
        dropped_records: cupti.dropped_records,
        buffer_utilization,
    });
}

#[allow(clippy::cast_precision_loss)]
pub(crate) fn utilization(retained: u64, capacity: u64) -> f64 {
    if capacity == 0 {
        0.0
    } else {
        retained as f64 / capacity as f64
    }
}

pub(crate) const fn match_policy_name(policy: MatchPolicy) -> &'static str {
    match policy {
        MatchPolicy::Exact => "exact",
        MatchPolicy::FirstAfter => "first-after",
        MatchPolicy::Nearest => "nearest",
        MatchPolicy::StackNested => "stack-nested",
        MatchPolicy::StreamOrder => "stream-order",
    }
}
