use crate::clock_domain_name;
use crate::live::match_policy_name;
use std::collections::BTreeMap;
use std::process::ExitCode;
use xprobe_correlator::MeasureError;
use xprobe_correlator::MeasureOptions;
use xprobe_protocol::ErrorCode;
use xprobe_protocol::ErrorResponse;
use xprobe_protocol::Event;
use xprobe_protocol::EventSource;
use xprobe_protocol::XprobeError;

#[derive(Debug)]
pub(crate) struct CommandFailure {
    pub(crate) code: ErrorCode,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
    pub(crate) details: BTreeMap<String, serde_json::Value>,
    pub(crate) hints: Vec<String>,
    pub(crate) artifact_events: Option<Vec<Event>>,
}

impl CommandFailure {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>, recoverable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable,
            details: BTreeMap::new(),
            hints: Vec::new(),
            artifact_events: None,
        }
    }

    pub(crate) fn with_detail(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    pub(crate) fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hints.push(hint.into());
        self
    }

    pub(crate) fn with_artifact_events(mut self, events: Vec<Event>) -> Self {
        self.artifact_events = Some(events);
        self
    }
}

pub(crate) fn measurement_failure(
    error: &MeasureError,
    options: &MeasureOptions,
    events: &[Event],
    preserve_artifact: bool,
) -> CommandFailure {
    let mut failure = CommandFailure::new(error.code(), error.to_string(), error.recoverable())
        .with_detail("start_selector", options.start_selector.clone())
        .with_detail("end_selector", options.end_selector.clone())
        .with_detail("match_policy", match_policy_name(options.match_policy));
    if preserve_artifact {
        failure = failure.with_artifact_events(events.to_vec());
    }
    match error {
        MeasureError::InvalidSelector(_) => {
            failure = failure.with_hint("run xprobe validate with the exact selector text");
        }
        MeasureError::InvalidPolicy(_) => {
            failure = failure
                .with_hint("use policy_recommendation.compatible_policies from xprobe validate");
        }
        MeasureError::InvalidLimit(_) => {
            failure = failure
                .with_hint("set positive samples or duration, timeout, and max-events bounds");
        }
        MeasureError::EventLimitExceeded { actual, maximum } => {
            failure = failure
                .with_detail("observed_events", *actual as u64)
                .with_detail("max_events", *maximum as u64)
                .with_hint("narrow the selectors or explicitly increase max-events");
        }
        MeasureError::EventsDropped { count } => {
            failure = failure
                .with_detail("dropped_events", *count)
                .with_hint("reduce the event rate or explicitly increase the capture capacity");
        }
        MeasureError::ClockDomainsDiffer { start, end } => {
            failure = failure
                .with_detail("start_clock", clock_domain_name(start))
                .with_detail("end_clock", clock_domain_name(end))
                .with_hint(
                    "use endpoints in one clock domain or a CUPTI capture normalized to host monotonic time",
                );
        }
        MeasureError::NoMatchedSamples => {
            let host_events = events
                .iter()
                .filter(|event| event.source == EventSource::Ebpf)
                .count() as u64;
            failure = failure
                .with_detail("captured_events", events.len() as u64)
                .with_detail("host_events", host_events)
                .with_detail("cuda_events", events.len() as u64 - host_events)
                .with_hint(
                    "inspect the events-out artifact, then adjust selectors or choose an explicitly compatible policy",
                );
        }
    }
    failure
}

pub(crate) fn emit_error(
    code: ErrorCode,
    message: String,
    recoverable: bool,
    json: bool,
) -> ExitCode {
    emit_xprobe_error(
        XprobeError {
            code,
            message,
            recoverable,
            details: BTreeMap::new(),
            hints: Vec::new(),
        },
        json,
    )
}

pub(crate) fn emit_command_failure(error: CommandFailure, json: bool) -> ExitCode {
    emit_xprobe_error(
        XprobeError {
            code: error.code,
            message: error.message,
            recoverable: error.recoverable,
            details: error.details,
            hints: error.hints,
        },
        json,
    )
}

pub(crate) fn emit_xprobe_error(error: XprobeError, json: bool) -> ExitCode {
    let code = error.code;
    let response = ErrorResponse::new(error);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).expect("error response must serialize")
        );
    } else {
        eprintln!("{code}: {}", response.error.message);
    }

    match code {
        ErrorCode::TargetNotFound | ErrorCode::TargetExited | ErrorCode::TargetReused => {
            ExitCode::from(3)
        }
        ErrorCode::PermissionDenied => ExitCode::from(4),
        _ => ExitCode::from(1),
    }
}
