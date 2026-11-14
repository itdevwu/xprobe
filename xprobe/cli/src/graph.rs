//! `validate --spec` and `measure --spec` for multi-edge measurement graphs.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use xprobe_collector::completed::CompletedCapture;
use xprobe_core::{graph, inspect};
use xprobe_correlator::{MeasureOptions, finalize, measure};
use xprobe_protocol::{
    CollectionSummary, ErrorCode, Event, EvidenceArtifact, GraphEdgeResult, GraphIssueScope,
    HostCaptureResult, MeasurementGraphResult, MeasurementGraphSpec,
    MeasurementGraphValidationResult, MeasurementMode, MeasurementResult, SchemaVersion3,
    SessionStatus, Warning,
};

use crate::{
    EvidenceOutput, ExportFormatArg, export_measurement_capture,
    failure::{CommandFailure, emit_command_failure, measurement_failure},
    finish_measurement_failure,
    live::{
        LiveCollection, LiveEvaluator, LiveMeasureRequest, LiveOutcome, LivePlan,
        apply_collection_summary, checked_live_capture, collect_live, validate_live_limits,
    },
    protocol_export_format,
};

/// Parse a graph spec, failing with the spec path on malformed input.
pub(crate) fn parse_spec(
    value: serde_json::Value,
    path: &Path,
) -> Result<MeasurementGraphSpec, CommandFailure> {
    serde_json::from_value(value).map_err(|error| {
        CommandFailure::new(
            ErrorCode::InvalidEventSelector,
            format!("invalid MeasurementGraphSpec {}: {error}", path.display()),
            true,
        )
    })
}

fn validate_graph(
    spec: &MeasurementGraphSpec,
) -> Result<MeasurementGraphValidationResult, CommandFailure> {
    let report = inspect::run(spec.target.pid).map_err(|error| {
        CommandFailure::new(error.code(), error.to_string(), error.recoverable())
    })?;
    graph::run(&report, spec).map_err(|error| {
        let edge = error.edge().map(str::to_owned);
        let failure = CommandFailure::new(error.code(), error.to_string(), error.recoverable());
        match edge {
            Some(edge) => failure.with_detail("edge", edge),
            None => failure,
        }
    })
}

pub(crate) fn run_validate_graph(spec: &MeasurementGraphSpec, json: bool) -> ExitCode {
    match validate_graph(spec) {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).expect("graph validation must serialize")
                );
            } else {
                print_graph_validation(&result);
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_command_failure(error, json),
    }
}

fn print_graph_validation(result: &MeasurementGraphValidationResult) {
    println!(
        "Graph validation for PID {}: {}",
        result.target.pid,
        if result.valid { "valid" } else { "invalid" }
    );
    for edge in &result.edges {
        println!(
            "  edge {}: {} -> {} ({:?}, recommended {:?})",
            edge.name, edge.from, edge.to, edge.match_policy, edge.policy_recommendation.policy
        );
    }
    for issue in &result.issues {
        println!(
            "  issue [{:?} {}] {}: {}",
            issue.scope,
            issue.name.as_deref().unwrap_or("-"),
            issue.code,
            issue.message
        );
    }
}

/// One edge of a running graph with its correlator options.
struct EdgePlan {
    name: String,
    options: MeasureOptions,
}

struct GraphEdges {
    session_id: String,
    edges: Vec<EdgePlan>,
}

pub(crate) struct GraphExecution {
    session_id: String,
    results: Vec<MeasurementResult>,
    status: SessionStatus,
    warnings: Vec<Warning>,
    events: Vec<Event>,
    /// The shared capture's summary; every edge reports the same one.
    collection: CollectionSummary,
}

impl LiveOutcome for GraphExecution {
    fn set_status(&mut self, status: SessionStatus) {
        self.status = status;
        for result in &mut self.results {
            result.status = status;
        }
    }

    fn push_warning(&mut self, warning: Warning) {
        self.warnings.push(warning);
    }

    fn into_events(self) -> Vec<Event> {
        self.events
    }
}

impl LiveEvaluator for GraphEdges {
    type Outcome = GraphExecution;

    fn evaluate(
        &self,
        host_captures: &[HostCaptureResult],
        collection: &LiveCollection,
        require_complete: bool,
    ) -> Result<GraphExecution, CommandFailure> {
        let capture = checked_live_capture(
            host_captures,
            collection,
            &self.session_id,
            require_complete,
        )?;
        let results = self
            .edges
            .iter()
            .map(|edge| measure_edge(edge, &capture, require_complete))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(GraphExecution {
            session_id: self.session_id.clone(),
            collection: results[0].collection.clone(),
            results,
            status: SessionStatus::Completed,
            warnings: Vec::new(),
            events: capture.events,
        })
    }

    fn reached_samples(&self, outcome: &GraphExecution) -> bool {
        self.edges
            .iter()
            .zip(&outcome.results)
            .all(|(edge, result)| {
                edge.options.samples.is_some_and(|samples| {
                    result.measurement.samples.matched
                        >= u64::try_from(samples).expect("sample limit fits u64")
                })
            })
    }
}

fn measure_edge(
    edge: &EdgePlan,
    capture: &CompletedCapture,
    require_complete: bool,
) -> Result<MeasurementResult, CommandFailure> {
    let options = MeasureOptions {
        dropped_events: capture.dropped_records,
        ..edge.options.clone()
    };
    let mut result = measure(&capture.events, &options).map_err(|error| {
        let mut failure = measurement_failure(&error, &options, &capture.events, require_complete)
            .with_detail("edge", edge.name.clone());
        failure.message = format!("edge {:?}: {}", edge.name, failure.message);
        failure
    })?;
    apply_collection_summary(&mut result, capture);
    Ok(result)
}

pub(crate) fn run_measure_graph(
    spec: MeasurementGraphSpec,
    cupti_socket: Option<PathBuf>,
    agent_path: Option<PathBuf>,
    output: EvidenceOutput<'_>,
    json: bool,
) -> ExitCode {
    match collect_graph(spec, cupti_socket, agent_path) {
        Ok((execution, spec)) => finish_graph(execution, &spec, output, json),
        Err(error) => finish_measurement_failure(error, output, true, json),
    }
}

fn collect_graph(
    spec: MeasurementGraphSpec,
    cupti_socket: Option<PathBuf>,
    agent_path: Option<PathBuf>,
) -> Result<(GraphExecution, MeasurementGraphSpec), CommandFailure> {
    let validation = validate_graph(&spec)?;
    if let Some(issue) = validation.issues.first() {
        let scope = match (issue.scope, issue.name.as_deref()) {
            (GraphIssueScope::Graph, _) | (_, None) => "graph".to_owned(),
            (GraphIssueScope::Endpoint, Some(name)) => format!("endpoint {name:?}"),
            (GraphIssueScope::Edge, Some(name)) => format!("edge {name:?}"),
        };
        return Err(
            CommandFailure::new(issue.code, format!("{scope}: {}", issue.message), true)
                .with_detail("issues", validation.issues.len() as u64)
                .with_hint("run validate --spec to see every graph issue"),
        );
    }
    let report = inspect::run(spec.target.pid).map_err(|error| {
        CommandFailure::new(error.code(), error.to_string(), error.recoverable())
    })?;
    let session_id = format!("xp_graph_{}", std::process::id());
    let limit = |value: u64, name: &str| {
        usize::try_from(value).map_err(|error| {
            CommandFailure::new(
                ErrorCode::SessionLimitExceeded,
                format!("graph {name} exceeds this platform: {error}"),
                true,
            )
        })
    };
    let max_events = limit(spec.max_events.unwrap_or(100_000), "max_events")?;
    let duration = spec.duration_ms.map(Duration::from_millis);
    let edges = spec
        .edges
        .iter()
        .map(|edge| {
            Ok(EdgePlan {
                name: edge.name.clone(),
                options: MeasureOptions {
                    session_id: session_id.clone(),
                    name: Some(edge.name.clone()),
                    start_selector: spec.endpoints[&edge.from].clone(),
                    end_selector: spec.endpoints[&edge.to].clone(),
                    match_policy: edge.match_policy,
                    samples: edge
                        .samples
                        .map(|samples| limit(samples, "samples"))
                        .transpose()?,
                    duration,
                    max_events,
                    dropped_events: 0,
                },
            })
        })
        .collect::<Result<Vec<_>, CommandFailure>>()?;
    let first = &edges[0].options;
    let all_sampled = edges.iter().all(|edge| edge.options.samples.is_some());
    let request = LiveMeasureRequest {
        pid: spec.target.pid,
        expected_target: Some(spec.target.clone()),
        cupti_socket,
        agent_path,
        timeout: Duration::from_millis(spec.timeout_ms),
        match_policy_text: graph::policy_text(first.match_policy),
        mode: MeasurementMode::Exact,
        options: MeasureOptions {
            session_id: session_id.clone(),
            name: spec.name.clone(),
            samples: all_sampled
                .then(|| edges.iter().filter_map(|edge| edge.options.samples).max())
                .flatten(),
            ..first.clone()
        },
    };
    validate_live_limits(&request)?;
    let plan = LivePlan {
        report,
        endpoints: validation
            .endpoints
            .into_iter()
            .map(|endpoint| endpoint.endpoint)
            .collect(),
        requirements: validation.requirements,
    };
    let execution = collect_live(plan, &request, &GraphEdges { session_id, edges })?;
    Ok((execution, spec))
}

fn finish_graph(
    execution: GraphExecution,
    spec: &MeasurementGraphSpec,
    output: EvidenceOutput<'_>,
    json: bool,
) -> ExitCode {
    let path = match output.artifact_path(true) {
        Ok(path) => path,
        Err(error) => return emit_command_failure(error, json),
    };
    let mut artifact = None;
    if let Some(path) = path {
        let format = output.format.unwrap_or(ExportFormatArg::Jsonl);
        if let Err(error) = export_measurement_capture(&execution.events, &path, format) {
            return emit_command_failure(error, json);
        }
        artifact = Some(EvidenceArtifact {
            path: path.display().to_string(),
            format: protocol_export_format(format),
            events: execution.events.len() as u64,
        });
    }
    let edges = spec
        .edges
        .iter()
        .zip(execution.results)
        .map(|(edge, mut result)| {
            finalize(&mut result, output.mode);
            GraphEdgeResult {
                name: edge.name.clone(),
                from: edge.from.clone(),
                to: edge.to.clone(),
                start_selector: spec.endpoints[&edge.from].clone(),
                end_selector: spec.endpoints[&edge.to].clone(),
                measurement: result.measurement,
                quality: result.quality,
                correlation: result.correlation,
                clock: result.clock,
                evidence: result.evidence,
                warnings: result.warnings,
            }
        })
        .collect();
    let result = MeasurementGraphResult {
        schema_version: SchemaVersion3::current(),
        ok: true,
        session_id: execution.session_id,
        status: execution.status,
        name: spec.name.clone(),
        target: spec.target.clone(),
        edges,
        collection: execution.collection,
        artifact,
        warnings: execution.warnings,
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("graph result must serialize")
        );
    } else {
        print_graph_result(&result);
    }
    ExitCode::SUCCESS
}

fn print_graph_result(result: &MeasurementGraphResult) {
    println!(
        "Graph {} on PID {}: {:?}",
        result.name.as_deref().unwrap_or("unnamed"),
        result.target.pid,
        result.status
    );
    for edge in &result.edges {
        let latency = &edge.measurement.latency_ns;
        println!(
            "  {:<24} matched {:>6}  p50 {:>10} ns  p99 {:>10} ns  {:?}",
            edge.name,
            edge.measurement.samples.matched,
            latency.p50,
            latency.p99,
            edge.quality.verdict
        );
    }
    if let Some(artifact) = &result.artifact {
        println!(
            "Evidence artifact: {} ({} events)",
            artifact.path, artifact.events
        );
    }
    for warning in &result.warnings {
        println!("Warning: {}: {}", warning.code, warning.message);
    }
}
