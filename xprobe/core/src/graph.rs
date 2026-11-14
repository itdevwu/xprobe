//! Read-only validation of multi-edge measurement graphs.

use std::{collections::BTreeSet, error::Error, fmt};

use xprobe_protocol::{
    AgentActivation, ErrorCode, GRAPH_MAX_EDGES, GRAPH_MAX_ENDPOINTS, GRAPH_MAX_LINUX_ENDPOINTS,
    GraphEdgeValidation, GraphEndpointValidation, GraphIssueScope, GraphValidationIssue,
    MatchPolicy, MeasurementGraphSpec, MeasurementGraphValidationResult, ProcessReport,
    SchemaVersion3, ValidatedEndpoint, ValidationRequirements,
};

use crate::{
    inspect::{self, InspectError},
    validate::{self, ValidateError},
};

#[derive(Debug)]
pub enum GraphValidateError {
    Inspect(InspectError),
    Edge { edge: String, source: ValidateError },
}

impl GraphValidateError {
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Inspect(error) => error.code(),
            Self::Edge { source, .. } => source.code(),
        }
    }

    #[must_use]
    pub fn recoverable(&self) -> bool {
        match self {
            Self::Inspect(error) => error.recoverable(),
            Self::Edge { source, .. } => source.recoverable(),
        }
    }

    #[must_use]
    pub fn edge(&self) -> Option<&str> {
        match self {
            Self::Inspect(_) => None,
            Self::Edge { edge, .. } => Some(edge),
        }
    }
}

impl fmt::Display for GraphValidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => error.fmt(formatter),
            Self::Edge { edge, source } => write!(formatter, "edge {edge:?}: {source}"),
        }
    }
}

impl Error for GraphValidateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inspect(error) => Some(error),
            Self::Edge { source, .. } => Some(source),
        }
    }
}

impl From<InspectError> for GraphValidateError {
    fn from(error: InspectError) -> Self {
        Self::Inspect(error)
    }
}

/// Text accepted by single-edge validation for a policy.
#[must_use]
pub const fn policy_text(policy: MatchPolicy) -> &'static str {
    match policy {
        MatchPolicy::Exact => "exact",
        MatchPolicy::FirstAfter => "first-after",
        MatchPolicy::Nearest => "nearest",
        MatchPolicy::StackNested => "stack-nested",
        MatchPolicy::StreamOrder => "stream-order",
    }
}

/// Validate a graph without attaching.
///
/// Structural problems, unknown endpoint names, collector slot limits, and
/// every single-edge issue are returned as scoped issues.
///
/// # Errors
///
/// Returns [`GraphValidateError`] when target identity changes or an edge's
/// selector cannot be resolved at all, naming the edge.
pub fn run(
    report: &ProcessReport,
    spec: &MeasurementGraphSpec,
) -> Result<MeasurementGraphValidationResult, GraphValidateError> {
    inspect::verify_target(&report.target)?;
    let mut issues = structural_issues(report, spec);
    let mut endpoints: Vec<GraphEndpointValidation> = Vec::new();
    let mut edges = Vec::new();
    let mut requirements: Option<ValidationRequirements> = None;
    let mut warnings = Vec::new();
    let resolvable = issues
        .iter()
        .all(|issue| issue.scope != GraphIssueScope::Graph);
    for edge in spec.edges.iter().filter(|_| resolvable) {
        let (Some(from), Some(to)) = (spec.endpoints.get(&edge.from), spec.endpoints.get(&edge.to))
        else {
            continue;
        };
        let result =
            validate::run(report, from, to, policy_text(edge.match_policy)).map_err(|source| {
                GraphValidateError::Edge {
                    edge: edge.name.clone(),
                    source,
                }
            })?;
        for (name, endpoint) in [(&edge.from, &result.start), (&edge.to, &result.end)] {
            if !endpoints.iter().any(|existing| &existing.name == name) {
                endpoints.push(GraphEndpointValidation {
                    name: name.clone(),
                    endpoint: endpoint.clone(),
                });
            }
        }
        issues.extend(result.issues.into_iter().map(|issue| GraphValidationIssue {
            scope: GraphIssueScope::Edge,
            name: Some(edge.name.clone()),
            code: issue.code,
            message: issue.message,
        }));
        warnings.extend(result.warnings);
        requirements = Some(match requirements {
            None => result.requirements,
            Some(merged) => merge_requirements(&merged, &result.requirements),
        });
        edges.push(GraphEdgeValidation {
            name: edge.name.clone(),
            from: edge.from.clone(),
            to: edge.to.clone(),
            match_policy: edge.match_policy,
            policy_recommendation: result.policy_recommendation,
        });
    }
    endpoints.sort_by(|left, right| left.name.cmp(&right.name));
    let public = endpoints
        .iter()
        .map(|endpoint| &endpoint.endpoint)
        .collect::<Vec<_>>();
    issues.extend(slot_issues(&public));
    warnings.dedup_by(|left, right| left.code == right.code && left.message == right.message);
    inspect::verify_target(&report.target)?;
    Ok(MeasurementGraphValidationResult {
        schema_version: SchemaVersion3::current(),
        ok: true,
        valid: issues.is_empty(),
        target: report.target.clone(),
        endpoints,
        edges,
        requirements: requirements.unwrap_or_else(empty_requirements),
        issues,
        warnings,
    })
}

fn graph_issue(message: String) -> GraphValidationIssue {
    GraphValidationIssue {
        scope: GraphIssueScope::Graph,
        name: None,
        code: ErrorCode::InvalidEventSelector,
        message,
    }
}

fn structural_issues(
    report: &ProcessReport,
    spec: &MeasurementGraphSpec,
) -> Vec<GraphValidationIssue> {
    let mut issues = Vec::new();
    if spec.target != report.target {
        issues.push(GraphValidationIssue {
            scope: GraphIssueScope::Graph,
            name: None,
            code: ErrorCode::TargetReused,
            message: "graph target identity does not match the process".to_owned(),
        });
    }
    if spec.edges.is_empty() || spec.edges.len() > GRAPH_MAX_EDGES {
        issues.push(graph_issue(format!(
            "a graph needs between 1 and {GRAPH_MAX_EDGES} edges, found {}",
            spec.edges.len()
        )));
    }
    if spec.endpoints.is_empty() || spec.endpoints.len() > GRAPH_MAX_ENDPOINTS {
        issues.push(graph_issue(format!(
            "a graph needs between 1 and {GRAPH_MAX_ENDPOINTS} endpoints, found {}",
            spec.endpoints.len()
        )));
    }
    if spec.timeout_ms == 0
        || spec.duration_ms == Some(0)
        || spec.max_events == Some(0)
        || spec.edges.iter().any(|edge| edge.samples == Some(0))
    {
        issues.push(GraphValidationIssue {
            scope: GraphIssueScope::Graph,
            name: None,
            code: ErrorCode::SessionLimitExceeded,
            message: "timeout, duration, max_events, and samples must be positive".to_owned(),
        });
    }
    if spec.duration_ms.is_none() && spec.edges.iter().any(|edge| edge.samples.is_none()) {
        issues.push(GraphValidationIssue {
            scope: GraphIssueScope::Graph,
            name: None,
            code: ErrorCode::SessionLimitExceeded,
            message: "set duration_ms or samples on every edge so the capture is bounded"
                .to_owned(),
        });
    }
    let mut names = BTreeSet::new();
    let mut used = BTreeSet::new();
    for edge in &spec.edges {
        if edge.name.is_empty() || !names.insert(edge.name.as_str()) {
            issues.push(GraphValidationIssue {
                scope: GraphIssueScope::Edge,
                name: Some(edge.name.clone()),
                code: ErrorCode::InvalidEventSelector,
                message: "edge names must be non-empty and unique".to_owned(),
            });
        }
        for endpoint in [&edge.from, &edge.to] {
            used.insert(endpoint.as_str());
            if !spec.endpoints.contains_key(endpoint) {
                issues.push(GraphValidationIssue {
                    scope: GraphIssueScope::Edge,
                    name: Some(edge.name.clone()),
                    code: ErrorCode::InvalidEventSelector,
                    message: format!("edge references unknown endpoint {endpoint:?}"),
                });
            }
        }
    }
    for name in spec
        .endpoints
        .keys()
        .filter(|name| !used.contains(name.as_str()))
    {
        issues.push(GraphValidationIssue {
            scope: GraphIssueScope::Endpoint,
            name: Some(name.clone()),
            code: ErrorCode::InvalidEventSelector,
            message: "endpoint is not used by any edge".to_owned(),
        });
    }
    issues
}

/// Syscall, tracepoint, and USDT endpoints share the Linux collector's slots.
fn slot_issues(endpoints: &[&ValidatedEndpoint]) -> Vec<GraphValidationIssue> {
    let linux = endpoints
        .iter()
        .filter(|endpoint| endpoint.linux.is_some())
        .map(|endpoint| endpoint.selector.as_str())
        .collect::<BTreeSet<_>>();
    if linux.len() <= GRAPH_MAX_LINUX_ENDPOINTS {
        return Vec::new();
    }
    vec![GraphValidationIssue {
        scope: GraphIssueScope::Graph,
        name: None,
        code: ErrorCode::SessionLimitExceeded,
        message: format!(
            "a graph supports at most {GRAPH_MAX_LINUX_ENDPOINTS} syscall, tracepoint, or USDT endpoints, found {}",
            linux.len()
        ),
    }]
}

const fn activation_rank(activation: AgentActivation) -> u8 {
    match activation {
        AgentActivation::NotRequired => 0,
        AgentActivation::AlreadyLoaded => 1,
        AgentActivation::InjectionRequired => 2,
        AgentActivation::StartupRequired => 3,
    }
}

fn merge_requirements(
    left: &ValidationRequirements,
    right: &ValidationRequirements,
) -> ValidationRequirements {
    let agent_activation =
        if activation_rank(right.agent_activation) > activation_rank(left.agent_activation) {
            right.agent_activation
        } else {
            left.agent_activation
        };
    ValidationRequirements {
        needs_ebpf: left.needs_ebpf || right.needs_ebpf,
        needs_cupti: left.needs_cupti || right.needs_cupti,
        needs_cupti_callback: left.needs_cupti_callback || right.needs_cupti_callback,
        needs_cupti_activity: left.needs_cupti_activity || right.needs_cupti_activity,
        needs_nvtx: left.needs_nvtx || right.needs_nvtx,
        needs_clock_alignment: left.needs_clock_alignment || right.needs_clock_alignment,
        agent_activation,
        target_mutation: agent_activation == AgentActivation::InjectionRequired,
    }
}

const fn empty_requirements() -> ValidationRequirements {
    ValidationRequirements {
        needs_ebpf: false,
        needs_cupti: false,
        needs_cupti_callback: false,
        needs_cupti_activity: false,
        needs_nvtx: false,
        needs_clock_alignment: false,
        agent_activation: AgentActivation::NotRequired,
        target_mutation: false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use xprobe_protocol::{
        AgentActivation, GraphEdgeSpec, GraphIssueScope, MatchPolicy, MeasurementGraphSpec,
        SchemaVersion3,
    };

    use super::{merge_requirements, structural_issues};
    use crate::inspect;

    fn spec(edges: &[(&str, &str, &str, Option<u64>)]) -> MeasurementGraphSpec {
        let report = inspect::run(std::process::id()).unwrap();
        MeasurementGraphSpec {
            schema_version: SchemaVersion3::current(),
            name: None,
            target: report.target,
            endpoints: BTreeMap::from([
                ("a".to_owned(), "cuda:kernel_start".to_owned()),
                ("b".to_owned(), "cuda:kernel_end".to_owned()),
            ]),
            edges: edges
                .iter()
                .map(|(name, from, to, samples)| GraphEdgeSpec {
                    name: (*name).to_owned(),
                    from: (*from).to_owned(),
                    to: (*to).to_owned(),
                    match_policy: MatchPolicy::Exact,
                    samples: *samples,
                })
                .collect(),
            duration_ms: None,
            timeout_ms: 1000,
            max_events: None,
        }
    }

    #[test]
    fn accepts_a_bounded_well_formed_graph() {
        let report = inspect::run(std::process::id()).unwrap();
        assert_eq!(
            structural_issues(&report, &spec(&[("k", "a", "b", Some(10))])),
            []
        );
    }

    #[test]
    fn reports_structural_problems_with_scope() {
        let report = inspect::run(std::process::id()).unwrap();
        let graph = spec(&[("k", "a", "c", None), ("k", "a", "b", Some(1))]);
        let issues = structural_issues(&report, &graph)
            .into_iter()
            .map(|issue| (issue.scope, issue.name, issue.message))
            .collect::<Vec<_>>();
        assert!(
            issues
                .iter()
                .any(|(scope, _, message)| *scope == GraphIssueScope::Graph
                    && message.contains("bounded"))
        );
        assert!(
            issues
                .iter()
                .any(|(scope, name, message)| *scope == GraphIssueScope::Edge
                    && name.as_deref() == Some("k")
                    && message.contains("unique"))
        );
        assert!(
            issues
                .iter()
                .any(|(_, _, message)| message.contains("unknown endpoint \"c\""))
        );
    }

    #[test]
    fn merged_requirements_take_the_strongest_activation() {
        let base = xprobe_protocol::ValidationRequirements {
            needs_ebpf: true,
            needs_cupti: false,
            needs_cupti_callback: false,
            needs_cupti_activity: false,
            needs_nvtx: false,
            needs_clock_alignment: false,
            agent_activation: AgentActivation::NotRequired,
            target_mutation: false,
        };
        let cuda = xprobe_protocol::ValidationRequirements {
            needs_ebpf: false,
            needs_cupti: true,
            needs_cupti_activity: true,
            agent_activation: AgentActivation::InjectionRequired,
            target_mutation: true,
            ..base.clone()
        };
        let merged = merge_requirements(&base, &cuda);
        assert!(merged.needs_ebpf && merged.needs_cupti && merged.needs_cupti_activity);
        assert_eq!(merged.agent_activation, AgentActivation::InjectionRequired);
        assert!(merged.target_mutation);
    }
}
