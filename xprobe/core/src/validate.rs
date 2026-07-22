use std::{collections::BTreeMap, error::Error, fmt};

use regex::Regex;
use xprobe_protocol::{
    AgentActivation, EndpointSource, ErrorCode, EventType, HostProbeKind, MatchPolicy, MemcpyKind,
    PolicyRecommendation, PolicyRecommendationReason, ProcessReport, ResolvedCudaSelector,
    SchemaVersion, ValidatedEndpoint, ValidationIssue, ValidationRequirements, ValidationResult,
    Warning,
};

use crate::{
    cupti_compat,
    inspect::{self, InspectError},
    resolve::{self, ResolveError},
};

#[derive(Debug)]
pub enum ValidateError {
    Inspect(InspectError),
    Resolve {
        endpoint: &'static str,
        source: ResolveError,
    },
    InvalidSelector(String),
    InvalidCorrelationPolicy(String),
}

impl ValidateError {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Inspect(error) => error.code(),
            Self::Resolve { source, .. } => source.code(),
            Self::InvalidSelector(_) => ErrorCode::InvalidEventSelector,
            Self::InvalidCorrelationPolicy(_) => ErrorCode::InvalidCorrelationPolicy,
        }
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::Inspect(error) => error.recoverable(),
            Self::Resolve { source, .. } => source.recoverable(),
            Self::InvalidSelector(_) | Self::InvalidCorrelationPolicy(_) => true,
        }
    }
}

impl fmt::Display for ValidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => error.fmt(formatter),
            Self::Resolve { endpoint, source } => {
                write!(formatter, "failed to resolve {endpoint} selector: {source}")
            }
            Self::InvalidSelector(reason) => write!(formatter, "invalid event selector: {reason}"),
            Self::InvalidCorrelationPolicy(policy) => {
                write!(formatter, "invalid correlation policy {policy:?}")
            }
        }
    }
}

impl Error for ValidateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inspect(error) => Some(error),
            Self::Resolve { source, .. } => Some(source),
            Self::InvalidSelector(_) | Self::InvalidCorrelationPolicy(_) => None,
        }
    }
}

impl From<InspectError> for ValidateError {
    fn from(error: InspectError) -> Self {
        Self::Inspect(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EndpointKind {
    HostEntry,
    HostReturn,
    CudaApi { domain: String, name: String },
    Kernel,
    Memcpy,
    Memset,
}

impl EndpointKind {
    const fn needs_callback(&self) -> bool {
        matches!(self, Self::CudaApi { .. })
    }

    const fn needs_activity(&self) -> bool {
        matches!(self, Self::Kernel | Self::Memcpy | Self::Memset)
    }

    const fn is_host(&self) -> bool {
        matches!(self, Self::HostEntry | Self::HostReturn)
    }

    const fn uses_host_clock(&self) -> bool {
        matches!(
            self,
            Self::HostEntry | Self::HostReturn | Self::CudaApi { .. }
        )
    }
}

struct Endpoint {
    public: ValidatedEndpoint,
    kind: EndpointKind,
}

/// Validate whether two selectors can be collected and correlated now.
///
/// This function only reads process and binary metadata. It does not attach a
/// probe, initialize CUPTI, or mutate the target.
///
/// # Errors
///
/// Returns [`ValidateError`] for malformed inputs, unresolved host selectors,
/// invalid regular expressions, or target identity failures.
pub fn run(
    report: &ProcessReport,
    start_selector: &str,
    end_selector: &str,
    match_policy: &str,
) -> Result<ValidationResult, ValidateError> {
    inspect::verify_target(&report.target)?;
    let start = resolve_endpoint(report, start_selector, "start")?;
    let end = resolve_endpoint(report, end_selector, "end")?;
    let match_policy = parse_match_policy(match_policy)?;

    let needs_ebpf = start.kind.is_host() || end.kind.is_host();
    let needs_cupti_callback = start.kind.needs_callback() || end.kind.needs_callback();
    let needs_cupti_activity = start.kind.needs_activity() || end.kind.needs_activity();
    let needs_cupti = needs_cupti_callback || needs_cupti_activity;
    let needs_clock_alignment = start.kind.uses_host_clock() != end.kind.uses_host_clock();
    let agent_activation = if !needs_cupti {
        AgentActivation::NotRequired
    } else if report.cuda.xprobe_cupti_loaded {
        AgentActivation::AlreadyLoaded
    } else {
        AgentActivation::InjectionRequired
    };
    let requirements = ValidationRequirements {
        needs_ebpf,
        needs_cupti,
        needs_cupti_callback,
        needs_cupti_activity,
        needs_clock_alignment,
        agent_activation,
        target_mutation: agent_activation == AgentActivation::InjectionRequired,
    };

    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    check_collectability(&start, "start", &mut issues);
    check_collectability(&end, "end", &mut issues);
    check_capabilities(
        report,
        &start,
        &end,
        &requirements,
        &mut issues,
        &mut warnings,
    );
    check_cupti_compatibility(report, &requirements, &mut issues);
    check_policy(&start, &end, match_policy, &mut issues, &mut warnings);
    let policy_recommendation = recommend_policy(&start, &end);
    check_selector_breadth(&start, "start", &mut warnings);
    check_selector_breadth(&end, "end", &mut warnings);

    inspect::verify_target(&report.target)?;
    Ok(ValidationResult {
        schema_version: SchemaVersion::current(),
        ok: true,
        valid: issues.is_empty(),
        target: report.target.clone(),
        start: start.public,
        end: end.public,
        match_policy,
        policy_recommendation,
        requirements,
        issues,
        warnings,
    })
}

fn recommend_policy(start: &Endpoint, end: &Endpoint) -> PolicyRecommendation {
    let mut compatible_policies = Vec::with_capacity(5);
    if supports_stack_nested(start, end) {
        compatible_policies.push(MatchPolicy::StackNested);
    }
    if supports_exact(&start.kind, &end.kind) {
        compatible_policies.push(MatchPolicy::Exact);
    }
    if supports_stream_order(&start.kind, &end.kind) {
        compatible_policies.push(MatchPolicy::StreamOrder);
    }
    compatible_policies.push(MatchPolicy::FirstAfter);
    compatible_policies.push(MatchPolicy::Nearest);

    let (policy, reason) = if compatible_policies.contains(&MatchPolicy::StackNested) {
        (
            MatchPolicy::StackNested,
            PolicyRecommendationReason::HostCallFrame,
        )
    } else if compatible_policies.contains(&MatchPolicy::Exact) {
        (
            MatchPolicy::Exact,
            PolicyRecommendationReason::DeterministicCorrelationKey,
        )
    } else if compatible_policies.contains(&MatchPolicy::StreamOrder) {
        (
            MatchPolicy::StreamOrder,
            PolicyRecommendationReason::CudaStreamOrder,
        )
    } else {
        (
            MatchPolicy::FirstAfter,
            PolicyRecommendationReason::TemporalOrderOnly,
        )
    };

    PolicyRecommendation {
        policy,
        reason,
        compatible_policies,
    }
}

fn check_cupti_compatibility(
    report: &ProcessReport,
    requirements: &ValidationRequirements,
    issues: &mut Vec<ValidationIssue>,
) {
    if !requirements.needs_cupti {
        return;
    }
    if let Err(error) = cupti_compat::target_major(report) {
        issues.push(issue(error.code(), error.to_string()));
    }
}

fn resolve_endpoint(
    report: &ProcessReport,
    selector: &str,
    endpoint: &'static str,
) -> Result<Endpoint, ValidateError> {
    if selector.starts_with("uprobe:") {
        let host = resolve::run(report, selector)
            .map_err(|source| ValidateError::Resolve { endpoint, source })?;
        let (event_type, kind, collectable) = match host.probe_kind {
            HostProbeKind::Uprobe => (EventType::HostFunctionEntry, EndpointKind::HostEntry, true),
            HostProbeKind::Uretprobe => {
                (EventType::HostFunctionExit, EndpointKind::HostReturn, true)
            }
            _ => unreachable!("resolve only returns userspace probe kinds"),
        };
        return Ok(Endpoint {
            public: ValidatedEndpoint {
                selector: selector.to_owned(),
                source: EndpointSource::Host,
                event_type,
                collectable,
                host: Some(host),
                cuda: None,
            },
            kind,
        });
    }

    let (cuda, kind, collectable) = parse_cuda_selector(selector)?;
    Ok(Endpoint {
        public: ValidatedEndpoint {
            selector: selector.to_owned(),
            source: EndpointSource::Cuda,
            event_type: cuda.event_type.clone(),
            collectable,
            host: None,
            cuda: Some(cuda),
        },
        kind,
    })
}

fn parse_cuda_selector(
    selector: &str,
) -> Result<(ResolvedCudaSelector, EndpointKind, bool), ValidateError> {
    let fields: Vec<&str> = selector.splitn(3, ':').collect();
    if fields.first() != Some(&"cuda") || fields.len() < 2 {
        return Err(ValidateError::InvalidSelector(
            "expected uprobe: or cuda: prefix".to_owned(),
        ));
    }

    match fields[1] {
        "kernel_start" | "kernel_end" => parse_kernel_selector(&fields),
        "memcpy_start" | "memcpy_end" => parse_memcpy_selector(&fields),
        "memset_start" | "memset_end" => parse_memset_selector(selector, &fields),
        "runtime_api" | "driver_api" => parse_api_selector(selector),
        event => Err(ValidateError::InvalidSelector(format!(
            "unsupported CUDA event {event:?}"
        ))),
    }
}

fn parse_kernel_selector(
    fields: &[&str],
) -> Result<(ResolvedCudaSelector, EndpointKind, bool), ValidateError> {
    let event_type = match fields[1] {
        "kernel_start" => EventType::GpuKernelStart,
        "kernel_end" => EventType::GpuKernelEnd,
        _ => unreachable!("kernel parser only receives kernel events"),
    };
    let kernel_name_regex = match fields.get(2) {
        None => None,
        Some(filter) => {
            let pattern = filter.strip_prefix("name~").ok_or_else(|| {
                ValidateError::InvalidSelector(
                    "kernel filter must use name~<regular-expression>".to_owned(),
                )
            })?;
            if pattern.is_empty() {
                return Err(ValidateError::InvalidSelector(
                    "kernel name regular expression must not be empty".to_owned(),
                ));
            }
            Regex::new(pattern).map_err(|error| {
                ValidateError::InvalidSelector(format!(
                    "invalid kernel name regular expression: {error}"
                ))
            })?;
            Some(pattern.to_owned())
        }
    };
    Ok((
        ResolvedCudaSelector {
            event_type,
            api_domain: None,
            api_name: None,
            kernel_name_regex,
            memcpy_kind: None,
        },
        EndpointKind::Kernel,
        true,
    ))
}

fn parse_memcpy_selector(
    fields: &[&str],
) -> Result<(ResolvedCudaSelector, EndpointKind, bool), ValidateError> {
    let event_type = match fields[1] {
        "memcpy_start" => EventType::GpuMemcpyStart,
        "memcpy_end" => EventType::GpuMemcpyEnd,
        _ => unreachable!("memcpy parser only receives memcpy events"),
    };
    let memcpy_kind = match fields.get(2) {
        None => None,
        Some(filter) => {
            let kind = filter.strip_prefix("kind=").ok_or_else(|| {
                ValidateError::InvalidSelector(
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
                    return Err(ValidateError::InvalidSelector(format!(
                        "unsupported memcpy kind {kind:?}"
                    )));
                }
            })
        }
    };
    Ok((
        ResolvedCudaSelector {
            event_type,
            api_domain: None,
            api_name: None,
            kernel_name_regex: None,
            memcpy_kind,
        },
        EndpointKind::Memcpy,
        true,
    ))
}

fn parse_memset_selector(
    selector: &str,
    fields: &[&str],
) -> Result<(ResolvedCudaSelector, EndpointKind, bool), ValidateError> {
    if fields.len() != 2 {
        return Err(ValidateError::InvalidSelector(format!(
            "memset selector {selector:?} does not accept a filter"
        )));
    }
    let event_type = match fields[1] {
        "memset_start" => EventType::GpuMemsetStart,
        "memset_end" => EventType::GpuMemsetEnd,
        _ => unreachable!("memset parser only receives memset events"),
    };
    Ok((
        ResolvedCudaSelector {
            event_type,
            api_domain: None,
            api_name: None,
            kernel_name_regex: None,
            memcpy_kind: None,
        },
        EndpointKind::Memset,
        true,
    ))
}

fn parse_api_selector(
    selector: &str,
) -> Result<(ResolvedCudaSelector, EndpointKind, bool), ValidateError> {
    let fields: Vec<&str> = selector.split(':').collect();
    if fields.len() != 4 || fields[2].is_empty() {
        return Err(ValidateError::InvalidSelector(
            "CUDA API selector must be cuda:<runtime_api|driver_api>:<name>:<entry|exit>"
                .to_owned(),
        ));
    }
    let event_type = match fields[3] {
        "entry" => EventType::CudaApiEntry,
        "exit" => EventType::CudaApiExit,
        _ => {
            return Err(ValidateError::InvalidSelector(
                "CUDA API boundary must be entry or exit".to_owned(),
            ));
        }
    };
    let domain = fields[1].to_owned();
    let name = fields[2].to_owned();
    let collectable = matches!(domain.as_str(), "runtime_api" | "driver_api");
    Ok((
        ResolvedCudaSelector {
            event_type,
            api_domain: Some(domain.clone()),
            api_name: Some(name.clone()),
            kernel_name_regex: None,
            memcpy_kind: None,
        },
        EndpointKind::CudaApi { domain, name },
        collectable,
    ))
}

fn parse_match_policy(policy: &str) -> Result<MatchPolicy, ValidateError> {
    match policy {
        "exact" => Ok(MatchPolicy::Exact),
        "first-after" | "first_after" => Ok(MatchPolicy::FirstAfter),
        "nearest" => Ok(MatchPolicy::Nearest),
        "stack-nested" | "stack_nested" => Ok(MatchPolicy::StackNested),
        "stream-order" | "stream_order" => Ok(MatchPolicy::StreamOrder),
        _ => Err(ValidateError::InvalidCorrelationPolicy(policy.to_owned())),
    }
}

fn check_collectability(endpoint: &Endpoint, name: &str, issues: &mut Vec<ValidationIssue>) {
    if !endpoint.public.collectable {
        issues.push(issue(
            ErrorCode::InvalidEventSelector,
            format!(
                "{name} selector {} is recognized but not collected by this build",
                endpoint.public.selector
            ),
        ));
    }
}

fn check_capabilities(
    report: &ProcessReport,
    start: &Endpoint,
    end: &Endpoint,
    requirements: &ValidationRequirements,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<Warning>,
) {
    if requirements.needs_ebpf {
        let needs_uprobe = matches!(start.kind, EndpointKind::HostEntry)
            || matches!(end.kind, EndpointKind::HostEntry);
        let needs_uretprobe = matches!(start.kind, EndpointKind::HostReturn)
            || matches!(end.kind, EndpointKind::HostReturn);
        if (needs_uprobe && !report.capabilities.uprobe)
            || (needs_uretprobe && !report.capabilities.uretprobe)
        {
            issues.push(issue(
                ErrorCode::PermissionDenied,
                "required eBPF userspace probe capability is unavailable".to_owned(),
            ));
        }
    }
    if requirements.agent_activation == AgentActivation::InjectionRequired {
        warnings.push(warning(
            "TARGET_PROCESS_WILL_BE_MODIFIED",
            "measure must inject the xprobe CUPTI agent into the target process",
        ));
    } else {
        if requirements.needs_cupti_callback && !report.capabilities.cuda_callback {
            issues.push(issue(
                ErrorCode::CuptiNotAvailable,
                "CUPTI callback collection is unavailable for the target".to_owned(),
            ));
        }
        if requirements.needs_cupti_activity && !report.capabilities.cuda_activity {
            issues.push(issue(
                ErrorCode::CuptiNotAvailable,
                "CUPTI activity collection is unavailable for the target".to_owned(),
            ));
        }
    }
}

fn check_policy(
    start: &Endpoint,
    end: &Endpoint,
    policy: MatchPolicy,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<Warning>,
) {
    match policy {
        MatchPolicy::Exact if !supports_exact(&start.kind, &end.kind) => issues.push(issue(
            ErrorCode::InvalidCorrelationPolicy,
            "exact matching requires endpoints that share a deterministic correlation key"
                .to_owned(),
        )),
        MatchPolicy::FirstAfter => warnings.push(warning(
            "HEURISTIC_CORRELATION",
            "first-after matching does not prove request-level causality",
        )),
        MatchPolicy::Nearest => warnings.push(warning(
            "HEURISTIC_CORRELATION",
            "nearest-event matching does not prove request-level causality",
        )),
        MatchPolicy::StackNested if !supports_stack_nested(start, end) => issues.push(issue(
            ErrorCode::InvalidCorrelationPolicy,
            "stack-nested matching requires entry and return probes for the same host function"
                .to_owned(),
        )),
        MatchPolicy::StreamOrder if !supports_stream_order(&start.kind, &end.kind) => {
            issues.push(issue(
                ErrorCode::InvalidCorrelationPolicy,
                "stream-order matching requires two GPU activity endpoints".to_owned(),
            ));
        }
        MatchPolicy::Exact | MatchPolicy::StackNested | MatchPolicy::StreamOrder => {}
    }
}

fn supports_exact(start: &EndpointKind, end: &EndpointKind) -> bool {
    match (start, end) {
        (
            EndpointKind::CudaApi {
                domain: start_domain,
                name: start_name,
            },
            EndpointKind::CudaApi {
                domain: end_domain,
                name: end_name,
            },
        ) => start_domain == end_domain && start_name == end_name,
        (EndpointKind::Kernel, EndpointKind::Kernel)
        | (EndpointKind::Memcpy, EndpointKind::Memcpy)
        | (EndpointKind::Memset, EndpointKind::Memset) => true,
        (EndpointKind::CudaApi { domain, name }, EndpointKind::Kernel)
        | (EndpointKind::Kernel, EndpointKind::CudaApi { domain, name }) => {
            (domain == "runtime_api" && name == "cudaLaunchKernel")
                || (domain == "driver_api" && name == "cuLaunchKernel")
        }
        _ => false,
    }
}

fn supports_stack_nested(start: &Endpoint, end: &Endpoint) -> bool {
    if !matches!(start.kind, EndpointKind::HostEntry)
        || !matches!(end.kind, EndpointKind::HostReturn)
    {
        return false;
    }
    let start = start
        .public
        .host
        .as_ref()
        .expect("host endpoint must resolve");
    let end = end
        .public
        .host
        .as_ref()
        .expect("host endpoint must resolve");
    start.binary_path == end.binary_path && start.file_offset == end.file_offset
}

fn supports_stream_order(start: &EndpointKind, end: &EndpointKind) -> bool {
    start.needs_activity() && end.needs_activity()
}

fn check_selector_breadth(endpoint: &Endpoint, name: &str, warnings: &mut Vec<Warning>) {
    let broad_kernel = matches!(endpoint.kind, EndpointKind::Kernel)
        && endpoint.public.cuda.as_ref().is_some_and(|cuda| {
            cuda.kernel_name_regex
                .as_deref()
                .is_none_or(|pattern| matches!(pattern, ".*" | "^.*$"))
        });
    if broad_kernel {
        warnings.push(warning(
            "BROAD_EVENT_SELECTOR",
            &format!("{name} selector matches every CUDA kernel activity"),
        ));
    }
}

fn issue(code: ErrorCode, message: String) -> ValidationIssue {
    ValidationIssue { code, message }
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
    use xprobe_protocol::{
        AgentActivation, ElfObjectKind, EndpointSource, EventType, HostProbeKind, MatchPolicy,
        MemcpyKind, PolicyRecommendationReason, ProcessMapping, ResolvedProbe, SchemaVersion,
        TargetIdentity, ValidatedEndpoint,
    };

    use super::{
        Endpoint, EndpointKind, parse_cuda_selector, parse_match_policy, recommend_policy, run,
    };
    use crate::inspect;

    #[test]
    fn parses_supported_cuda_selectors_and_policies() {
        let (api, _, collectable) =
            parse_cuda_selector("cuda:runtime_api:cudaLaunchKernel:exit").unwrap();
        assert_eq!(api.api_name.as_deref(), Some("cudaLaunchKernel"));
        assert!(collectable);

        let (kernel, _, collectable) =
            parse_cuda_selector("cuda:kernel_start:name~flash_(fwd|bwd):sm90").unwrap();
        assert_eq!(
            kernel.kernel_name_regex.as_deref(),
            Some("flash_(fwd|bwd):sm90")
        );
        assert!(collectable);

        let (memcpy, _, collectable) = parse_cuda_selector("cuda:memcpy_end:kind=HtoD").unwrap();
        assert_eq!(memcpy.memcpy_kind, Some(MemcpyKind::HostToDevice));
        assert!(collectable);

        let (memset, _, collectable) = parse_cuda_selector("cuda:memset_start").unwrap();
        assert_eq!(memset.event_type, EventType::GpuMemsetStart);
        assert!(collectable);
        assert_eq!(
            parse_match_policy("first-after").unwrap(),
            MatchPolicy::FirstAfter
        );
    }

    #[test]
    fn rejects_invalid_filters_and_policies() {
        assert!(parse_cuda_selector("cuda:kernel_start:name~[").is_err());
        assert!(parse_cuda_selector("cuda:memcpy_start:kind=sideways").is_err());
        assert!(parse_match_policy("probably-near").is_err());
    }

    #[test]
    fn reports_missing_cupti_without_failing_validation() {
        let report = inspect::run(std::process::id()).unwrap();
        let result = run(
            &report,
            "cuda:runtime_api:cudaLaunchKernel:exit",
            "cuda:kernel_start:name~test.*",
            "exact",
        )
        .unwrap();
        assert!(result.valid);
        assert_eq!(result.policy_recommendation.policy, MatchPolicy::Exact);
        assert_eq!(
            result.policy_recommendation.reason,
            PolicyRecommendationReason::DeterministicCorrelationKey
        );
        assert_eq!(
            result.requirements.agent_activation,
            AgentActivation::InjectionRequired
        );
        assert!(result.requirements.target_mutation);
        assert!(result.issues.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.code == "TARGET_PROCESS_WILL_BE_MODIFIED")
        );
    }

    #[test]
    fn accepts_exact_kernel_duration_when_agent_is_available() {
        let mut report = inspect::run(std::process::id()).unwrap();
        report.cuda.xprobe_cupti_loaded = true;
        report.capabilities.cuda_callback = true;
        report.capabilities.cuda_activity = true;
        let result = run(
            &report,
            "cuda:kernel_start:name~test.*",
            "cuda:kernel_end:name~test.*",
            "exact",
        )
        .unwrap();
        assert!(result.valid);
        assert_eq!(
            result.requirements.agent_activation,
            AgentActivation::AlreadyLoaded
        );
        assert!(!result.requirements.target_mutation);
        assert!(!result.requirements.needs_clock_alignment);
        assert!(result.issues.is_empty());
    }

    #[test]
    fn recommends_stack_matching_for_host_function_spans() {
        let endpoint = |selector: &str, event_type, kind, probe_kind| Endpoint {
            public: ValidatedEndpoint {
                selector: selector.to_owned(),
                source: EndpointSource::Host,
                event_type,
                collectable: true,
                host: Some(ResolvedProbe {
                    schema_version: SchemaVersion::current(),
                    ok: true,
                    target: TargetIdentity {
                        pid: 1,
                        process_start_time: 1,
                    },
                    selector: selector.to_owned(),
                    binary_path: "/srv/app".to_owned(),
                    build_id: None,
                    object_kind: ElfObjectKind::Executable,
                    probe_kind,
                    symbol: Some("work".to_owned()),
                    symbol_virtual_address: Some(0x1000),
                    symbol_size: Some(16),
                    file_offset: 0x1000,
                    runtime_address: 0x401000,
                    mapping: ProcessMapping {
                        start_address: 0x400000,
                        end_address: 0x500000,
                        file_offset: 0,
                    },
                }),
                cuda: None,
            },
            kind,
        };
        let start = endpoint(
            "uprobe:/srv/app:work:entry",
            EventType::HostFunctionEntry,
            EndpointKind::HostEntry,
            HostProbeKind::Uprobe,
        );
        let end = endpoint(
            "uprobe:/srv/app:work:return",
            EventType::HostFunctionExit,
            EndpointKind::HostReturn,
            HostProbeKind::Uretprobe,
        );
        let recommendation = recommend_policy(&start, &end);
        assert_eq!(recommendation.policy, MatchPolicy::StackNested);
        assert_eq!(
            recommendation.reason,
            PolicyRecommendationReason::HostCallFrame
        );
        assert!(
            recommendation
                .compatible_policies
                .contains(&MatchPolicy::Nearest)
        );
    }

    #[test]
    fn accepts_api_to_kernel_when_normalized_agent_is_available() {
        let mut report = inspect::run(std::process::id()).unwrap();
        report.cuda.xprobe_cupti_loaded = true;
        report.capabilities.cuda_callback = true;
        report.capabilities.cuda_activity = true;
        let result = run(
            &report,
            "cuda:runtime_api:cudaLaunchKernel:entry",
            "cuda:kernel_start:name~test.*",
            "exact",
        )
        .unwrap();
        assert!(result.valid);
        assert!(result.requirements.needs_clock_alignment);
        assert!(result.issues.is_empty());
    }
}
