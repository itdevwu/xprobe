//! Lowering of validated CUDA selectors into fixed CUPTI Agent filters.

use std::{error::Error, fmt};

use xprobe_protocol::{EventType, MemcpyKind, ResolvedCudaSelector};

use super::{
    CUPTI_NAME_CAPACITY, CuptiApiDomain, CuptiEventFilter, CuptiMemcpyKind, CuptiNameFilter,
    CuptiRecordKind,
};

type NameLowering = fn(String) -> CuptiNameFilter;

/// A validated CUDA selector that cannot be represented as an Agent filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CuptiFilterError {
    NonCudaEventType(EventType),
    UnsupportedApiDomain(String),
}

impl fmt::Display for CuptiFilterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCudaEventType(event_type) => write!(
                formatter,
                "validated CUDA endpoint has a non-CUDA event type {event_type:?}"
            ),
            Self::UnsupportedApiDomain(domain) => write!(
                formatter,
                "validated CUDA endpoint has unsupported API domain {domain:?}"
            ),
        }
    }
}

impl Error for CuptiFilterError {}

/// Lower one validated CUDA endpoint into the Agent's fixed filter layout.
///
/// Name regexes that cannot be expressed as a bounded literal match lower to
/// [`CuptiNameFilter::Any`]; the correlator still applies the full regex.
///
/// # Errors
///
/// Returns [`CuptiFilterError`] when the selector is not a CUDA event type or
/// names an API domain the Agent does not support.
pub fn event_filter(selector: &ResolvedCudaSelector) -> Result<CuptiEventFilter, CuptiFilterError> {
    let record_kind = match selector.event_type {
        EventType::CudaApiEntry => CuptiRecordKind::CudaApiEntry,
        EventType::CudaApiExit => CuptiRecordKind::CudaApiExit,
        EventType::GpuKernelStart => CuptiRecordKind::GpuKernelStart,
        EventType::GpuKernelEnd => CuptiRecordKind::GpuKernelEnd,
        EventType::GpuMemcpyStart => CuptiRecordKind::GpuMemcpyStart,
        EventType::GpuMemcpyEnd => CuptiRecordKind::GpuMemcpyEnd,
        EventType::GpuMemsetStart => CuptiRecordKind::GpuMemsetStart,
        EventType::GpuMemsetEnd => CuptiRecordKind::GpuMemsetEnd,
        EventType::NvtxRangeStart => CuptiRecordKind::NvtxRangeStart,
        EventType::NvtxRangeEnd => CuptiRecordKind::NvtxRangeEnd,
        ref other => return Err(CuptiFilterError::NonCudaEventType(other.clone())),
    };
    let api_domain = match selector.api_domain.as_deref() {
        None => CuptiApiDomain::Any,
        Some("driver_api") => CuptiApiDomain::Driver,
        Some("runtime_api") => CuptiApiDomain::Runtime,
        Some(domain) => return Err(CuptiFilterError::UnsupportedApiDomain(domain.to_owned())),
    };
    let memcpy_kind = match selector.memcpy_kind {
        None | Some(MemcpyKind::Unknown) => CuptiMemcpyKind::Any,
        Some(MemcpyKind::HostToDevice) => CuptiMemcpyKind::HostToDevice,
        Some(MemcpyKind::DeviceToHost) => CuptiMemcpyKind::DeviceToHost,
        Some(MemcpyKind::DeviceToDevice) => CuptiMemcpyKind::DeviceToDevice,
        Some(MemcpyKind::HostToHost) => CuptiMemcpyKind::HostToHost,
        Some(MemcpyKind::PeerToPeer) => CuptiMemcpyKind::PeerToPeer,
    };
    let name = if let Some(name) = selector.api_name.as_ref() {
        CuptiNameFilter::Exact(name.clone())
    } else if let Some(pattern) = selector
        .kernel_name_regex
        .as_deref()
        .or(selector.nvtx_name_regex.as_deref())
    {
        bounded_name_filter(pattern)
    } else {
        CuptiNameFilter::Any
    };
    Ok(CuptiEventFilter {
        record_kind,
        api_domain,
        memcpy_kind,
        name,
    })
}

/// Lower a name regex to an equivalent bounded literal filter when possible.
///
/// Returns [`CuptiNameFilter::Any`] for `.*` and for any pattern that is not
/// exactly an anchored or unanchored escaped literal fitting the Agent buffer.
#[must_use]
pub fn bounded_name_filter(pattern: &str) -> CuptiNameFilter {
    if pattern == ".*" {
        return CuptiNameFilter::Any;
    }
    let candidates: [(&str, &str, NameLowering); 8] = [
        ("^", "$", CuptiNameFilter::Exact),
        ("^", ".*", CuptiNameFilter::Prefix),
        (".*", "$", CuptiNameFilter::Suffix),
        (".*", ".*", CuptiNameFilter::Contains),
        ("^", "", CuptiNameFilter::Prefix),
        ("", "$", CuptiNameFilter::Suffix),
        (".*", "", CuptiNameFilter::Contains),
        ("", "", CuptiNameFilter::Contains),
    ];
    for (prefix, suffix, filter) in candidates {
        let Some(literal) = pattern
            .strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(suffix))
            .and_then(regex_literal)
        else {
            continue;
        };
        if !literal.is_empty() && literal.len() < CUPTI_NAME_CAPACITY {
            return filter(literal);
        }
    }
    CuptiNameFilter::Any
}

fn regex_literal(pattern: &str) -> Option<String> {
    let mut literal = String::with_capacity(pattern.len());
    let mut characters = pattern.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            let escaped = characters.next()?;
            if escaped.is_ascii_alphanumeric() {
                return None;
            }
            literal.push(escaped);
        } else if ".+*?()|[]{}^$".contains(character) {
            return None;
        } else {
            literal.push(character);
        }
    }
    Some(literal)
}

#[cfg(test)]
mod tests {
    use xprobe_protocol::{EventType, MemcpyKind, ResolvedCudaSelector};

    use super::{
        CuptiApiDomain, CuptiFilterError, CuptiMemcpyKind, CuptiNameFilter, CuptiRecordKind,
        bounded_name_filter, event_filter, regex_literal,
    };

    fn selector(event_type: EventType) -> ResolvedCudaSelector {
        ResolvedCudaSelector {
            event_type,
            api_domain: None,
            api_name: None,
            kernel_name_regex: None,
            nvtx_name_regex: None,
            memcpy_kind: None,
        }
    }

    #[test]
    fn lowers_only_equivalent_bounded_name_patterns() {
        assert_eq!(
            bounded_name_filter("^flash_.*"),
            CuptiNameFilter::Prefix("flash_".to_owned())
        );
        assert_eq!(
            bounded_name_filter(".*_kernel$"),
            CuptiNameFilter::Suffix("_kernel".to_owned())
        );
        assert_eq!(
            bounded_name_filter("^gemm$"),
            CuptiNameFilter::Exact("gemm".to_owned())
        );
        assert_eq!(
            bounded_name_filter("cudaLaunch"),
            CuptiNameFilter::Contains("cudaLaunch".to_owned())
        );
        assert_eq!(
            bounded_name_filter(".*xprobe_multisource_kernel.*"),
            CuptiNameFilter::Contains("xprobe_multisource_kernel".to_owned())
        );
        assert_eq!(
            bounded_name_filter("^(flash|attention)$"),
            CuptiNameFilter::Any
        );
        assert_eq!(bounded_name_filter(".*"), CuptiNameFilter::Any);
        assert_eq!(
            bounded_name_filter(&"k".repeat(super::CUPTI_NAME_CAPACITY)),
            CuptiNameFilter::Any
        );
    }

    #[test]
    fn decodes_escaped_regex_literals_conservatively() {
        assert_eq!(regex_literal("kernel\\.v1"), Some("kernel.v1".to_owned()));
        assert_eq!(regex_literal("kernel\\d"), None);
        assert_eq!(regex_literal("kernel+"), None);
    }

    #[test]
    fn lowers_cuda_selectors_to_agent_filters() {
        let mut api = selector(EventType::CudaApiExit);
        api.api_domain = Some("runtime_api".to_owned());
        api.api_name = Some("cudaLaunchKernel".to_owned());
        let filter = event_filter(&api).expect("runtime API selector lowers");
        assert_eq!(filter.record_kind, CuptiRecordKind::CudaApiExit);
        assert_eq!(filter.api_domain, CuptiApiDomain::Runtime);
        assert_eq!(
            filter.name,
            CuptiNameFilter::Exact("cudaLaunchKernel".to_owned())
        );

        let mut memcpy = selector(EventType::GpuMemcpyEnd);
        memcpy.memcpy_kind = Some(MemcpyKind::DeviceToHost);
        let filter = event_filter(&memcpy).expect("memcpy selector lowers");
        assert_eq!(filter.memcpy_kind, CuptiMemcpyKind::DeviceToHost);
        assert_eq!(filter.name, CuptiNameFilter::Any);

        let mut nvtx = selector(EventType::NvtxRangeStart);
        nvtx.nvtx_name_regex = Some("^step$".to_owned());
        let filter = event_filter(&nvtx).expect("NVTX selector lowers");
        assert_eq!(filter.name, CuptiNameFilter::Exact("step".to_owned()));
    }

    #[test]
    fn rejects_selectors_the_agent_cannot_filter() {
        assert_eq!(
            event_filter(&selector(EventType::HostFunctionEntry)),
            Err(CuptiFilterError::NonCudaEventType(
                EventType::HostFunctionEntry
            ))
        );
        let mut unknown = selector(EventType::CudaApiEntry);
        unknown.api_domain = Some("graph_api".to_owned());
        assert_eq!(
            event_filter(&unknown),
            Err(CuptiFilterError::UnsupportedApiDomain(
                "graph_api".to_owned()
            ))
        );
    }
}
