use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use object::{Object, ObjectSymbol, SymbolKind};
use xprobe_protocol::{
    DiscoveredEvent, DiscoveryOrigin, DiscoveryResult, EndpointSource, ErrorCode, EventType,
    ProcessReport, SchemaVersion, Warning,
};

use crate::inspect::{self, InspectError};

#[derive(Debug)]
pub enum DiscoverError {
    Inspect(InspectError),
    InvalidLimit,
    Io { path: PathBuf, source: io::Error },
    InvalidElf { path: PathBuf, reason: String },
}

impl DiscoverError {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Inspect(error) => error.code(),
            Self::InvalidLimit => ErrorCode::SessionLimitExceeded,
            Self::Io { .. } | Self::InvalidElf { .. } => ErrorCode::Internal,
        }
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::Inspect(error) => error.recoverable(),
            Self::InvalidLimit => true,
            Self::Io { .. } | Self::InvalidElf { .. } => false,
        }
    }
}

impl fmt::Display for DiscoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => error.fmt(formatter),
            Self::InvalidLimit => write!(formatter, "discover limit must be greater than zero"),
            Self::Io { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::InvalidElf { path, reason } => {
                write!(
                    formatter,
                    "failed to parse ELF {}: {reason}",
                    path.display()
                )
            }
        }
    }
}

impl Error for DiscoverError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inspect(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::InvalidLimit | Self::InvalidElf { .. } => None,
        }
    }
}

impl From<InspectError> for DiscoverError {
    fn from(error: InspectError) -> Self {
        Self::Inspect(error)
    }
}

/// Discover selectors supported by xprobe for one target process.
///
/// # Errors
///
/// Returns [`DiscoverError`] when process identity changes, a mapped ELF cannot
/// be read, or the requested result limit is zero.
pub fn run(
    report: &ProcessReport,
    query: Option<&str>,
    limit: usize,
) -> Result<DiscoveryResult, DiscoverError> {
    if limit == 0 {
        return Err(DiscoverError::InvalidLimit);
    }
    inspect::verify_target(&report.target)?;

    let mut paths = BTreeSet::from([PathBuf::from(&report.executable)]);
    paths.extend(report.loaded_libraries.iter().map(PathBuf::from));
    let mut events = BTreeMap::new();
    let mut warnings = Vec::new();
    for path in paths {
        if !path.exists() {
            warnings.push(warning(
                "MAPPED_FILE_UNAVAILABLE",
                format!("mapped file {} is not visible from xprobe", path.display()),
            ));
            continue;
        }
        discover_elf(&path, &mut events)?;
    }
    add_activity_templates(&mut events);

    let query = query.filter(|value| !value.is_empty());
    let mut matches = events
        .into_values()
        .filter(|event| query.is_none_or(|query| event_matches(event, query)))
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| left.selector.cmp(&right.selector));
    let total_matches = matches.len();
    matches.truncate(limit);

    inspect::verify_target(&report.target)?;
    Ok(DiscoveryResult {
        schema_version: SchemaVersion::current(),
        ok: true,
        target: report.target.clone(),
        query: query.map(str::to_owned),
        limit: limit as u64,
        total_matches: total_matches as u64,
        truncated: total_matches > matches.len(),
        events: matches,
        warnings,
    })
}

fn discover_elf(
    path: &Path,
    events: &mut BTreeMap<String, DiscoveredEvent>,
) -> Result<(), DiscoverError> {
    let bytes = fs::read(path).map_err(|source| DiscoverError::Io {
        path: path.to_owned(),
        source,
    })?;
    let file =
        object::File::parse(bytes.as_slice()).map_err(|error| DiscoverError::InvalidElf {
            path: path.to_owned(),
            reason: error.to_string(),
        })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let cuda_domain = if file_name.starts_with("libcudart.so") {
        Some("runtime_api")
    } else if file_name.starts_with("libcuda.so") {
        Some("driver_api")
    } else {
        None
    };

    let mut symbols = BTreeSet::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if symbol.is_definition() && symbol.kind() == SymbolKind::Text {
            if let Ok(name) = symbol.name() {
                if !name.is_empty() {
                    symbols.insert(name.to_owned());
                }
            }
        }
    }
    for symbol in symbols {
        add_host_events(path, &symbol, events);
        if let Some(domain) = cuda_domain {
            if is_cuda_api(domain, &symbol) {
                add_cuda_api_events(domain, &symbol, path, events);
            }
        }
    }
    Ok(())
}

fn add_host_events(path: &Path, symbol: &str, events: &mut BTreeMap<String, DiscoveredEvent>) {
    for (boundary, event_type) in [
        ("entry", EventType::HostFunctionEntry),
        ("return", EventType::HostFunctionExit),
    ] {
        let selector = format!("uprobe:{}:{symbol}:{boundary}", path.display());
        events.entry(selector.clone()).or_insert(DiscoveredEvent {
            selector,
            source: EndpointSource::Host,
            event_type,
            origin: DiscoveryOrigin::ElfSymbol,
            binary_path: Some(path.to_string_lossy().into_owned()),
            symbol: Some(symbol.to_owned()),
            requires_observation: false,
        });
    }
}

fn is_cuda_api(domain: &str, symbol: &str) -> bool {
    match domain {
        "runtime_api" => symbol.starts_with("cuda"),
        "driver_api" => {
            symbol.starts_with("cu") && symbol.as_bytes().get(2).is_some_and(u8::is_ascii_uppercase)
        }
        _ => false,
    }
}

fn add_cuda_api_events(
    domain: &str,
    symbol: &str,
    path: &Path,
    events: &mut BTreeMap<String, DiscoveredEvent>,
) {
    for (boundary, event_type) in [
        ("entry", EventType::CudaApiEntry),
        ("exit", EventType::CudaApiExit),
    ] {
        let selector = format!("cuda:{domain}:{symbol}:{boundary}");
        events.entry(selector.clone()).or_insert(DiscoveredEvent {
            selector,
            source: EndpointSource::Cuda,
            event_type,
            origin: DiscoveryOrigin::CudaApiSymbol,
            binary_path: Some(path.to_string_lossy().into_owned()),
            symbol: Some(symbol.to_owned()),
            requires_observation: false,
        });
    }
}

fn add_activity_templates(events: &mut BTreeMap<String, DiscoveredEvent>) {
    for (selector, event_type) in [
        ("cuda:kernel_start:name~.*", EventType::GpuKernelStart),
        ("cuda:kernel_end:name~.*", EventType::GpuKernelEnd),
        ("cuda:memcpy_start", EventType::GpuMemcpyStart),
        ("cuda:memcpy_end", EventType::GpuMemcpyEnd),
        ("cuda:memset_start", EventType::GpuMemsetStart),
        ("cuda:memset_end", EventType::GpuMemsetEnd),
    ] {
        events.insert(
            selector.to_owned(),
            DiscoveredEvent {
                selector: selector.to_owned(),
                source: EndpointSource::Cuda,
                event_type,
                origin: DiscoveryOrigin::CuptiActivity,
                binary_path: None,
                symbol: None,
                requires_observation: true,
            },
        );
    }
}

fn event_matches(event: &DiscoveredEvent, query: &str) -> bool {
    event.selector.contains(query)
        || event
            .symbol
            .as_deref()
            .is_some_and(|symbol| symbol.contains(query))
        || event
            .binary_path
            .as_deref()
            .is_some_and(|path| path.contains(query))
}

fn warning(code: &str, message: String) -> Warning {
    Warning {
        code: code.to_owned(),
        message,
        details: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use xprobe_protocol::{DiscoveredEvent, DiscoveryOrigin, EndpointSource, EventType};

    use super::{add_activity_templates, event_matches, is_cuda_api};

    #[test]
    fn classifies_cuda_api_symbols() {
        assert!(is_cuda_api("runtime_api", "cudaLaunchKernel"));
        assert!(is_cuda_api("driver_api", "cuLaunchKernel"));
        assert!(!is_cuda_api("driver_api", "cudaLaunchKernel"));
        assert!(is_cuda_api("runtime_api", "cudaGetErrorString"));
    }

    #[test]
    fn activity_templates_are_searchable() {
        let mut events = BTreeMap::new();
        add_activity_templates(&mut events);
        let kernel = events.get("cuda:kernel_start:name~.*").unwrap();
        assert!(kernel.requires_observation);
        assert!(event_matches(kernel, "kernel_start"));

        let host = DiscoveredEvent {
            selector: "uprobe:/srv/app:request:entry".to_owned(),
            source: EndpointSource::Host,
            event_type: EventType::HostFunctionEntry,
            origin: DiscoveryOrigin::ElfSymbol,
            binary_path: Some("/srv/app".to_owned()),
            symbol: Some("request".to_owned()),
            requires_observation: false,
        };
        assert!(event_matches(&host, "request"));
    }
}
