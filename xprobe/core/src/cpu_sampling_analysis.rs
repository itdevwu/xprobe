use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use cpp_demangle::{DemangleOptions, Symbol as CppSymbol};
use object::{Object, ObjectSegment, ObjectSymbol, SymbolKind};
use xprobe_protocol::{
    CpuCaptureCompleteness, CpuFrameLanguage, CpuHotspot, CpuSampleCollectionSummary,
    CpuSampleEvent, CpuSampleInventory, CpuSampleInventoryResult, CpuSamplingSpec, CpuStackFrame,
    CpuStackGroup, CpuSymbolizationSummary, ErrorCode, ProcessReport, PythonSymbolizationStatus,
    SchemaVersion, SessionStatus, Warning,
};

use crate::inspect::{self, InspectError};

const MAX_PERF_MAP_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCpuSample {
    pub thread_id: u32,
    pub addresses: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct CpuCaptureData {
    pub samples: Vec<RawCpuSample>,
    pub observed_samples: u64,
    pub lost_samples: u64,
    pub truncated_stacks: u64,
    pub throttled_records: u64,
    pub threads_observed: usize,
    pub threads_attached: usize,
    pub skipped_threads: Vec<u32>,
    pub capacity_reached: bool,
    pub python_status: PythonSymbolizationStatus,
}

#[derive(Debug)]
pub enum CpuAnalysisError {
    Inspect(InspectError),
    Io { path: PathBuf, source: io::Error },
    InvalidMaps { path: PathBuf, reason: String },
    InvalidPerfMap { path: PathBuf, reason: String },
    InvalidUtf8 { path: PathBuf },
    Limit { name: &'static str, value: u64 },
}

impl CpuAnalysisError {
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Inspect(error) => error.code(),
            Self::Io { source, .. } if source.kind() == io::ErrorKind::PermissionDenied => {
                ErrorCode::PermissionDenied
            }
            Self::Limit { .. } => ErrorCode::SessionLimitExceeded,
            Self::Io { .. }
            | Self::InvalidMaps { .. }
            | Self::InvalidPerfMap { .. }
            | Self::InvalidUtf8 { .. } => ErrorCode::Internal,
        }
    }

    #[must_use]
    pub fn recoverable(&self) -> bool {
        match self {
            Self::Inspect(error) => error.recoverable(),
            Self::Io { source, .. } => matches!(
                source.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ),
            Self::Limit { .. } => true,
            Self::InvalidMaps { .. } | Self::InvalidPerfMap { .. } | Self::InvalidUtf8 { .. } => {
                false
            }
        }
    }
}

impl fmt::Display for CpuAnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => error.fmt(formatter),
            Self::Io { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::InvalidMaps { path, reason } => {
                write!(formatter, "invalid {}: {reason}", path.display())
            }
            Self::InvalidPerfMap { path, reason } => {
                write!(
                    formatter,
                    "invalid Python perf map {}: {reason}",
                    path.display()
                )
            }
            Self::InvalidUtf8 { path } => {
                write!(formatter, "{} is not valid UTF-8", path.display())
            }
            Self::Limit { name, value } => {
                write!(
                    formatter,
                    "CPU analysis {name} exceeds the supported bound: {value}"
                )
            }
        }
    }
}

impl Error for CpuAnalysisError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inspect(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::InvalidMaps { .. }
            | Self::InvalidPerfMap { .. }
            | Self::InvalidUtf8 { .. }
            | Self::Limit { .. } => None,
        }
    }
}

impl From<InspectError> for CpuAnalysisError {
    fn from(error: InspectError) -> Self {
        Self::Inspect(error)
    }
}

#[derive(Debug, Clone)]
struct MapRegion {
    start: u64,
    end: u64,
    file_offset: u64,
    path: PathBuf,
}

#[derive(Debug, Clone)]
struct ModuleSymbol {
    file_offset: u64,
    size: u64,
    name: String,
}

#[derive(Debug, Clone)]
struct Module {
    build_id: Option<String>,
    symbols: Vec<ModuleSymbol>,
}

#[derive(Debug, Clone)]
struct PerfMapSymbol {
    start: u64,
    end: u64,
    name: String,
}

struct Symbolizer {
    maps: Vec<MapRegion>,
    modules: BTreeMap<PathBuf, Module>,
    python_symbols: Vec<PerfMapSymbol>,
    python_status: PythonSymbolizationStatus,
    warnings: Vec<Warning>,
}

/// Aggregate and symbolize one completed bounded CPU capture.
///
/// # Errors
///
/// Returns [`CpuAnalysisError`] when target identity, procfs mappings, Python
/// perf-map data, or public integer bounds are invalid.
pub fn analyze(
    report: &ProcessReport,
    spec: &CpuSamplingSpec,
    session_id: String,
    capture: &CpuCaptureData,
) -> Result<CpuSampleInventoryResult, CpuAnalysisError> {
    inspect::verify_target(&report.target)?;
    let mut symbolizer = Symbolizer::load(report, capture.python_status)?;
    let (raw_groups, group_capacity_reached) =
        aggregate_raw_stacks(&capture.samples, spec.max_groups);
    let grouped_samples = raw_groups.iter().map(|(_, count)| count).sum::<u64>();
    let sample_denominator = capture.observed_samples.max(1);
    let stack_groups = raw_groups
        .iter()
        .map(|(addresses, samples)| CpuStackGroup {
            frames: addresses
                .iter()
                .map(|address| symbolizer.symbolize(*address))
                .collect(),
            samples: *samples,
            proportion: ratio(*samples, sample_denominator),
        })
        .collect::<Vec<_>>();
    let hotspots = aggregate_hotspots(
        &raw_groups,
        &symbolizer,
        sample_denominator,
        spec.max_groups,
    );
    let symbolization = summarize_symbolization(&stack_groups, symbolizer.python_status);
    let mut warnings = std::mem::take(&mut symbolizer.warnings);
    append_capture_warnings(capture, &mut warnings);
    if group_capacity_reached {
        warnings.push(warning(
            "CPU_GROUP_CAPACITY_REACHED",
            "distinct stack groups exceeded max_groups; only the heaviest groups and hotspots were retained",
        ));
    }
    if symbolization.python_status == PythonSymbolizationStatus::Active
        && symbolization.resolved_python_frames == 0
    {
        warnings.push(warning(
            "PYTHON_FRAMES_UNRESOLVED",
            "the CPython perf map is active, but sampled callchains contained no resolvable Python trampoline frames",
        ));
    }
    inspect::verify_target(&report.target)?;

    Ok(CpuSampleInventoryResult {
        schema_version: SchemaVersion::current(),
        ok: true,
        session_id,
        status: SessionStatus::Completed,
        target: report.target.clone(),
        inventory: CpuSampleInventory {
            name: spec.name.clone(),
            sample_event: CpuSampleEvent::CpuClock,
            frequency_hz: spec.frequency_hz,
            duration_ms: spec.duration_ms,
            stack_groups,
            hotspots,
        },
        collection: CpuSampleCollectionSummary {
            completeness: if capture_is_complete(capture, grouped_samples, group_capacity_reached) {
                CpuCaptureCompleteness::Complete
            } else {
                CpuCaptureCompleteness::Incomplete
            },
            observed_samples: capture.observed_samples,
            grouped_samples,
            lost_samples: capture.lost_samples,
            sample_capacity: spec.max_samples,
            group_capacity: spec.max_groups,
            groups: u64::try_from(raw_groups.len()).map_err(|_| CpuAnalysisError::Limit {
                name: "group count",
                value: u64::MAX,
            })?,
            table_utilization: ratio(
                u64::try_from(raw_groups.len()).unwrap_or(u64::MAX),
                spec.max_groups.max(1),
            ),
            stack_depth: spec.stack_depth,
            truncated_stacks: capture.truncated_stacks,
            threads_observed: u32::try_from(capture.threads_observed).map_err(|_| {
                CpuAnalysisError::Limit {
                    name: "observed thread count",
                    value: u64::MAX,
                }
            })?,
            threads_attached: u32::try_from(capture.threads_attached).map_err(|_| {
                CpuAnalysisError::Limit {
                    name: "attached thread count",
                    value: u64::MAX,
                }
            })?,
            thread_capacity: spec.max_threads,
        },
        symbolization,
        warnings,
    })
}

impl Symbolizer {
    fn load(
        report: &ProcessReport,
        python_status: PythonSymbolizationStatus,
    ) -> Result<Self, CpuAnalysisError> {
        let maps_path = PathBuf::from(format!("/proc/{}/maps", report.target.pid));
        let maps_text = fs::read_to_string(&maps_path).map_err(|source| CpuAnalysisError::Io {
            path: maps_path.clone(),
            source,
        })?;
        let maps = parse_executable_maps(&maps_text, &maps_path)?;
        let mut modules = BTreeMap::new();
        let mut warnings = Vec::new();
        for path in maps
            .iter()
            .map(|region| &region.path)
            .collect::<BTreeSet<_>>()
        {
            match load_module(path) {
                Ok(module) => {
                    modules.insert(path.clone(), module);
                }
                Err(message) => warnings.push(warning(
                    "NATIVE_MODULE_UNAVAILABLE",
                    &format!("could not symbolize {}: {message}", path.display()),
                )),
            }
        }
        let (python_symbols, python_status) = load_python_symbols(report, python_status)?;
        Ok(Self {
            maps,
            modules,
            python_symbols,
            python_status,
            warnings,
        })
    }

    fn symbolize(&self, address: u64) -> CpuStackFrame {
        if let Some(symbol) = find_perf_symbol(&self.python_symbols, address) {
            return CpuStackFrame {
                address,
                module_path: None,
                build_id: None,
                file_offset: None,
                symbol: Some(symbol.name.clone()),
                symbol_offset: Some(address - symbol.start),
                language: CpuFrameLanguage::Python,
                source_path: None,
                line: None,
            };
        }
        let Some(mapping) = self
            .maps
            .iter()
            .find(|mapping| address >= mapping.start && address < mapping.end)
        else {
            return unresolved_frame(address);
        };
        let file_offset = mapping.file_offset + (address - mapping.start);
        let module = self.modules.get(&mapping.path);
        let symbol = module.and_then(|module| find_module_symbol(&module.symbols, file_offset));
        CpuStackFrame {
            address,
            module_path: Some(mapping.path.to_string_lossy().into_owned()),
            build_id: module.and_then(|module| module.build_id.clone()),
            file_offset: Some(file_offset),
            symbol: symbol.map(|symbol| symbol.name.clone()),
            symbol_offset: symbol.map(|symbol| file_offset - symbol.file_offset),
            language: CpuFrameLanguage::Native,
            source_path: None,
            line: None,
        }
    }
}

fn aggregate_raw_stacks(samples: &[RawCpuSample], max_groups: u64) -> (Vec<(Vec<u64>, u64)>, bool) {
    let mut groups = BTreeMap::<Vec<u64>, u64>::new();
    for sample in samples {
        groups
            .entry(sample.addresses.clone())
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
    }
    let mut groups = groups.into_iter().collect::<Vec<_>>();
    groups.sort_by(|(left_stack, left_count), (right_stack, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_stack.cmp(right_stack))
    });
    let capacity = usize::try_from(max_groups).unwrap_or(usize::MAX);
    let capacity_reached = groups.len() > capacity;
    groups.truncate(capacity);
    (groups, capacity_reached)
}

fn aggregate_hotspots(
    groups: &[(Vec<u64>, u64)],
    symbolizer: &Symbolizer,
    denominator: u64,
    max_hotspots: u64,
) -> Vec<CpuHotspot> {
    let mut counts = BTreeMap::<u64, (u64, u64)>::new();
    for (stack, samples) in groups {
        if let Some(address) = stack.first() {
            let entry = counts.entry(*address).or_default();
            entry.1 = entry.1.saturating_add(*samples);
        }
        let mut seen = BTreeSet::new();
        for address in stack {
            if seen.insert(*address) {
                let entry = counts.entry(*address).or_default();
                entry.0 = entry.0.saturating_add(*samples);
            }
        }
    }
    let mut hotspots = counts
        .into_iter()
        .map(|(address, (inclusive, exclusive))| {
            let frame = symbolizer.symbolize(address);
            let (entry_selector_hint, return_selector_hint) = selector_hints(&frame);
            CpuHotspot {
                frame,
                inclusive_samples: inclusive,
                exclusive_samples: exclusive,
                inclusive_proportion: ratio(inclusive, denominator),
                exclusive_proportion: ratio(exclusive, denominator),
                entry_selector_hint,
                return_selector_hint,
            }
        })
        .collect::<Vec<_>>();
    hotspots.sort_by(|left, right| {
        right
            .inclusive_samples
            .cmp(&left.inclusive_samples)
            .then_with(|| right.exclusive_samples.cmp(&left.exclusive_samples))
            .then_with(|| left.frame.address.cmp(&right.frame.address))
    });
    hotspots.truncate(usize::try_from(max_hotspots).unwrap_or(usize::MAX));
    hotspots
}

fn selector_hints(frame: &CpuStackFrame) -> (Option<String>, Option<String>) {
    if frame.language != CpuFrameLanguage::Native {
        return (None, None);
    }
    let (Some(path), Some(offset), Some(symbol_offset)) =
        (&frame.module_path, frame.file_offset, frame.symbol_offset)
    else {
        return (None, None);
    };
    let Some(symbol_start) = offset.checked_sub(symbol_offset) else {
        return (None, None);
    };
    (
        Some(format!("uprobe:{path}:+0x{symbol_start:x}:entry")),
        Some(format!("uprobe:{path}:+0x{symbol_start:x}:return")),
    )
}

fn summarize_symbolization(
    groups: &[CpuStackGroup],
    python_status: PythonSymbolizationStatus,
) -> CpuSymbolizationSummary {
    let mut summary = CpuSymbolizationSummary {
        total_frames: 0,
        resolved_native_frames: 0,
        resolved_python_frames: 0,
        unresolved_frames: 0,
        python_status,
    };
    for group in groups {
        for frame in &group.frames {
            summary.total_frames += 1;
            match (frame.language, frame.symbol.is_some()) {
                (CpuFrameLanguage::Native, true) => summary.resolved_native_frames += 1,
                (CpuFrameLanguage::Python, true) => summary.resolved_python_frames += 1,
                _ => summary.unresolved_frames += 1,
            }
        }
    }
    summary
}

fn append_capture_warnings(capture: &CpuCaptureData, warnings: &mut Vec<Warning>) {
    if capture.capacity_reached {
        warnings.push(warning(
            "CPU_SAMPLE_CAPACITY_REACHED",
            "the configured sample capacity was reached; shorten or lower the sampling frequency before interpreting proportions",
        ));
    }
    if capture.lost_samples != 0 {
        warnings.push(warning(
            "CPU_SAMPLES_LOST",
            &format!("perf reported {} lost samples", capture.lost_samples),
        ));
    }
    if capture.throttled_records != 0 {
        warnings.push(warning(
            "CPU_SAMPLING_THROTTLED",
            &format!(
                "perf reported {} throttle records",
                capture.throttled_records
            ),
        ));
    }
    if !capture.skipped_threads.is_empty() {
        warnings.push(warning(
            "CPU_THREADS_NOT_ATTACHED",
            &format!(
                "{} observed threads exited or exceeded max_threads before attachment",
                capture.skipped_threads.len()
            ),
        ));
    }
}

fn capture_is_complete(
    capture: &CpuCaptureData,
    grouped_samples: u64,
    group_capacity_reached: bool,
) -> bool {
    !capture.capacity_reached
        && !group_capacity_reached
        && capture.lost_samples == 0
        && capture.throttled_records == 0
        && capture.skipped_threads.is_empty()
        && grouped_samples == capture.observed_samples
}

fn parse_executable_maps(text: &str, path: &Path) -> Result<Vec<MapRegion>, CpuAnalysisError> {
    text.lines()
        .filter_map(|line| match parse_map_line(line, path) {
            Ok(Some(mapping)) => Some(Ok(mapping)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn parse_map_line(line: &str, path: &Path) -> Result<Option<MapRegion>, CpuAnalysisError> {
    let mut fields = line.split_whitespace();
    let range = required_field(&mut fields, path, "address range")?;
    let permissions = required_field(&mut fields, path, "permissions")?;
    let offset = required_field(&mut fields, path, "file offset")?;
    let _device = required_field(&mut fields, path, "device")?;
    let _inode = required_field(&mut fields, path, "inode")?;
    let mapped_path = fields.collect::<Vec<_>>().join(" ");
    if mapped_path.is_empty() {
        return Ok(None);
    }
    if !permissions.contains('x') || !mapped_path.starts_with('/') {
        return Ok(None);
    }
    let mapped_path = mapped_path
        .strip_suffix(" (deleted)")
        .unwrap_or(&mapped_path);
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| invalid_maps(path, "invalid address range"))?;
    let start = parse_hex(start, path, "invalid mapping start")?;
    let end = parse_hex(end, path, "invalid mapping end")?;
    let file_offset = parse_hex(offset, path, "invalid mapping file offset")?;
    if start >= end {
        return Err(invalid_maps(path, "mapping start must precede its end"));
    }
    Ok(Some(MapRegion {
        start,
        end,
        file_offset,
        path: PathBuf::from(mapped_path),
    }))
}

fn required_field<'a>(
    fields: &mut impl Iterator<Item = &'a str>,
    path: &Path,
    name: &str,
) -> Result<&'a str, CpuAnalysisError> {
    fields
        .next()
        .ok_or_else(|| invalid_maps(path, &format!("missing {name}")))
}

fn invalid_maps(path: &Path, reason: &str) -> CpuAnalysisError {
    CpuAnalysisError::InvalidMaps {
        path: path.to_owned(),
        reason: reason.to_owned(),
    }
}

fn parse_hex(value: &str, path: &Path, reason: &str) -> Result<u64, CpuAnalysisError> {
    u64::from_str_radix(value, 16).map_err(|_| invalid_maps(path, reason))
}

fn load_module(path: &Path) -> Result<Module, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let file = object::File::parse(bytes.as_slice()).map_err(|error| error.to_string())?;
    let build_id = file
        .build_id()
        .map_err(|error| error.to_string())?
        .map(hex_encode);
    let mut symbols = BTreeMap::<u64, ModuleSymbol>::new();
    for symbol in file.dynamic_symbols().chain(file.symbols()) {
        if !symbol.is_definition() || symbol.kind() != SymbolKind::Text {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        let Some(file_offset) = virtual_address_to_file_offset(&file, symbol.address()) else {
            continue;
        };
        let name = demangle_cpp(name).unwrap_or_else(|| name.to_owned());
        symbols
            .entry(file_offset)
            .and_modify(|current| current.size = current.size.max(symbol.size()))
            .or_insert(ModuleSymbol {
                file_offset,
                size: symbol.size(),
                name,
            });
    }
    Ok(Module {
        build_id,
        symbols: symbols.into_values().collect(),
    })
}

fn virtual_address_to_file_offset(file: &object::File<'_>, address: u64) -> Option<u64> {
    file.segments().find_map(|segment| {
        let delta = address.checked_sub(segment.address())?;
        let (file_offset, file_size) = segment.file_range();
        (delta < file_size).then(|| file_offset + delta)
    })
}

fn find_module_symbol(symbols: &[ModuleSymbol], offset: u64) -> Option<&ModuleSymbol> {
    let index = symbols.partition_point(|symbol| symbol.file_offset <= offset);
    let symbol = symbols.get(index.checked_sub(1)?)?;
    let next_start = symbols.get(index).map(|next| next.file_offset);
    let within_size = symbol.size != 0 && offset - symbol.file_offset < symbol.size;
    let before_next = symbol.size == 0 && next_start.is_none_or(|next| offset < next);
    (within_size || before_next).then_some(symbol)
}

fn load_python_symbols(
    report: &ProcessReport,
    detected_status: PythonSymbolizationStatus,
) -> Result<(Vec<PerfMapSymbol>, PythonSymbolizationStatus), CpuAnalysisError> {
    if matches!(
        detected_status,
        PythonSymbolizationStatus::NotDetected | PythonSymbolizationStatus::Unsupported
    ) {
        return Ok((Vec::new(), detected_status));
    }
    let path = PathBuf::from(format!(
        "/proc/{}/root/tmp/perf-{}.map",
        report.target.pid, report.target.pid
    ));
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok((Vec::new(), PythonSymbolizationStatus::Inactive));
        }
        Err(source) => return Err(CpuAnalysisError::Io { path, source }),
    };
    if metadata.len() > MAX_PERF_MAP_BYTES {
        return Err(CpuAnalysisError::Limit {
            name: "Python perf map bytes",
            value: metadata.len(),
        });
    }
    let bytes = fs::read(&path).map_err(|source| CpuAnalysisError::Io {
        path: path.clone(),
        source,
    })?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CpuAnalysisError::InvalidUtf8 { path: path.clone() })?;
    let symbols = parse_perf_map(text, &path)?;
    let status = if symbols.is_empty() {
        PythonSymbolizationStatus::Inactive
    } else {
        PythonSymbolizationStatus::Active
    };
    Ok((symbols, status))
}

fn parse_perf_map(text: &str, path: &Path) -> Result<Vec<PerfMapSymbol>, CpuAnalysisError> {
    let mut symbols = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.splitn(3, ' ');
        let start = fields.next().unwrap_or_default();
        let size = fields.next().unwrap_or_default();
        let name = fields.next().unwrap_or_default();
        let start =
            u64::from_str_radix(start, 16).map_err(|_| CpuAnalysisError::InvalidPerfMap {
                path: path.to_owned(),
                reason: format!("line {} has an invalid address", index + 1),
            })?;
        let size = u64::from_str_radix(size, 16).map_err(|_| CpuAnalysisError::InvalidPerfMap {
            path: path.to_owned(),
            reason: format!("line {} has an invalid size", index + 1),
        })?;
        if size == 0 || name.is_empty() {
            return Err(CpuAnalysisError::InvalidPerfMap {
                path: path.to_owned(),
                reason: format!("line {} has an empty symbol or zero size", index + 1),
            });
        }
        let end = start
            .checked_add(size)
            .ok_or_else(|| CpuAnalysisError::InvalidPerfMap {
                path: path.to_owned(),
                reason: format!("line {} address range overflows", index + 1),
            })?;
        symbols.push(PerfMapSymbol {
            start,
            end,
            name: name.to_owned(),
        });
    }
    symbols.sort_by_key(|symbol| symbol.start);
    Ok(symbols)
}

fn find_perf_symbol(symbols: &[PerfMapSymbol], address: u64) -> Option<&PerfMapSymbol> {
    let index = symbols.partition_point(|symbol| symbol.start <= address);
    let symbol = symbols.get(index.checked_sub(1)?)?;
    (address < symbol.end).then_some(symbol)
}

fn unresolved_frame(address: u64) -> CpuStackFrame {
    CpuStackFrame {
        address,
        module_path: None,
        build_id: None,
        file_offset: None,
        symbol: None,
        symbol_offset: None,
        language: CpuFrameLanguage::Unknown,
        source_path: None,
        line: None,
    }
}

fn warning(code: &str, message: &str) -> Warning {
    Warning {
        code: code.to_owned(),
        message: message.to_owned(),
        details: BTreeMap::new(),
    }
}

fn demangle_cpp(name: &str) -> Option<String> {
    if !name.starts_with("_Z") {
        return None;
    }
    CppSymbol::new(name)
        .ok()?
        .demangle(&DemangleOptions::default())
        .ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    use fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}

#[allow(clippy::cast_precision_loss)]
fn ratio(numerator: u64, denominator: u64) -> f64 {
    numerator as f64 / denominator as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_heaviest_stack_groups_deterministically() {
        let samples = vec![
            raw(&[1, 2]),
            raw(&[3, 4]),
            raw(&[1, 2]),
            raw(&[5, 6]),
            raw(&[3, 4]),
            raw(&[1, 2]),
        ];
        assert_eq!(
            aggregate_raw_stacks(&samples, 2),
            (vec![(vec![1, 2], 3), (vec![3, 4], 2)], true)
        );
    }

    #[test]
    fn parses_executable_maps_with_spaces_and_deleted_suffixes() {
        let mappings = parse_executable_maps(
            "55550000-55551000 r-xp 00001000 08:01 42 /tmp/app name (deleted)\n\
             7fff0000-7fff1000 rw-p 00000000 00:00 0 [stack]\n",
            Path::new("maps"),
        )
        .unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].path, PathBuf::from("/tmp/app name"));
        assert_eq!(mappings[0].file_offset, 0x1000);
    }

    #[test]
    fn parses_and_resolves_python_perf_map_symbols() {
        let symbols = parse_perf_map(
            "7f000000 20 py::worker (/srv/app.py:7)\n7f000020 10 py::leaf\n",
            Path::new("perf.map"),
        )
        .unwrap();
        assert_eq!(
            find_perf_symbol(&symbols, 0x7f00_0005).unwrap().name,
            "py::worker (/srv/app.py:7)"
        );
        assert!(find_perf_symbol(&symbols, 0x7f00_0030).is_none());
    }

    #[test]
    fn selector_hints_use_the_resolved_symbol_start() {
        let frame = CpuStackFrame {
            address: 0x7f00_0042,
            module_path: Some("/tmp/native workload".to_owned()),
            build_id: None,
            file_offset: Some(0x1642),
            symbol: Some("hot_loop".to_owned()),
            symbol_offset: Some(0x42),
            language: CpuFrameLanguage::Native,
            source_path: None,
            line: None,
        };
        assert_eq!(
            selector_hints(&frame),
            (
                Some("uprobe:/tmp/native workload:+0x1600:entry".to_owned()),
                Some("uprobe:/tmp/native workload:+0x1600:return".to_owned()),
            )
        );
    }

    #[test]
    fn unresolved_native_frames_do_not_claim_function_boundaries() {
        let frame = CpuStackFrame {
            address: 0x7f00_0042,
            module_path: Some("/tmp/native".to_owned()),
            build_id: None,
            file_offset: Some(0x1642),
            symbol: None,
            symbol_offset: None,
            language: CpuFrameLanguage::Native,
            source_path: None,
            line: None,
        };
        assert_eq!(selector_hints(&frame), (None, None));
    }

    fn raw(addresses: &[u64]) -> RawCpuSample {
        RawCpuSample {
            thread_id: 1,
            addresses: addresses.to_vec(),
        }
    }
}
