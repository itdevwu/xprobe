use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use cpp_demangle::{DemangleOptions, Symbol as CppSymbol};
use object::{Object, ObjectKind, ObjectSegment, ObjectSymbol, SymbolKind};
use xprobe_protocol::{
    ElfObjectKind, ErrorCode, HostProbeKind, ProcessMapping, ProcessReport, ResolvedProbe,
    SchemaVersion,
};

use crate::inspect::{self, InspectError};

#[derive(Debug)]
pub enum ResolveError {
    Inspect(InspectError),
    InvalidSelector(String),
    BinaryNotMapped { path: PathBuf, pid: u32 },
    SymbolNotFound { symbol: String, path: PathBuf },
    AmbiguousSymbol { symbol: String, path: PathBuf },
    OffsetNotLoadable { offset: u64, path: PathBuf },
    AddressNotMapped { offset: u64, path: PathBuf },
    Io { path: PathBuf, source: io::Error },
    InvalidMaps { path: PathBuf, reason: String },
    InvalidElf { path: PathBuf, reason: String },
    UnsupportedElf { path: PathBuf },
}

impl ResolveError {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Inspect(error) => error.code(),
            Self::InvalidSelector(_) | Self::OffsetNotLoadable { .. } => {
                ErrorCode::InvalidEventSelector
            }
            Self::BinaryNotMapped { .. } | Self::AddressNotMapped { .. } => {
                ErrorCode::BinaryNotMapped
            }
            Self::SymbolNotFound { .. } => ErrorCode::SymbolNotFound,
            Self::AmbiguousSymbol { .. } => ErrorCode::AmbiguousTarget,
            Self::Io { .. }
            | Self::InvalidMaps { .. }
            | Self::InvalidElf { .. }
            | Self::UnsupportedElf { .. } => ErrorCode::Internal,
        }
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::Inspect(error) => error.recoverable(),
            Self::InvalidSelector(_)
            | Self::BinaryNotMapped { .. }
            | Self::SymbolNotFound { .. }
            | Self::AmbiguousSymbol { .. }
            | Self::OffsetNotLoadable { .. }
            | Self::AddressNotMapped { .. } => true,
            Self::Io { .. }
            | Self::InvalidMaps { .. }
            | Self::InvalidElf { .. }
            | Self::UnsupportedElf { .. } => false,
        }
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => error.fmt(formatter),
            Self::InvalidSelector(reason) => write!(formatter, "invalid event selector: {reason}"),
            Self::BinaryNotMapped { path, pid } => {
                write!(
                    formatter,
                    "{} is not mapped by target PID {pid}",
                    path.display()
                )
            }
            Self::SymbolNotFound { symbol, path } => write!(
                formatter,
                "symbol {symbol:?} was not found in {}",
                path.display()
            ),
            Self::AmbiguousSymbol { symbol, path } => write!(
                formatter,
                "symbol {symbol:?} resolves to multiple addresses in {}",
                path.display()
            ),
            Self::OffsetNotLoadable { offset, path } => write!(
                formatter,
                "file offset {offset:#x} is not in a loadable segment of {}",
                path.display()
            ),
            Self::AddressNotMapped { offset, path } => write!(
                formatter,
                "file offset {offset:#x} in {} is not mapped by the target",
                path.display()
            ),
            Self::Io { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::InvalidMaps { path, reason } => {
                write!(
                    formatter,
                    "invalid procfs maps data in {}: {reason}",
                    path.display()
                )
            }
            Self::InvalidElf { path, reason } => {
                write!(
                    formatter,
                    "failed to parse ELF {}: {reason}",
                    path.display()
                )
            }
            Self::UnsupportedElf { path } => {
                write!(
                    formatter,
                    "{} is not a supported ELF executable or shared library",
                    path.display()
                )
            }
        }
    }
}

impl Error for ResolveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inspect(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<InspectError> for ResolveError {
    fn from(error: InspectError) -> Self {
        Self::Inspect(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Boundary {
    Entry,
    Return,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProbeTarget {
    Symbol(String),
    FileOffset(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Selector {
    binary: PathBuf,
    target: ProbeTarget,
    boundary: Boundary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MapRegion {
    start: u64,
    end: u64,
    file_offset: u64,
    path: PathBuf,
}

/// Resolve a userspace probe selector against one inspected process.
///
/// # Errors
///
/// Returns [`ResolveError`] when the selector is malformed, the binary or
/// symbol cannot be resolved, procfs changes, or ELF metadata is invalid.
pub fn run(report: &ProcessReport, selector_text: &str) -> Result<ResolvedProbe, ResolveError> {
    inspect::verify_target(&report.target)?;
    let selector = parse_selector(selector_text)?;
    let binary = fs::canonicalize(&selector.binary).map_err(|source| ResolveError::Io {
        path: selector.binary.clone(),
        source,
    })?;
    let maps_path = PathBuf::from(format!("/proc/{}/maps", report.target.pid));
    let maps_text = fs::read_to_string(&maps_path).map_err(|source| ResolveError::Io {
        path: maps_path.clone(),
        source,
    })?;
    let maps = parse_maps(&maps_text, &maps_path)?;
    let binary_maps: Vec<&MapRegion> = maps
        .iter()
        .filter(|region| map_path_matches(&region.path, &binary))
        .collect();
    if binary_maps.is_empty() {
        return Err(ResolveError::BinaryNotMapped {
            path: binary,
            pid: report.target.pid,
        });
    }

    let bytes = fs::read(&binary).map_err(|source| ResolveError::Io {
        path: binary.clone(),
        source,
    })?;
    let file = object::File::parse(bytes.as_slice()).map_err(|error| ResolveError::InvalidElf {
        path: binary.clone(),
        reason: error.to_string(),
    })?;
    let object_kind = classify_object(&file, &binary, &report.executable)?;
    let build_id = file
        .build_id()
        .map_err(|error| ResolveError::InvalidElf {
            path: binary.clone(),
            reason: error.to_string(),
        })?
        .map(hex_encode);

    let (symbol, symbol_demangled, symbol_virtual_address, symbol_size, file_offset) =
        resolve_probe_target(&file, &selector.target, &binary)?;
    let map = binary_maps
        .into_iter()
        .find(|region| region_contains_offset(region, file_offset))
        .ok_or_else(|| ResolveError::AddressNotMapped {
            offset: file_offset,
            path: binary.clone(),
        })?;
    let runtime_address = map.start + (file_offset - map.file_offset);
    let probe_kind = match selector.boundary {
        Boundary::Entry => HostProbeKind::Uprobe,
        Boundary::Return => HostProbeKind::Uretprobe,
    };

    inspect::verify_target(&report.target)?;
    Ok(ResolvedProbe {
        schema_version: SchemaVersion::current(),
        ok: true,
        target: report.target.clone(),
        selector: selector_text.to_owned(),
        binary_path: binary.to_string_lossy().into_owned(),
        build_id,
        object_kind,
        probe_kind,
        symbol,
        symbol_demangled,
        symbol_virtual_address,
        symbol_size,
        file_offset,
        runtime_address,
        mapping: ProcessMapping {
            start_address: map.start,
            end_address: map.end,
            file_offset: map.file_offset,
        },
    })
}

fn parse_selector(text: &str) -> Result<Selector, ResolveError> {
    let rest = text
        .strip_prefix("uprobe:")
        .ok_or_else(|| ResolveError::InvalidSelector("expected uprobe: prefix".to_owned()))?;
    let (binary_and_target, boundary) = rest.rsplit_once(':').ok_or_else(|| {
        ResolveError::InvalidSelector("expected :entry or :return suffix".to_owned())
    })?;
    let boundary = match boundary {
        "entry" => Boundary::Entry,
        "return" => Boundary::Return,
        _ => {
            return Err(ResolveError::InvalidSelector(
                "probe boundary must be entry or return".to_owned(),
            ));
        }
    };
    let (binary, target) = if let Some(parts) = binary_and_target.split_once(":symbol=") {
        parts
    } else {
        binary_and_target.rsplit_once(':').ok_or_else(|| {
            ResolveError::InvalidSelector("expected binary path and symbol or offset".to_owned())
        })?
    };
    if binary.is_empty() || target.is_empty() {
        return Err(ResolveError::InvalidSelector(
            "binary path and probe target must not be empty".to_owned(),
        ));
    }
    let target = if let Some(hex) = target.strip_prefix("+0x") {
        let offset = u64::from_str_radix(hex, 16).map_err(|_| {
            ResolveError::InvalidSelector("offset must be hexadecimal after +0x".to_owned())
        })?;
        ProbeTarget::FileOffset(offset)
    } else if target.starts_with('+') {
        return Err(ResolveError::InvalidSelector(
            "offset must use +0x hexadecimal syntax".to_owned(),
        ));
    } else {
        ProbeTarget::Symbol(target.to_owned())
    };
    Ok(Selector {
        binary: PathBuf::from(binary),
        target,
        boundary,
    })
}

fn parse_maps(text: &str, path: &Path) -> Result<Vec<MapRegion>, ResolveError> {
    text.lines()
        .filter(|line| {
            line.split_whitespace()
                .nth(5)
                .is_some_and(|value| value.starts_with('/'))
        })
        .map(|line| parse_map_region(line, path))
        .collect()
}

fn parse_map_region(line: &str, path: &Path) -> Result<MapRegion, ResolveError> {
    let mut fields = line.split_whitespace();
    let range = fields
        .next()
        .ok_or_else(|| invalid_maps(path, "missing address range"))?;
    let _permissions = fields
        .next()
        .ok_or_else(|| invalid_maps(path, "missing permissions"))?;
    let offset = fields
        .next()
        .ok_or_else(|| invalid_maps(path, "missing file offset"))?;
    let _device = fields
        .next()
        .ok_or_else(|| invalid_maps(path, "missing device"))?;
    let _inode = fields
        .next()
        .ok_or_else(|| invalid_maps(path, "missing inode"))?;
    let mapped_path = fields.collect::<Vec<_>>().join(" ");
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| invalid_maps(path, "invalid address range"))?;
    let start = parse_hex(start, path, "invalid mapping start")?;
    let end = parse_hex(end, path, "invalid mapping end")?;
    let file_offset = parse_hex(offset, path, "invalid mapping file offset")?;
    if start >= end || mapped_path.is_empty() {
        return Err(invalid_maps(path, "invalid file-backed mapping"));
    }
    Ok(MapRegion {
        start,
        end,
        file_offset,
        path: PathBuf::from(mapped_path),
    })
}

fn invalid_maps(path: &Path, reason: &str) -> ResolveError {
    ResolveError::InvalidMaps {
        path: path.to_owned(),
        reason: reason.to_owned(),
    }
}

fn parse_hex(value: &str, path: &Path, reason: &str) -> Result<u64, ResolveError> {
    u64::from_str_radix(value, 16).map_err(|_| invalid_maps(path, reason))
}

fn map_path_matches(mapped: &Path, binary: &Path) -> bool {
    let mapped = mapped.to_string_lossy();
    Path::new(mapped.strip_suffix(" (deleted)").unwrap_or(&mapped)) == binary
}

fn classify_object(
    file: &object::File<'_>,
    binary: &Path,
    executable: &str,
) -> Result<ElfObjectKind, ResolveError> {
    match file.kind() {
        ObjectKind::Executable => Ok(ElfObjectKind::Executable),
        ObjectKind::Dynamic if map_path_matches(Path::new(executable), binary) => {
            Ok(ElfObjectKind::PositionIndependentExecutable)
        }
        ObjectKind::Dynamic => Ok(ElfObjectKind::SharedLibrary),
        _ => Err(ResolveError::UnsupportedElf {
            path: binary.to_owned(),
        }),
    }
}

#[derive(Debug)]
struct ResolvedSymbol {
    mangled: String,
    demangled: Option<String>,
    address: u64,
    size: u64,
}

type ResolvedProbeTarget = (
    Option<String>,
    Option<String>,
    Option<u64>,
    Option<u64>,
    u64,
);

fn resolve_probe_target(
    file: &object::File<'_>,
    target: &ProbeTarget,
    path: &Path,
) -> Result<ResolvedProbeTarget, ResolveError> {
    match target {
        ProbeTarget::Symbol(name) => {
            let resolved = resolve_symbol(file, name, path)?;
            let offset =
                virtual_address_to_file_offset(file, resolved.address).ok_or_else(|| {
                    ResolveError::OffsetNotLoadable {
                        offset: resolved.address,
                        path: path.to_owned(),
                    }
                })?;
            Ok((
                Some(resolved.mangled),
                resolved.demangled,
                Some(resolved.address),
                Some(resolved.size),
                offset,
            ))
        }
        ProbeTarget::FileOffset(offset) => {
            if file_offset_to_virtual_address(file, *offset).is_none() {
                return Err(ResolveError::OffsetNotLoadable {
                    offset: *offset,
                    path: path.to_owned(),
                });
            }
            Ok((None, None, None, None, *offset))
        }
    }
}

fn resolve_symbol(
    file: &object::File<'_>,
    name: &str,
    path: &Path,
) -> Result<ResolvedSymbol, ResolveError> {
    let mut matches = BTreeMap::new();
    collect_symbol_matches(
        file.dynamic_symbols().chain(file.symbols()),
        name,
        false,
        &mut matches,
    );
    if let Some(resolved) = select_symbol_match(matches, name, path)? {
        return Ok(resolved);
    }

    let mut matches = BTreeMap::new();
    collect_symbol_matches(file.dynamic_symbols(), name, true, &mut matches);
    if let Some(resolved) = select_symbol_match(matches, name, path)? {
        return Ok(resolved);
    }

    let mut matches = BTreeMap::new();
    collect_symbol_matches(file.symbols(), name, true, &mut matches);
    select_symbol_match(matches, name, path)?.ok_or_else(|| ResolveError::SymbolNotFound {
        symbol: name.to_owned(),
        path: path.to_owned(),
    })
}

fn collect_symbol_matches<'data>(
    symbols: impl Iterator<Item = impl ObjectSymbol<'data>>,
    name: &str,
    match_demangled: bool,
    matches: &mut BTreeMap<u64, ResolvedSymbol>,
) {
    for symbol in symbols {
        if !symbol.is_definition() || symbol.kind() != SymbolKind::Text {
            continue;
        }
        let Ok(mangled) = symbol.name() else {
            continue;
        };
        let demangled = if match_demangled {
            demangle_cpp(mangled)
        } else {
            None
        };
        let is_match = if match_demangled {
            demangled.as_deref() == Some(name)
        } else {
            mangled == name
        };
        if !is_match {
            continue;
        }
        matches
            .entry(symbol.address())
            .and_modify(|resolved: &mut ResolvedSymbol| {
                resolved.size = resolved.size.max(symbol.size());
            })
            .or_insert_with(|| ResolvedSymbol {
                mangled: mangled.to_owned(),
                demangled: demangled.or_else(|| demangle_cpp(mangled)),
                address: symbol.address(),
                size: symbol.size(),
            });
    }
}

fn select_symbol_match(
    matches: BTreeMap<u64, ResolvedSymbol>,
    name: &str,
    path: &Path,
) -> Result<Option<ResolvedSymbol>, ResolveError> {
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.into_values().next()),
        _ => Err(ResolveError::AmbiguousSymbol {
            symbol: name.to_owned(),
            path: path.to_owned(),
        }),
    }
}

fn demangle_cpp(name: &str) -> Option<String> {
    if !name.starts_with("_Z") {
        return None;
    }
    let symbol = CppSymbol::new(name).ok()?;
    symbol.demangle(&DemangleOptions::default()).ok()
}

fn virtual_address_to_file_offset(file: &object::File<'_>, address: u64) -> Option<u64> {
    file.segments().find_map(|segment| {
        let delta = address.checked_sub(segment.address())?;
        let (file_offset, file_size) = segment.file_range();
        (delta < file_size).then(|| file_offset + delta)
    })
}

fn file_offset_to_virtual_address(file: &object::File<'_>, offset: u64) -> Option<u64> {
    file.segments().find_map(|segment| {
        let (file_offset, file_size) = segment.file_range();
        let delta = offset.checked_sub(file_offset)?;
        (delta < file_size).then(|| segment.address() + delta)
    })
}

fn region_contains_offset(region: &MapRegion, offset: u64) -> bool {
    let length = region.end - region.start;
    offset >= region.file_offset && offset - region.file_offset < length
}

fn hex_encode(bytes: &[u8]) -> String {
    use fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{Boundary, ProbeTarget, map_path_matches, parse_maps, parse_selector};

    #[test]
    fn parses_symbol_and_offset_selectors() {
        let symbol = parse_selector("uprobe:/srv/lib.so:handle_request:return").unwrap();
        assert_eq!(symbol.binary, PathBuf::from("/srv/lib.so"));
        assert_eq!(
            symbol.target,
            ProbeTarget::Symbol("handle_request".to_owned())
        );
        assert_eq!(symbol.boundary, Boundary::Return);

        let offset = parse_selector("uprobe:/srv/app:+0x1234:entry").unwrap();
        assert_eq!(offset.target, ProbeTarget::FileOffset(0x1234));
        assert_eq!(offset.boundary, Boundary::Entry);

        let demangled = parse_selector(
            "uprobe:/srv/libtorch_cpu.so:symbol=at::native::mm(at::Tensor const&):entry",
        )
        .unwrap();
        assert_eq!(
            demangled.target,
            ProbeTarget::Symbol("at::native::mm(at::Tensor const&)".to_owned())
        );
    }

    #[test]
    fn rejects_invalid_selector_boundaries_and_offsets() {
        assert!(parse_selector("tracepoint:sched:sched_switch").is_err());
        assert!(parse_selector("uprobe:/srv/app:+1234:entry").is_err());
        assert!(parse_selector("uprobe:/srv/app:main:middle").is_err());
    }

    #[test]
    fn parses_file_backed_maps_and_deleted_suffixes() {
        let maps = parse_maps(
            "55550000-55551000 r--p 00000000 08:01 42 /tmp/app\n\
             7f000000-7f001000 r-xp 00001000 08:01 43 /tmp/lib name.so (deleted)\n\
             7fff0000-7fff1000 rw-p 00000000 00:00 0 [stack]\n",
            Path::new("maps"),
        )
        .unwrap();
        assert_eq!(maps.len(), 2);
        assert_eq!(maps[1].file_offset, 0x1000);
        assert!(map_path_matches(
            &maps[1].path,
            Path::new("/tmp/lib name.so")
        ));
    }
}
