//! CPython interpreter layouts and where they live in a target process.
//!
//! An external sampler reads interpreter state with `process_vm_readv`. The
//! offsets below come from compiling `tests/integration/python-layout/layout.c`
//! against each minor version's internal headers; a unit test pins this table
//! to that fixture and a live test regenerates the fixture from real headers.
//! CPython 3.13 and newer also describe their own layout in
//! `_Py_DebugOffsets`, which the sampler checks against this table at runtime.

use std::{
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
};

use object::{Object, ObjectSegment, ObjectSymbol};
use xprobe_protocol::ProcessReport;

/// How a thread state reaches its innermost frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramePath {
    /// `tstate->frame` (3.9, 3.10) or `tstate->current_frame` (3.13+).
    Direct { tstate_frame: u64 },
    /// `tstate->cframe->current_frame` (3.11, 3.12).
    CFrame {
        tstate_cframe: u64,
        cframe_current_frame: u64,
    },
}

/// Where the GIL records its holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GilPath {
    /// Inside `_PyRuntime` (3.9–3.11).
    Runtime { last_holder: u64, locked: u64 },
    /// Behind `interp->ceval.gil` (3.12+).
    Interpreter {
        interp_gil: u64,
        last_holder: u64,
        locked: u64,
    },
}

/// Positions of checked fields inside `_Py_DebugOffsets` (3.13+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugOffsetsLayout {
    pub version: u64,
    pub runtime_interpreters_head: u64,
    pub interp_threads_head: u64,
    pub tstate_next: u64,
    pub tstate_native_thread_id: u64,
    pub tstate_current_frame: u64,
    pub frame_back: u64,
    pub frame_code: u64,
    pub frame_owner: u64,
    pub code_filename: u64,
    pub code_qualname: u64,
    pub code_firstlineno: u64,
    pub object_type: u64,
}

/// Offsets the sampler reads for one CPython minor version (release builds,
/// 64-bit, with the GIL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PythonLayout {
    pub minor: u8,
    pub runtime_interpreters_head: u64,
    pub gil: GilPath,
    pub interp_threads_head: u64,
    pub tstate_next: u64,
    pub tstate_thread_id: u64,
    /// Present from 3.11; older versions map `pthread_t` to a TID.
    pub tstate_native_thread_id: Option<u64>,
    pub frame: FramePath,
    pub frame_back: u64,
    pub frame_code: u64,
    /// `_PyInterpreterFrame.owner` (3.11+), one byte.
    pub frame_owner: Option<u64>,
    /// Frames owned by this value or above are interpreter entry or C-stack
    /// shims, not Python frames (3.12+).
    pub first_non_python_owner: Option<u8>,
    /// The code reference is a tagged `_PyStackRef` (3.14+).
    pub code_tagged: bool,
    pub code_filename: u64,
    pub code_name: u64,
    pub code_qualname: Option<u64>,
    pub code_firstlineno: u64,
    pub object_type: u64,
    pub ascii_length: u64,
    pub ascii_state: u64,
    pub ascii_size: u64,
    pub compact_size: u64,
    pub debug: Option<DebugOffsetsLayout>,
}

const PRE_311_STRINGS: (u64, u64, u64, u64) = (16, 32, 48, 72);
const POST_312_STRINGS: (u64, u64, u64, u64) = (16, 32, 40, 56);

const LAYOUTS: [PythonLayout; 6] = [
    PythonLayout {
        minor: 9,
        runtime_interpreters_head: 32,
        gil: GilPath::Runtime {
            last_holder: 360,
            locked: 368,
        },
        interp_threads_head: 8,
        tstate_next: 8,
        tstate_thread_id: 176,
        tstate_native_thread_id: None,
        frame: FramePath::Direct { tstate_frame: 24 },
        frame_back: 24,
        frame_code: 32,
        frame_owner: None,
        first_non_python_owner: None,
        code_tagged: false,
        code_filename: 104,
        code_name: 112,
        code_qualname: None,
        code_firstlineno: 40,
        object_type: 8,
        ascii_length: PRE_311_STRINGS.0,
        ascii_state: PRE_311_STRINGS.1,
        ascii_size: PRE_311_STRINGS.2,
        compact_size: PRE_311_STRINGS.3,
        debug: None,
    },
    PythonLayout {
        minor: 10,
        runtime_interpreters_head: 32,
        gil: GilPath::Runtime {
            last_holder: 360,
            locked: 368,
        },
        interp_threads_head: 8,
        tstate_next: 8,
        tstate_thread_id: 176,
        tstate_native_thread_id: None,
        frame: FramePath::Direct { tstate_frame: 24 },
        frame_back: 24,
        frame_code: 32,
        frame_owner: None,
        first_non_python_owner: None,
        code_tagged: false,
        code_filename: 104,
        code_name: 112,
        code_qualname: None,
        code_firstlineno: 40,
        object_type: 8,
        ascii_length: PRE_311_STRINGS.0,
        ascii_state: PRE_311_STRINGS.1,
        ascii_size: PRE_311_STRINGS.2,
        compact_size: PRE_311_STRINGS.3,
        debug: None,
    },
    PythonLayout {
        minor: 11,
        runtime_interpreters_head: 40,
        gil: GilPath::Runtime {
            last_holder: 368,
            locked: 376,
        },
        interp_threads_head: 16,
        tstate_next: 8,
        tstate_thread_id: 152,
        tstate_native_thread_id: Some(160),
        frame: FramePath::CFrame {
            tstate_cframe: 56,
            cframe_current_frame: 8,
        },
        frame_back: 48,
        frame_code: 32,
        frame_owner: Some(69),
        first_non_python_owner: None,
        code_tagged: false,
        code_filename: 112,
        code_name: 120,
        code_qualname: Some(128),
        code_firstlineno: 72,
        object_type: 8,
        ascii_length: PRE_311_STRINGS.0,
        ascii_state: PRE_311_STRINGS.1,
        ascii_size: PRE_311_STRINGS.2,
        compact_size: PRE_311_STRINGS.3,
        debug: None,
    },
    PythonLayout {
        minor: 12,
        runtime_interpreters_head: 40,
        gil: GilPath::Interpreter {
            interp_gil: 384,
            last_holder: 8,
            locked: 16,
        },
        interp_threads_head: 72,
        tstate_next: 8,
        tstate_thread_id: 136,
        tstate_native_thread_id: Some(144),
        frame: FramePath::CFrame {
            tstate_cframe: 56,
            cframe_current_frame: 0,
        },
        frame_back: 8,
        frame_code: 0,
        frame_owner: Some(70),
        first_non_python_owner: Some(3),
        code_tagged: false,
        code_filename: 112,
        code_name: 120,
        code_qualname: Some(128),
        code_firstlineno: 68,
        object_type: 8,
        ascii_length: POST_312_STRINGS.0,
        ascii_state: POST_312_STRINGS.1,
        ascii_size: POST_312_STRINGS.2,
        compact_size: POST_312_STRINGS.3,
        debug: None,
    },
    PythonLayout {
        minor: 13,
        runtime_interpreters_head: 632,
        gil: GilPath::Interpreter {
            interp_gil: 16,
            last_holder: 8,
            locked: 16,
        },
        interp_threads_head: 7344,
        tstate_next: 8,
        tstate_thread_id: 152,
        tstate_native_thread_id: Some(160),
        frame: FramePath::Direct { tstate_frame: 72 },
        frame_back: 8,
        frame_code: 0,
        frame_owner: Some(70),
        first_non_python_owner: Some(3),
        code_tagged: false,
        code_filename: 112,
        code_name: 120,
        code_qualname: Some(128),
        code_firstlineno: 68,
        object_type: 8,
        ascii_length: POST_312_STRINGS.0,
        ascii_state: POST_312_STRINGS.1,
        ascii_size: POST_312_STRINGS.2,
        compact_size: POST_312_STRINGS.3,
        debug: Some(DebugOffsetsLayout {
            version: 8,
            runtime_interpreters_head: 40,
            interp_threads_head: 72,
            tstate_next: 168,
            tstate_native_thread_id: 200,
            tstate_current_frame: 184,
            frame_back: 232,
            frame_code: 240,
            frame_owner: 264,
            code_filename: 280,
            code_qualname: 296,
            code_firstlineno: 312,
            object_type: 360,
        }),
    },
    PythonLayout {
        minor: 14,
        runtime_interpreters_head: 808,
        gil: GilPath::Interpreter {
            interp_gil: 16,
            last_holder: 8,
            locked: 16,
        },
        interp_threads_head: 7344,
        tstate_next: 8,
        tstate_thread_id: 152,
        tstate_native_thread_id: Some(160),
        frame: FramePath::Direct { tstate_frame: 72 },
        frame_back: 8,
        frame_code: 0,
        frame_owner: Some(74),
        first_non_python_owner: Some(3),
        code_tagged: true,
        code_filename: 112,
        code_name: 120,
        code_qualname: Some(128),
        code_firstlineno: 68,
        object_type: 8,
        ascii_length: POST_312_STRINGS.0,
        ascii_state: POST_312_STRINGS.1,
        ascii_size: POST_312_STRINGS.2,
        compact_size: POST_312_STRINGS.3,
        debug: Some(DebugOffsetsLayout {
            version: 8,
            runtime_interpreters_head: 40,
            interp_threads_head: 72,
            tstate_next: 192,
            tstate_native_thread_id: 224,
            tstate_current_frame: 208,
            frame_back: 256,
            frame_code: 264,
            frame_owner: 288,
            code_filename: 320,
            code_qualname: 336,
            code_firstlineno: 352,
            object_type: 408,
        }),
    },
];

/// The layout of CPython `3.minor`, if xprobe supports it.
#[must_use]
pub fn layout(minor: u8) -> Option<&'static PythonLayout> {
    LAYOUTS.iter().find(|layout| layout.minor == minor)
}

/// Minor versions with a known layout.
#[must_use]
pub fn supported_minors() -> Vec<u8> {
    LAYOUTS.iter().map(|layout| layout.minor).collect()
}

/// A CPython interpreter found in a target's mappings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonRuntime {
    /// The executable or libpython that defines `_PyRuntime`.
    pub binary: PathBuf,
    pub minor: u8,
    pub layout: &'static PythonLayout,
    /// Runtime addresses in the target.
    pub runtime_address: u64,
    pub code_type_address: u64,
}

#[derive(Debug)]
pub enum PythonLocateError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    InvalidElf {
        path: PathBuf,
        reason: String,
    },
    /// No mapped object defines `_PyRuntime`.
    NotPython,
    UnknownVersion {
        path: PathBuf,
    },
    UnsupportedVersion {
        path: PathBuf,
        minor: u8,
    },
    NotMapped {
        path: PathBuf,
    },
}

impl fmt::Display for PythonLocateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::InvalidElf { path, reason } => {
                write!(
                    formatter,
                    "{} is not a readable ELF object: {reason}",
                    path.display()
                )
            }
            Self::NotPython => write!(
                formatter,
                "no mapped executable or libpython defines the CPython runtime (_PyRuntime)"
            ),
            Self::UnknownVersion { path } => write!(
                formatter,
                "cannot tell which CPython version {} is",
                path.display()
            ),
            Self::UnsupportedVersion { path, minor } => write!(
                formatter,
                "{} is CPython 3.{minor}; external sampling supports 3.{}",
                path.display(),
                supported_minors()
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(", 3.")
            ),
            Self::NotMapped { path } => write!(
                formatter,
                "{} is not mapped from file offset zero in the target",
                path.display()
            ),
        }
    }
}

impl Error for PythonLocateError {}

/// Find the CPython runtime of an inspected process.
///
/// # Errors
///
/// Returns [`PythonLocateError`] when no mapped object is CPython, its
/// version is unknown or unsupported, or its files or mappings are unreadable.
pub fn locate(report: &ProcessReport) -> Result<PythonRuntime, PythonLocateError> {
    let maps_path = PathBuf::from(format!("/proc/{}/maps", report.target.pid));
    let maps = fs::read_to_string(&maps_path).map_err(|source| PythonLocateError::Io {
        path: maps_path,
        source,
    })?;
    let mut candidates = vec![PathBuf::from(&report.executable)];
    candidates.extend(
        report
            .loaded_libraries
            .iter()
            .map(PathBuf::from)
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("libpython"))
            }),
    );
    for path in candidates {
        let bytes = fs::read(&path).map_err(|source| PythonLocateError::Io {
            path: path.clone(),
            source,
        })?;
        let Some(symbols) = runtime_symbols(&path, &bytes)? else {
            continue;
        };
        let minor = symbols
            .version_hex
            .map(|hex| u8::try_from((hex >> 16) & 0xff).unwrap_or(u8::MAX))
            .or_else(|| minor_from_name(&path))
            .ok_or_else(|| PythonLocateError::UnknownVersion { path: path.clone() })?;
        let layout = layout(minor).ok_or_else(|| PythonLocateError::UnsupportedVersion {
            path: path.clone(),
            minor,
        })?;
        let base = load_base(&maps, &path)
            .ok_or_else(|| PythonLocateError::NotMapped { path: path.clone() })?;
        let bias = base.wrapping_sub(symbols.first_load_address);
        return Ok(PythonRuntime {
            binary: path,
            minor,
            layout,
            runtime_address: bias.wrapping_add(symbols.runtime),
            code_type_address: bias.wrapping_add(symbols.code_type),
        });
    }
    Err(PythonLocateError::NotPython)
}

struct RuntimeSymbols {
    runtime: u64,
    code_type: u64,
    /// `Py_Version` (3.11+), read from the file.
    version_hex: Option<u64>,
    /// Page-aligned address of the segment loaded from file offset zero.
    first_load_address: u64,
}

fn runtime_symbols(path: &Path, bytes: &[u8]) -> Result<Option<RuntimeSymbols>, PythonLocateError> {
    let file = object::File::parse(bytes).map_err(|error| PythonLocateError::InvalidElf {
        path: path.to_owned(),
        reason: error.to_string(),
    })?;
    let address = |wanted: &str| {
        file.dynamic_symbols()
            .chain(file.symbols())
            .find(|symbol| symbol.name() == Ok(wanted) && symbol.address() != 0)
            .map(|symbol| symbol.address())
    };
    let (Some(runtime), Some(code_type)) = (address("_PyRuntime"), address("PyCode_Type")) else {
        return Ok(None);
    };
    let first_load_address = file
        .segments()
        .find(|segment| segment.file_range().0 == 0)
        .map(|segment| segment.address() & !0xfff)
        .ok_or_else(|| PythonLocateError::InvalidElf {
            path: path.to_owned(),
            reason: "no segment loads from file offset zero".to_owned(),
        })?;
    let version_hex = address("Py_Version").and_then(|symbol| {
        file.segments().find_map(|segment| {
            let (offset, size) = segment.file_range();
            let start = segment.address();
            (symbol >= start && symbol + 8 <= start + size).then(|| {
                let at = usize::try_from(offset + (symbol - start)).ok()?;
                let raw = bytes.get(at..at + 8)?;
                Some(u64::from_le_bytes(raw.try_into().ok()?))
            })?
        })
    });
    Ok(Some(RuntimeSymbols {
        runtime,
        code_type,
        version_hex,
        first_load_address,
    }))
}

/// `3.minor` from a `python3.N` or `libpython3.N` file name.
fn minor_from_name(path: &Path) -> Option<u8> {
    let name = path.file_name()?.to_str()?;
    let rest = name
        .strip_prefix("libpython3.")
        .or_else(|| name.strip_prefix("python3."))?;
    let digits = rest
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits.parse().ok()
}

/// Start address of the mapping of `path` at file offset zero.
fn load_base(maps: &str, path: &Path) -> Option<u64> {
    maps.lines().find_map(|line| {
        // address perms offset dev inode path, where the path may hold spaces.
        let mut rest = line;
        let mut fields = [""; 5];
        for field in &mut fields {
            rest = rest.trim_start();
            let end = rest.find(char::is_whitespace)?;
            *field = &rest[..end];
            rest = &rest[end..];
        }
        let mapped = rest.trim();
        let mapped = mapped.strip_suffix(" (deleted)").unwrap_or(mapped);
        if u64::from_str_radix(fields[2], 16).ok()? != 0 || Path::new(mapped) != path {
            return None;
        }
        u64::from_str_radix(fields[0].split_once('-')?.0, 16).ok()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{FramePath, GilPath, LAYOUTS, PythonLayout, load_base, minor_from_name};

    /// The fields `layout.c` prints, from this table.
    fn printed(layout: &PythonLayout) -> BTreeMap<String, u64> {
        let mut fields = BTreeMap::from([
            (
                "runtime_interpreters_head",
                layout.runtime_interpreters_head,
            ),
            ("interp_threads_head", layout.interp_threads_head),
            ("tstate_next", layout.tstate_next),
            ("tstate_thread_id", layout.tstate_thread_id),
            ("frame_back", layout.frame_back),
            ("frame_code", layout.frame_code),
            ("code_filename", layout.code_filename),
            ("code_name", layout.code_name),
            ("code_firstlineno", layout.code_firstlineno),
            ("object_type", layout.object_type),
            ("ascii_length", layout.ascii_length),
            ("ascii_state", layout.ascii_state),
            ("ascii_size", layout.ascii_size),
            ("compact_size", layout.compact_size),
        ]);
        match layout.gil {
            GilPath::Runtime {
                last_holder,
                locked,
            } => {
                fields.insert("runtime_gil_last_holder", last_holder);
                fields.insert("runtime_gil_locked", locked);
            }
            GilPath::Interpreter {
                interp_gil,
                last_holder,
                locked,
            } => {
                fields.insert("interp_ceval_gil", interp_gil);
                fields.insert("gil_last_holder", last_holder);
                fields.insert("gil_locked", locked);
            }
        }
        match layout.frame {
            FramePath::Direct { tstate_frame } if layout.minor >= 13 => {
                fields.insert("tstate_current_frame", tstate_frame);
            }
            FramePath::Direct { tstate_frame } => {
                fields.insert("tstate_frame", tstate_frame);
            }
            FramePath::CFrame {
                tstate_cframe,
                cframe_current_frame,
            } => {
                fields.insert("tstate_cframe", tstate_cframe);
                fields.insert("cframe_current_frame", cframe_current_frame);
            }
        }
        let optional = [
            ("tstate_native_thread_id", layout.tstate_native_thread_id),
            ("frame_owner", layout.frame_owner),
            ("code_qualname", layout.code_qualname),
            (
                "first_non_python_owner",
                layout.first_non_python_owner.map(u64::from),
            ),
        ];
        for (name, value) in optional {
            if let Some(value) = value {
                fields.insert(name, value);
            }
        }
        if layout.frame_owner.is_some() {
            fields.insert("frame_owner_size", 1);
        }
        if layout.debug.is_some() {
            fields.insert("debug_offsets", 0);
        }
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect()
    }

    #[test]
    fn layouts_match_the_header_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/integration/python-layout/expected.json"
        ))
        .unwrap();
        for layout in &LAYOUTS {
            let version = format!("3.{}", layout.minor);
            let expected: BTreeMap<String, u64> =
                serde_json::from_value(fixture["layouts"][&version].clone()).unwrap();
            assert_eq!(printed(layout), expected, "CPython {version}");
            if let Some(debug) = layout.debug {
                let expected: BTreeMap<String, u64> =
                    serde_json::from_value(fixture["debug_offsets"][&version].clone()).unwrap();
                for (name, value) in [
                    ("version", debug.version),
                    ("runtime_interpreters_head", debug.runtime_interpreters_head),
                    ("interp_threads_head", debug.interp_threads_head),
                    ("tstate_next", debug.tstate_next),
                    ("tstate_native_thread_id", debug.tstate_native_thread_id),
                    ("tstate_current_frame", debug.tstate_current_frame),
                    ("frame_back", debug.frame_back),
                    ("frame_code", debug.frame_code),
                    ("frame_owner", debug.frame_owner),
                    ("code_filename", debug.code_filename),
                    ("code_qualname", debug.code_qualname),
                    ("code_firstlineno", debug.code_firstlineno),
                    ("object_type", debug.object_type),
                ] {
                    assert_eq!(expected[name], value, "CPython {version} debug {name}");
                }
            }
        }
    }

    #[test]
    fn reads_minor_versions_from_file_names() {
        for (name, minor) in [
            ("/usr/lib/libpython3.10.so.1.0", Some(10)),
            ("/usr/local/bin/python3.12", Some(12)),
            ("/opt/conda/bin/python3.9", Some(9)),
            ("/usr/bin/python3", None),
        ] {
            assert_eq!(minor_from_name(std::path::Path::new(name)), minor, "{name}");
        }
    }

    #[test]
    fn finds_the_mapping_at_file_offset_zero() {
        let maps = "\
55d0c0000000-55d0c0001000 r--p 00000000 08:01 12 /usr/bin/python3.12
55d0c0001000-55d0c0200000 r-xp 00001000 08:01 12 /usr/bin/python3.12
7f0000000000-7f0000010000 r--p 00000000 08:01 13 /usr/lib/lib with space.so
";
        assert_eq!(
            load_base(maps, std::path::Path::new("/usr/bin/python3.12")),
            Some(0x55d0_c000_0000)
        );
        assert_eq!(
            load_base(maps, std::path::Path::new("/usr/lib/lib with space.so")),
            Some(0x7f00_0000_0000)
        );
        assert_eq!(
            load_base(maps, std::path::Path::new("/usr/bin/other")),
            None
        );
    }
}
