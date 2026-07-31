use std::{
    collections::BTreeSet,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use object::{Object, ObjectSection};
use xprobe_protocol::{ErrorCode, ProcessReport};

const STAPSDT_SECTION: &str = ".note.stapsdt";
const STAPSDT_OWNER: &[u8] = b"stapsdt\0";
const PYTHON_PROVIDER: &str = "python";
const GC_START: &str = "gc__start";
const GC_DONE: &str = "gc__done";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonGcProbes {
    pub binary_path: String,
}

#[derive(Debug)]
pub enum UsdtError {
    Read { path: PathBuf, source: io::Error },
    ParseObject { path: PathBuf, message: String },
    ReadSection { path: PathBuf, message: String },
    MalformedNote { path: PathBuf, message: String },
}

impl UsdtError {
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Read { source, .. } if source.kind() == io::ErrorKind::PermissionDenied => {
                ErrorCode::PermissionDenied
            }
            Self::Read { .. }
            | Self::ParseObject { .. }
            | Self::ReadSection { .. }
            | Self::MalformedNote { .. } => ErrorCode::Internal,
        }
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        matches!(self, Self::Read { .. })
    }
}

impl fmt::Display for UsdtError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::ParseObject { path, message } => {
                write!(
                    formatter,
                    "failed to parse {} as an object: {message}",
                    path.display()
                )
            }
            Self::ReadSection { path, message } => write!(
                formatter,
                "failed to read {STAPSDT_SECTION} from {}: {message}",
                path.display()
            ),
            Self::MalformedNote { path, message } => write!(
                formatter,
                "malformed {STAPSDT_SECTION} in {}: {message}",
                path.display()
            ),
        }
    }
}

impl Error for UsdtError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::ParseObject { .. } | Self::ReadSection { .. } | Self::MalformedNote { .. } => {
                None
            }
        }
    }
}

pub fn find_python_gc_probes(report: &ProcessReport) -> Result<Option<PythonGcProbes>, UsdtError> {
    let mut candidates = BTreeSet::from([PathBuf::from(&report.executable)]);
    candidates.extend(report.loaded_libraries.iter().filter_map(|path| {
        let candidate = Path::new(path);
        candidate
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("libpython") && name.contains(".so"))
            .then(|| candidate.to_path_buf())
    }));

    for path in candidates {
        let names = stap_probe_names(&path)?;
        if names.contains(&(PYTHON_PROVIDER.to_owned(), GC_START.to_owned()))
            && names.contains(&(PYTHON_PROVIDER.to_owned(), GC_DONE.to_owned()))
        {
            return Ok(Some(PythonGcProbes {
                binary_path: path.to_string_lossy().into_owned(),
            }));
        }
    }
    Ok(None)
}

fn stap_probe_names(path: &Path) -> Result<BTreeSet<(String, String)>, UsdtError> {
    let bytes = fs::read(path).map_err(|source| UsdtError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let object = object::File::parse(bytes.as_slice()).map_err(|error| UsdtError::ParseObject {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    let Some(section) = object.section_by_name(STAPSDT_SECTION) else {
        return Ok(BTreeSet::new());
    };
    let data = section.data().map_err(|error| UsdtError::ReadSection {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    parse_stapsdt_notes(data, object.is_little_endian(), object.is_64()).map_err(|message| {
        UsdtError::MalformedNote {
            path: path.to_path_buf(),
            message,
        }
    })
}

fn parse_stapsdt_notes(
    data: &[u8],
    little_endian: bool,
    is_64: bool,
) -> Result<BTreeSet<(String, String)>, String> {
    let mut offset = 0_usize;
    let mut probes = BTreeSet::new();
    while offset < data.len() {
        let namesz = read_u32(data, offset, little_endian)? as usize;
        let descsz = read_u32(data, offset + 4, little_endian)? as usize;
        offset = offset
            .checked_add(12)
            .ok_or_else(|| "note header offset overflowed".to_owned())?;
        let name_end = offset
            .checked_add(namesz)
            .ok_or_else(|| "note owner length overflowed".to_owned())?;
        let owner = data
            .get(offset..name_end)
            .ok_or_else(|| "note owner exceeds section bounds".to_owned())?;
        offset = align_four(name_end)?;
        let desc_end = offset
            .checked_add(descsz)
            .ok_or_else(|| "note descriptor length overflowed".to_owned())?;
        let descriptor = data
            .get(offset..desc_end)
            .ok_or_else(|| "note descriptor exceeds section bounds".to_owned())?;
        offset = align_four(desc_end)?;
        if owner == STAPSDT_OWNER {
            probes.insert(parse_stapsdt_descriptor(descriptor, is_64)?);
        }
    }
    Ok(probes)
}

fn parse_stapsdt_descriptor(descriptor: &[u8], is_64: bool) -> Result<(String, String), String> {
    let address_bytes = if is_64 { 24 } else { 12 };
    let strings = descriptor
        .get(address_bytes..)
        .ok_or_else(|| "descriptor does not contain three addresses".to_owned())?;
    let (provider, rest) = take_c_string(strings, "provider")?;
    let (name, _) = take_c_string(rest, "name")?;
    Ok((provider.to_owned(), name.to_owned()))
}

fn take_c_string<'a>(data: &'a [u8], field: &str) -> Result<(&'a str, &'a [u8]), String> {
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("descriptor {field} is not NUL terminated"))?;
    let value = std::str::from_utf8(&data[..end])
        .map_err(|error| format!("descriptor {field} is not UTF-8: {error}"))?;
    Ok((value, &data[end + 1..]))
}

fn read_u32(data: &[u8], offset: usize, little_endian: bool) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| "note integer offset overflowed".to_owned())?;
    let bytes: [u8; 4] = data
        .get(offset..end)
        .ok_or_else(|| "note header exceeds section bounds".to_owned())?
        .try_into()
        .expect("four-byte range");
    Ok(if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn align_four(value: usize) -> Result<usize, String> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| "note alignment overflowed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{parse_stapsdt_descriptor, parse_stapsdt_notes};

    #[test]
    fn parses_python_gc_probe_names() {
        let descriptor = descriptor("python", "gc__start", "-4@%edi");
        let mut note = Vec::new();
        note.extend_from_slice(&8_u32.to_le_bytes());
        note.extend_from_slice(
            &u32::try_from(descriptor.len())
                .expect("test descriptor fits u32")
                .to_le_bytes(),
        );
        note.extend_from_slice(&3_u32.to_le_bytes());
        note.extend_from_slice(b"stapsdt\0");
        note.extend_from_slice(&descriptor);
        while note.len() % 4 != 0 {
            note.push(0);
        }
        let probes = parse_stapsdt_notes(&note, true, true).unwrap();
        assert!(probes.contains(&("python".to_owned(), "gc__start".to_owned())));
    }

    #[test]
    fn rejects_unterminated_descriptor_strings() {
        let mut descriptor = vec![0; 24];
        descriptor.extend_from_slice(b"python");
        let error = parse_stapsdt_descriptor(&descriptor, true).unwrap_err();
        assert!(error.contains("provider is not NUL terminated"));
    }

    fn descriptor(provider: &str, name: &str, arguments: &str) -> Vec<u8> {
        let mut descriptor = vec![0; 24];
        for value in [provider, name, arguments] {
            descriptor.extend_from_slice(value.as_bytes());
            descriptor.push(0);
        }
        descriptor
    }
}
