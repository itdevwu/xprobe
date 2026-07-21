use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use xprobe_protocol::{ErrorCode, ProcessReport};

const SUPPORTED_MAJORS: [u32; 2] = [12, 13];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CuptiLibrary {
    pub major: u32,
    pub path: PathBuf,
    pub already_loaded: bool,
}

#[derive(Debug)]
pub enum CuptiCompatibilityError {
    ConflictingTargetVersions(Vec<u32>),
    UnsupportedMajor(u32),
    AmbiguousInstalledVersions(Vec<u32>),
    LibraryNotFound(Option<u32>),
    LinkerCache { detail: String },
    Io { path: PathBuf, source: io::Error },
}

impl CuptiCompatibilityError {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::UnsupportedMajor(_)
            | Self::ConflictingTargetVersions(_)
            | Self::AmbiguousInstalledVersions(_) => ErrorCode::UnsupportedCudaVersion,
            Self::LibraryNotFound(_) | Self::LinkerCache { .. } | Self::Io { .. } => {
                ErrorCode::CuptiNotAvailable
            }
        }
    }
}

impl fmt::Display for CuptiCompatibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConflictingTargetVersions(majors) => {
                write!(
                    formatter,
                    "target maps conflicting CUDA/CUPTI majors {majors:?}"
                )
            }
            Self::UnsupportedMajor(major) => {
                write!(
                    formatter,
                    "CUDA/CUPTI major {major} is unsupported; expected 12 or 13"
                )
            }
            Self::AmbiguousInstalledVersions(majors) => write!(
                formatter,
                "target CUDA major is not observable and installed CUPTI majors {majors:?} are ambiguous"
            ),
            Self::LibraryNotFound(Some(major)) => {
                write!(formatter, "libcupti.so.{major} was not found")
            }
            Self::LibraryNotFound(None) => {
                formatter.write_str("no supported libcupti.so.12 or libcupti.so.13 was found")
            }
            Self::LinkerCache { detail } => {
                write!(
                    formatter,
                    "failed to inspect the dynamic linker cache: {detail}"
                )
            }
            Self::Io { path, source } => {
                write!(formatter, "failed to inspect {}: {source}", path.display())
            }
        }
    }
}

impl Error for CuptiCompatibilityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Return the CUDA/CUPTI major observable from a target's loaded libraries.
///
/// # Errors
///
/// Returns an error if loaded CUDA and CUPTI libraries report conflicting
/// majors or if the observed major is unsupported.
pub fn target_major(report: &ProcessReport) -> Result<Option<u32>, CuptiCompatibilityError> {
    target_major_from_libraries(&report.loaded_libraries)
}

fn target_major_from_libraries(
    libraries: &[String],
) -> Result<Option<u32>, CuptiCompatibilityError> {
    let cupti = collect_target_cupti_majors(libraries);
    let runtime = collect_majors(libraries, "libcudart.so.");
    let observed = cupti.union(&runtime).copied().collect::<Vec<_>>();

    if observed.len() > 1 {
        return Err(CuptiCompatibilityError::ConflictingTargetVersions(observed));
    }
    let major = observed.first().copied();
    if let Some(major) = major {
        ensure_supported(major)?;
    }
    Ok(major)
}

/// Locate the CUPTI library matching the target process.
///
/// # Errors
///
/// Returns an error when the target version is unsupported, installed versions
/// are ambiguous, or the matching library cannot be located.
pub fn resolve_library(report: &ProcessReport) -> Result<CuptiLibrary, CuptiCompatibilityError> {
    let target_major = target_major(report)?;
    if let Some(major) = target_major {
        if let Some(path) = loaded_library(&report.loaded_libraries, "libcupti.so.", major) {
            return Ok(CuptiLibrary {
                major,
                path,
                already_loaded: true,
            });
        }
    }

    let installed = installed_libraries()?;
    let major = match target_major {
        Some(major) => major,
        None if installed.len() > 1 => {
            return Err(CuptiCompatibilityError::AmbiguousInstalledVersions(
                installed.keys().copied().collect(),
            ));
        }
        None => installed
            .keys()
            .next()
            .copied()
            .ok_or(CuptiCompatibilityError::LibraryNotFound(None))?,
    };
    let path = installed
        .get(&major)
        .cloned()
        .ok_or(CuptiCompatibilityError::LibraryNotFound(Some(major)))?;
    Ok(CuptiLibrary {
        major,
        path,
        already_loaded: false,
    })
}

fn ensure_supported(major: u32) -> Result<(), CuptiCompatibilityError> {
    if SUPPORTED_MAJORS.contains(&major) {
        Ok(())
    } else {
        Err(CuptiCompatibilityError::UnsupportedMajor(major))
    }
}

fn collect_majors(libraries: &[String], prefix: &str) -> BTreeSet<u32> {
    libraries
        .iter()
        .filter_map(|library| library_major(Path::new(library), prefix))
        .collect()
}

fn collect_target_cupti_majors(libraries: &[String]) -> BTreeSet<u32> {
    collect_majors(libraries, "libcupti.so.")
        .into_iter()
        .filter(|major| *major < 100)
        .collect()
}

fn loaded_library(libraries: &[String], prefix: &str, major: u32) -> Option<PathBuf> {
    libraries.iter().find_map(|library| {
        let path = Path::new(library);
        (library_major(path, prefix) == Some(major) && !library.ends_with(" (deleted)"))
            .then(|| path.to_owned())
    })
}

fn library_major(path: &Path, prefix: &str) -> Option<u32> {
    let file_name = path.file_name()?.to_str()?;
    let suffix = file_name.strip_prefix(prefix)?;
    suffix.split('.').next()?.parse().ok()
}

fn installed_libraries() -> Result<BTreeMap<u32, PathBuf>, CuptiCompatibilityError> {
    let mut libraries = linker_cache_libraries()?;
    for major in SUPPORTED_MAJORS {
        for path in known_cuda_paths(major)? {
            if path.is_file() {
                libraries.insert(major, path);
                break;
            }
        }
    }
    Ok(libraries)
}

fn linker_cache_libraries() -> Result<BTreeMap<u32, PathBuf>, CuptiCompatibilityError> {
    let output = match Command::new("ldconfig").arg("-p").output() {
        Ok(output) => output,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(source) => {
            return Err(CuptiCompatibilityError::Io {
                path: PathBuf::from("ldconfig"),
                source,
            });
        }
    };
    if !output.status.success() {
        return Err(CuptiCompatibilityError::LinkerCache {
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(parse_linker_cache(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_linker_cache(output: &str) -> BTreeMap<u32, PathBuf> {
    let mut libraries = BTreeMap::new();
    for line in output.lines() {
        let Some((name, path)) = line.trim().split_once(" => ") else {
            continue;
        };
        let Some(major) = library_major(
            Path::new(name.split_whitespace().next().unwrap_or("")),
            "libcupti.so.",
        ) else {
            continue;
        };
        if SUPPORTED_MAJORS.contains(&major) {
            libraries
                .entry(major)
                .or_insert_with(|| PathBuf::from(path));
        }
    }
    libraries
}

fn known_cuda_paths(major: u32) -> Result<Vec<PathBuf>, CuptiCompatibilityError> {
    let mut roots = vec![PathBuf::from("/usr/local/cuda")];
    let local = Path::new("/usr/local");
    match fs::read_dir(local) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|source| CuptiCompatibilityError::Io {
                    path: local.to_owned(),
                    source,
                })?;
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(&format!("cuda-{major}")))
                {
                    roots.push(entry.path());
                }
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(CuptiCompatibilityError::Io {
                path: local.to_owned(),
                source,
            });
        }
    }
    let mut paths = Vec::new();
    for root in roots {
        paths.push(root.join(format!("extras/CUPTI/lib64/libcupti.so.{major}")));
        paths.push(root.join(format!("targets/x86_64-linux/lib/libcupti.so.{major}")));
        paths.push(root.join(format!("lib64/libcupti.so.{major}")));
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        CuptiCompatibilityError, collect_target_cupti_majors, library_major, parse_linker_cache,
        target_major_from_libraries,
    };

    #[test]
    fn parses_cuda_library_majors() {
        assert_eq!(
            library_major(Path::new("/usr/lib/libcudart.so.12.9.79"), "libcudart.so."),
            Some(12)
        );
        assert_eq!(
            library_major(Path::new("/usr/lib/libcupti.so.13"), "libcupti.so."),
            Some(13)
        );
        assert_eq!(
            library_major(Path::new("/usr/lib/libcuda.so.1"), "libcudart.so."),
            None
        );
    }

    #[test]
    fn parses_supported_cupti_entries_from_linker_cache() {
        let libraries = parse_linker_cache(
            "libcupti.so.13 (libc6,x86-64) => /opt/cuda13/libcupti.so.13\n\
             libcupti.so.12 (libc6,x86-64) => /opt/cuda12/libcupti.so.12\n\
             libcuda.so.1 (libc6,x86-64) => /usr/lib/libcuda.so.1\n",
        );
        assert_eq!(libraries[&12], Path::new("/opt/cuda12/libcupti.so.12"));
        assert_eq!(libraries[&13], Path::new("/opt/cuda13/libcupti.so.13"));
        assert_eq!(libraries.len(), 2);
    }

    #[test]
    fn ignores_calendar_versions_in_mapped_cupti_file_names() {
        let libraries = vec!["/usr/local/cuda/lib64/libcupti.so.2025.1.1".to_owned()];
        assert!(collect_target_cupti_majors(&libraries).is_empty());
    }

    #[test]
    fn resolves_and_rejects_target_cuda_majors() {
        let cuda12 = vec![
            "/usr/lib/libcudart.so.12.9".to_owned(),
            "/usr/lib/libcupti.so.2025.1.1".to_owned(),
        ];
        assert_eq!(target_major_from_libraries(&cuda12).unwrap(), Some(12));

        let conflicting = vec![
            "/usr/lib/libcudart.so.12".to_owned(),
            "/usr/lib/libcupti.so.13".to_owned(),
        ];
        assert!(matches!(
            target_major_from_libraries(&conflicting),
            Err(CuptiCompatibilityError::ConflictingTargetVersions(_))
        ));

        let unsupported = vec!["/usr/lib/libcudart.so.11".to_owned()];
        assert!(matches!(
            target_major_from_libraries(&unsupported),
            Err(CuptiCompatibilityError::UnsupportedMajor(11))
        ));
    }
}
