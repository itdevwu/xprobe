use std::{
    collections::BTreeSet,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use xprobe_protocol::{
    Capabilities, CgroupEntry, CheckResult, CheckStatus, ErrorCode, ProcessCredentials,
    ProcessCudaState, ProcessReport, SchemaVersion, TargetIdentity,
};

use crate::doctor;

#[derive(Debug)]
pub enum InspectError {
    TargetNotFound { pid: u32 },
    TargetExited { pid: u32 },
    TargetReused { pid: u32 },
    PermissionDenied { pid: u32, path: PathBuf },
    Io { path: PathBuf, source: io::Error },
    InvalidProc { path: PathBuf, reason: String },
    Environment(doctor::DoctorError),
}

impl InspectError {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::TargetNotFound { .. } => ErrorCode::TargetNotFound,
            Self::TargetExited { .. } => ErrorCode::TargetExited,
            Self::TargetReused { .. } => ErrorCode::TargetReused,
            Self::PermissionDenied { .. } => ErrorCode::PermissionDenied,
            Self::Io { .. } | Self::InvalidProc { .. } | Self::Environment(_) => {
                ErrorCode::Internal
            }
        }
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        matches!(
            self,
            Self::TargetNotFound { .. }
                | Self::TargetExited { .. }
                | Self::TargetReused { .. }
                | Self::PermissionDenied { .. }
        )
    }
}

impl fmt::Display for InspectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetNotFound { pid } => write!(formatter, "target PID {pid} was not found"),
            Self::TargetExited { pid } => {
                write!(formatter, "target PID {pid} exited during inspection")
            }
            Self::TargetReused { pid } => {
                write!(formatter, "target PID {pid} was reused during inspection")
            }
            Self::PermissionDenied { pid, path } => write!(
                formatter,
                "permission denied while inspecting PID {pid} at {}",
                path.display()
            ),
            Self::Io { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::InvalidProc { path, reason } => {
                write!(
                    formatter,
                    "invalid procfs data in {}: {reason}",
                    path.display()
                )
            }
            Self::Environment(error) => write!(formatter, "environment inspection failed: {error}"),
        }
    }
}

impl Error for InspectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Environment(error) => Some(error),
            Self::TargetNotFound { .. }
            | Self::TargetExited { .. }
            | Self::TargetReused { .. }
            | Self::PermissionDenied { .. }
            | Self::InvalidProc { .. } => None,
        }
    }
}

/// Inspect a Linux process without modifying or attaching to it.
///
/// # Errors
///
/// Returns [`InspectError`] if the process is unavailable, cannot be read, is
/// reused during inspection, or exposes malformed procfs data.
pub fn run(pid: u32) -> Result<ProcessReport, InspectError> {
    let first_start_time = read_start_time(pid, true)?;
    let executable = read_link(pid, "exe")?;
    let command_line = parse_command_line(&read_bytes(pid, "cmdline")?, pid)?;
    let status = read_text(pid, "status")?;
    let credentials = parse_credentials(&status, pid)?;
    let namespace_pids = parse_namespace_pids(&status, pid)?;
    let mount_namespace = read_link(pid, "ns/mnt")?;
    let cgroups = parse_cgroups(&read_text(pid, "cgroup")?, pid)?;
    let loaded_libraries = parse_loaded_libraries(&read_text(pid, "maps")?);
    let final_start_time = read_start_time(pid, false)?;

    if first_start_time != final_start_time {
        return Err(InspectError::TargetReused { pid });
    }

    let libcuda_loaded = contains_library(&loaded_libraries, "libcuda.so");
    let libcudart_loaded = contains_library(&loaded_libraries, "libcudart.so");
    let xprobe_cupti_loaded = contains_library(&loaded_libraries, "libxprobe-cupti.so");
    let context = if libcuda_loaded {
        CheckResult {
            status: CheckStatus::Unknown,
            detail: Some("CUDA context state is not externally observable".to_owned()),
        }
    } else {
        CheckResult {
            status: CheckStatus::Unavailable,
            detail: Some("libcuda is not loaded in the target process".to_owned()),
        }
    };

    let local_capabilities = doctor::run()
        .map_err(InspectError::Environment)?
        .capabilities;

    Ok(ProcessReport {
        schema_version: SchemaVersion::current(),
        ok: true,
        target: TargetIdentity {
            pid,
            process_start_time: first_start_time,
        },
        executable,
        command_line,
        credentials,
        namespace_pids,
        mount_namespace,
        cgroups,
        loaded_libraries,
        cuda: ProcessCudaState {
            libcuda_loaded,
            libcudart_loaded,
            xprobe_cupti_loaded,
            context,
        },
        capabilities: Capabilities {
            cuda_callback: xprobe_cupti_loaded,
            cuda_activity: xprobe_cupti_loaded,
            runtime_injection: false,
            ..local_capabilities
        },
    })
}

/// Verify that a previously inspected target still names the same process.
///
/// # Errors
///
/// Returns [`InspectError::TargetExited`] if the process no longer exists, or
/// [`InspectError::TargetReused`] if the PID now belongs to another process.
pub fn verify_target(target: &TargetIdentity) -> Result<(), InspectError> {
    let current_start_time = read_start_time(target.pid, false)?;
    if current_start_time != target.process_start_time {
        return Err(InspectError::TargetReused { pid: target.pid });
    }
    Ok(())
}

fn proc_path(pid: u32, entry: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/{entry}"))
}

fn read_start_time(pid: u32, initial: bool) -> Result<u64, InspectError> {
    let path = proc_path(pid, "stat");
    let stat = fs::read_to_string(&path)
        .map_err(|source| process_io_error(pid, path.clone(), source, initial))?;
    parse_start_time(&stat, &path)
}

fn parse_start_time(stat: &str, path: &Path) -> Result<u64, InspectError> {
    let command_end = stat
        .rfind(')')
        .ok_or_else(|| invalid_proc(path, "missing command terminator"))?;
    let tail = stat
        .get(command_end + 1..)
        .ok_or_else(|| invalid_proc(path, "missing stat fields"))?;
    let value = tail
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| invalid_proc(path, "missing process start time"))?;
    value
        .parse()
        .map_err(|_| invalid_proc(path, "invalid process start time"))
}

fn read_text(pid: u32, entry: &str) -> Result<String, InspectError> {
    let path = proc_path(pid, entry);
    fs::read_to_string(&path).map_err(|source| process_io_error(pid, path, source, false))
}

fn read_bytes(pid: u32, entry: &str) -> Result<Vec<u8>, InspectError> {
    let path = proc_path(pid, entry);
    fs::read(&path).map_err(|source| process_io_error(pid, path, source, false))
}

fn read_link(pid: u32, entry: &str) -> Result<String, InspectError> {
    let path = proc_path(pid, entry);
    let target = fs::read_link(&path)
        .map_err(|source| process_io_error(pid, path.clone(), source, false))?;
    target
        .into_os_string()
        .into_string()
        .map_err(|_| invalid_proc(path, "path is not valid UTF-8"))
}

fn process_io_error(pid: u32, path: PathBuf, source: io::Error, initial: bool) -> InspectError {
    match source.kind() {
        io::ErrorKind::NotFound if initial => InspectError::TargetNotFound { pid },
        io::ErrorKind::NotFound => InspectError::TargetExited { pid },
        io::ErrorKind::PermissionDenied => InspectError::PermissionDenied { pid, path },
        _ => InspectError::Io { path, source },
    }
}

fn invalid_proc(path: impl AsRef<Path>, reason: &str) -> InspectError {
    InspectError::InvalidProc {
        path: path.as_ref().to_owned(),
        reason: reason.to_owned(),
    }
}

fn parse_command_line(bytes: &[u8], pid: u32) -> Result<Vec<String>, InspectError> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| {
            String::from_utf8(argument.to_vec())
                .map_err(|_| invalid_proc(proc_path(pid, "cmdline"), "argument is not valid UTF-8"))
        })
        .collect()
}

fn parse_credentials(status: &str, pid: u32) -> Result<ProcessCredentials, InspectError> {
    let uids = parse_four_ids(status, "Uid:", pid)?;
    let gids = parse_four_ids(status, "Gid:", pid)?;
    Ok(ProcessCredentials {
        real_uid: uids[0],
        effective_uid: uids[1],
        saved_uid: uids[2],
        filesystem_uid: uids[3],
        real_gid: gids[0],
        effective_gid: gids[1],
        saved_gid: gids[2],
        filesystem_gid: gids[3],
    })
}

fn parse_four_ids(status: &str, field: &str, pid: u32) -> Result<[u32; 4], InspectError> {
    let path = proc_path(pid, "status");
    let values = status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .ok_or_else(|| invalid_proc(&path, &format!("missing {field}")))?
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<Vec<u32>, _>>()
        .map_err(|_| invalid_proc(&path, &format!("invalid {field}")))?;
    values
        .try_into()
        .map_err(|_| invalid_proc(path, &format!("expected four values for {field}")))
}

fn parse_namespace_pids(status: &str, pid: u32) -> Result<Vec<u32>, InspectError> {
    let path = proc_path(pid, "status");
    status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .ok_or_else(|| invalid_proc(&path, "missing NSpid"))?
        .split_whitespace()
        .map(|value| {
            value
                .parse()
                .map_err(|_| invalid_proc(&path, "invalid NSpid"))
        })
        .collect()
}

fn parse_cgroups(cgroup: &str, pid: u32) -> Result<Vec<CgroupEntry>, InspectError> {
    let path = proc_path(pid, "cgroup");
    cgroup
        .lines()
        .map(|line| {
            let mut fields = line.splitn(3, ':');
            let hierarchy_id = fields
                .next()
                .ok_or_else(|| invalid_proc(&path, "missing cgroup hierarchy"))?
                .parse()
                .map_err(|_| invalid_proc(&path, "invalid cgroup hierarchy"))?;
            let controllers = fields
                .next()
                .ok_or_else(|| invalid_proc(&path, "missing cgroup controllers"))?
                .split(',')
                .filter(|controller| !controller.is_empty())
                .map(str::to_owned)
                .collect();
            let cgroup_path = fields
                .next()
                .ok_or_else(|| invalid_proc(&path, "missing cgroup path"))?
                .to_owned();
            Ok(CgroupEntry {
                hierarchy_id,
                controllers,
                path: cgroup_path,
            })
        })
        .collect()
}

fn parse_loaded_libraries(maps: &str) -> Vec<String> {
    maps.lines()
        .filter_map(maps_path)
        .filter(|path| path.starts_with('/') && path.contains(".so"))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn maps_path(line: &str) -> Option<&str> {
    let mut fields_seen = 0;
    let mut in_field = false;
    for (index, character) in line.char_indices() {
        if character.is_whitespace() {
            if in_field {
                fields_seen += 1;
                in_field = false;
                if fields_seen == 5 {
                    return Some(line.get(index..)?.trim_start());
                }
            }
        } else {
            in_field = true;
        }
    }
    None
}

fn contains_library(libraries: &[String], name: &str) -> bool {
    libraries.iter().any(|path| {
        Path::new(path)
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .is_some_and(|file_name| file_name.starts_with(name))
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{maps_path, parse_cgroups, parse_start_time};

    #[test]
    fn parses_start_time_after_a_command_with_spaces() {
        let stat = "42 (worker thread) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 98765 20";
        assert_eq!(
            parse_start_time(stat, Path::new("fixture")).unwrap(),
            98_765
        );
    }

    #[test]
    fn extracts_a_maps_path_after_fixed_fields() {
        let line = "7f00-7f10 r-xp 00000000 08:01 42 /usr/lib/libcuda.so.1";
        assert_eq!(maps_path(line), Some("/usr/lib/libcuda.so.1"));
    }

    #[test]
    fn parses_cgroup_v2_entry() {
        let entries = parse_cgroups("0::/user.slice\n", 1).unwrap();
        assert_eq!(entries[0].hierarchy_id, 0);
        assert!(entries[0].controllers.is_empty());
        assert_eq!(entries[0].path, "/user.slice");
    }
}
