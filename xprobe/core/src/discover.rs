use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, io,
    process::Command,
};

use xprobe_protocol::{
    CudaProcessCandidate, DiscoveryResult, ErrorCode, ProcessReport, SchemaVersion, Warning,
};

use crate::inspect::{self, InspectError};

#[derive(Debug)]
pub enum DiscoverError {
    Inspect(InspectError),
    InvalidLimit,
    NvmlCommand(io::Error),
    NvmlFailed { status: Option<i32>, stderr: String },
    InvalidNvmlOutput(String),
}

impl DiscoverError {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Inspect(error) => error.code(),
            Self::InvalidLimit => ErrorCode::SessionLimitExceeded,
            Self::NvmlCommand(_) | Self::NvmlFailed { .. } => ErrorCode::CuptiNotAvailable,
            Self::InvalidNvmlOutput(_) => ErrorCode::Internal,
        }
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::Inspect(error) => error.recoverable(),
            Self::InvalidLimit | Self::NvmlCommand(_) | Self::NvmlFailed { .. } => true,
            Self::InvalidNvmlOutput(_) => false,
        }
    }
}

impl fmt::Display for DiscoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => error.fmt(formatter),
            Self::InvalidLimit => formatter.write_str("discover limit must be greater than zero"),
            Self::NvmlCommand(error) => write!(formatter, "failed to execute nvidia-smi: {error}"),
            Self::NvmlFailed { status, stderr } => write!(
                formatter,
                "nvidia-smi compute-process query failed with status {status:?}: {stderr}"
            ),
            Self::InvalidNvmlOutput(line) => {
                write!(
                    formatter,
                    "nvidia-smi returned an invalid compute-process row: {line:?}"
                )
            }
        }
    }
}

impl Error for DiscoverError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inspect(error) => Some(error),
            Self::NvmlCommand(error) => Some(error),
            Self::InvalidLimit | Self::NvmlFailed { .. } | Self::InvalidNvmlOutput(_) => None,
        }
    }
}

impl From<InspectError> for DiscoverError {
    fn from(error: InspectError) -> Self {
        Self::Inspect(error)
    }
}

/// List CUDA compute-context holders at or below one process-tree root.
///
/// # Errors
///
/// Returns [`DiscoverError`] when NVML cannot enumerate compute processes,
/// procfs identity changes, or the requested result limit is zero.
pub fn run(report: &ProcessReport, limit: usize) -> Result<DiscoveryResult, DiscoverError> {
    if limit == 0 {
        return Err(DiscoverError::InvalidLimit);
    }
    inspect::verify_target(&report.target)?;
    let output = Command::new("nvidia-smi")
        .args([
            "--query-compute-apps=pid,gpu_uuid",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .map_err(DiscoverError::NvmlCommand)?;
    if !output.status.success() {
        return Err(DiscoverError::NvmlFailed {
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    let rows = String::from_utf8(output.stdout)
        .map_err(|error| DiscoverError::InvalidNvmlOutput(error.to_string()))?;
    let processes = parse_compute_processes(&rows)?;
    let mut candidates = Vec::new();
    let mut unavailable = Vec::new();
    for (pid, gpu_uuids) in processes {
        match ancestry(pid, report.target.pid, inspect::read_parent_pid)? {
            Ancestry::Descendant => {}
            Ancestry::Unrelated => continue,
            Ancestry::Unavailable => {
                unavailable.push(pid);
                continue;
            }
        }
        let candidate = match inspect::run(pid).and_then(|candidate_report| {
            Ok(CudaProcessCandidate {
                parent_pid: inspect::read_parent_pid(pid)?,
                target: candidate_report.target,
                executable: candidate_report.executable,
                command_line: candidate_report.command_line,
                gpu_uuids: gpu_uuids.into_iter().collect(),
            })
        }) {
            Ok(candidate) => candidate,
            Err(InspectError::TargetExited { .. } | InspectError::TargetNotFound { .. }) => {
                unavailable.push(pid);
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        candidates.push(candidate);
    }
    candidates.sort_by_key(|candidate| candidate.target.pid);
    let total_candidates = candidates.len();
    candidates.truncate(limit);
    inspect::verify_target(&report.target)?;
    Ok(DiscoveryResult {
        schema_version: SchemaVersion::current(),
        ok: true,
        root: report.target.clone(),
        limit: limit as u64,
        total_candidates: total_candidates as u64,
        truncated: total_candidates > candidates.len(),
        candidates,
        warnings: unavailable_warning(&unavailable).into_iter().collect(),
    })
}

/// Relationship between an NVML compute PID and the requested root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ancestry {
    Descendant,
    Unrelated,
    /// The PID is not visible in this PID namespace or exited before its
    /// ancestry could be read. Either way it cannot be inspected as a worker.
    Unavailable,
}

/// Walk parent links from `pid` to `root`. NVML reports compute processes from
/// every container sharing the GPU, so a PID that this namespace cannot see is
/// not a descendant of `root`. If an ancestor exits mid-walk the candidate has
/// been reparented; walk once more from the candidate.
fn ancestry(
    pid: u32,
    root: u32,
    parent_of: impl Fn(u32) -> Result<u32, InspectError>,
) -> Result<Ancestry, DiscoverError> {
    for _ in 0..2 {
        match walk_ancestry(pid, root, &parent_of) {
            Ok(true) => return Ok(Ancestry::Descendant),
            Ok(false) => return Ok(Ancestry::Unrelated),
            Err(InspectError::TargetExited { pid: missing }) if missing == pid => {
                return Ok(Ancestry::Unavailable);
            }
            Err(InspectError::TargetExited { .. }) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(Ancestry::Unavailable)
}

fn walk_ancestry(
    mut pid: u32,
    root: u32,
    parent_of: &impl Fn(u32) -> Result<u32, InspectError>,
) -> Result<bool, InspectError> {
    let mut visited = BTreeSet::new();
    loop {
        if pid == root {
            return Ok(true);
        }
        if pid == 0 || !visited.insert(pid) {
            return Ok(false);
        }
        pid = parent_of(pid)?;
    }
}

fn unavailable_warning(pids: &[u32]) -> Option<Warning> {
    if pids.is_empty() {
        return None;
    }
    Some(Warning {
        code: "NVML_PROCESS_UNAVAILABLE".to_owned(),
        message: format!(
            "{} NVML compute processes are not visible in this PID namespace or exited before inspection",
            pids.len()
        ),
        details: [("nvml_pids".to_owned(), serde_json::json!(pids))]
            .into_iter()
            .collect(),
    })
}

fn parse_compute_processes(output: &str) -> Result<BTreeMap<u32, BTreeSet<String>>, DiscoverError> {
    let mut processes = BTreeMap::<u32, BTreeSet<String>>::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let (pid, uuid) = line
            .split_once(',')
            .ok_or_else(|| DiscoverError::InvalidNvmlOutput(line.to_owned()))?;
        let pid = pid
            .trim()
            .parse::<u32>()
            .map_err(|_| DiscoverError::InvalidNvmlOutput(line.to_owned()))?;
        let uuid = uuid.trim();
        if uuid.is_empty() {
            return Err(DiscoverError::InvalidNvmlOutput(line.to_owned()));
        }
        processes.entry(pid).or_default().insert(uuid.to_owned());
    }
    Ok(processes)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::inspect::InspectError;

    use super::{Ancestry, DiscoverError, ancestry, parse_compute_processes, unavailable_warning};

    fn tree(edges: &[(u32, u32)]) -> impl Fn(u32) -> Result<u32, InspectError> {
        let parents = edges.iter().copied().collect::<BTreeMap<_, _>>();
        move |pid| {
            parents
                .get(&pid)
                .copied()
                .ok_or(InspectError::TargetExited { pid })
        }
    }

    #[test]
    fn classifies_descendants_unrelated_and_invisible_processes() {
        let parents = tree(&[(30, 20), (20, 10), (10, 1), (40, 1), (1, 0)]);
        assert_eq!(ancestry(30, 10, &parents).unwrap(), Ancestry::Descendant);
        assert_eq!(ancestry(10, 10, &parents).unwrap(), Ancestry::Descendant);
        assert_eq!(ancestry(40, 10, &parents).unwrap(), Ancestry::Unrelated);
        assert_eq!(ancestry(111, 10, &parents).unwrap(), Ancestry::Unavailable);
    }

    #[test]
    fn rewalks_once_when_an_ancestor_exits_mid_walk() {
        let calls = std::cell::Cell::new(0);
        let parents = |pid: u32| {
            calls.set(calls.get() + 1);
            match (pid, calls.get()) {
                (30, 1) => Ok(20),
                (20, 2) => Err(InspectError::TargetExited { pid: 20 }),
                (30, _) => Ok(10),
                (pid, _) => Err(InspectError::TargetExited { pid }),
            }
        };
        assert_eq!(ancestry(30, 10, parents).unwrap(), Ancestry::Descendant);
    }

    #[test]
    fn propagates_other_inspection_failures() {
        let denied = |pid: u32| {
            Err(InspectError::PermissionDenied {
                pid,
                path: format!("/proc/{pid}/stat").into(),
            })
        };
        assert!(matches!(
            ancestry(30, 10, denied),
            Err(DiscoverError::Inspect(
                InspectError::PermissionDenied { .. }
            ))
        ));
    }

    #[test]
    fn reports_unavailable_nvml_processes() {
        assert!(unavailable_warning(&[]).is_none());
        let warning = unavailable_warning(&[111, 222]).unwrap();
        assert_eq!(warning.code, "NVML_PROCESS_UNAVAILABLE");
        assert_eq!(warning.details["nvml_pids"], serde_json::json!([111, 222]));
    }

    #[test]
    fn groups_compute_processes_across_devices() {
        let processes =
            parse_compute_processes("42, GPU-b\n7, GPU-a\n42, GPU-a\n42, GPU-a\n").unwrap();
        assert_eq!(
            processes[&42]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["GPU-a", "GPU-b"]
        );
    }

    #[test]
    fn rejects_malformed_nvml_rows() {
        assert!(matches!(
            parse_compute_processes("not-a-pid, GPU-a"),
            Err(DiscoverError::InvalidNvmlOutput(_))
        ));
    }
}
