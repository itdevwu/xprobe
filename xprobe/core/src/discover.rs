use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, io,
    process::Command,
};

use xprobe_protocol::{
    CudaProcessCandidate, DiscoveryResult, DiscoverySchemaVersion, ErrorCode, ProcessReport,
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
    for (pid, gpu_uuids) in processes {
        if !is_descendant(pid, report.target.pid)? {
            continue;
        }
        let candidate_report = inspect::run(pid)?;
        candidates.push(CudaProcessCandidate {
            target: candidate_report.target,
            parent_pid: inspect::read_parent_pid(pid)?,
            executable: candidate_report.executable,
            command_line: candidate_report.command_line,
            gpu_uuids: gpu_uuids.into_iter().collect(),
        });
    }
    candidates.sort_by_key(|candidate| candidate.target.pid);
    let total_candidates = candidates.len();
    candidates.truncate(limit);
    inspect::verify_target(&report.target)?;
    Ok(DiscoveryResult {
        schema_version: DiscoverySchemaVersion::current(),
        ok: true,
        root: report.target.clone(),
        limit: limit as u64,
        total_candidates: total_candidates as u64,
        truncated: total_candidates > candidates.len(),
        candidates,
        warnings: Vec::new(),
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

fn is_descendant(mut pid: u32, root: u32) -> Result<bool, DiscoverError> {
    let mut visited = BTreeSet::new();
    loop {
        if pid == root {
            return Ok(true);
        }
        if pid == 0 || !visited.insert(pid) {
            return Ok(false);
        }
        pid = inspect::read_parent_pid(pid)?;
    }
}

#[cfg(test)]
mod tests {
    use super::{DiscoverError, parse_compute_processes};

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
