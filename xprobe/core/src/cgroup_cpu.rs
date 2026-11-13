//! CFS bandwidth throttling counters for a process's CPU cgroup.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use xprobe_protocol::{CgroupCpuThrottling, CgroupVersion};

use crate::inspect::InspectError;

/// The CPU controller directory for one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuCgroup {
    pub version: CgroupVersion,
    pub path: String,
    directory: PathBuf,
}

/// A configured CFS bandwidth limit.
#[derive(Debug, Clone, Copy, PartialEq)]
enum CpuLimit {
    Unlimited,
    Cpus(f64),
}

impl CpuLimit {
    const fn cpus(self) -> Option<f64> {
        match self {
            Self::Unlimited => None,
            Self::Cpus(cpus) => Some(cpus),
        }
    }
}

/// Cumulative throttling counters at one point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuCounters {
    pub periods: u64,
    pub throttled_periods: u64,
    pub throttled_ns: u64,
}

/// Find the CPU cgroup of `pid` as seen from this mount namespace.
///
/// Returns `Ok(None)` when no CPU controller directory is mounted for it.
///
/// # Errors
///
/// Returns [`InspectError`] when `/proc/<pid>/cgroup` is unreadable or
/// malformed.
pub fn locate(pid: u32) -> Result<Option<CpuCgroup>, InspectError> {
    let path = PathBuf::from(format!("/proc/{pid}/cgroup"));
    let text = fs::read_to_string(&path).map_err(|source| match source.kind() {
        io::ErrorKind::NotFound => InspectError::TargetExited { pid },
        _ => InspectError::Io {
            path: path.clone(),
            source,
        },
    })?;
    let Some((version, relative)) = cpu_cgroup_path(&text) else {
        return Ok(None);
    };
    let root = match version {
        CgroupVersion::V2 => PathBuf::from("/sys/fs/cgroup"),
        CgroupVersion::V1 => ["/sys/fs/cgroup/cpu,cpuacct", "/sys/fs/cgroup/cpu"]
            .into_iter()
            .map(PathBuf::from)
            .find(|root| root.is_dir())
            .unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup/cpu")),
    };
    let directory = root.join(relative.trim_start_matches('/'));
    if !directory.join("cpu.stat").is_file() {
        return Ok(None);
    }
    Ok(Some(CpuCgroup {
        version,
        path: relative,
        directory,
    }))
}

/// Pick the v2 unified entry, or the v1 entry carrying the `cpu` controller.
fn cpu_cgroup_path(text: &str) -> Option<(CgroupVersion, String)> {
    let mut unified = None;
    for line in text.lines() {
        let mut fields = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if controllers.split(',').any(|controller| controller == "cpu") {
            return Some((CgroupVersion::V1, path.to_owned()));
        }
        if controllers.is_empty() {
            unified = Some((CgroupVersion::V2, path.to_owned()));
        }
    }
    unified
}

impl CpuCgroup {
    /// Read cumulative throttling counters.
    ///
    /// # Errors
    ///
    /// Returns [`InspectError`] when `cpu.stat` is unreadable.
    pub fn counters(&self) -> Result<CpuCounters, InspectError> {
        let text = read(&self.directory.join("cpu.stat"))?;
        Ok(parse_cpu_stat(&text, self.version))
    }

    /// Read the configured quota as a CPU count, `None` when unlimited.
    ///
    /// # Errors
    ///
    /// Returns [`InspectError`] when present limit files are unreadable or
    /// malformed.
    pub fn quota_cpus(&self) -> Result<Option<f64>, InspectError> {
        match self.version {
            CgroupVersion::V2 => {
                let path = self.directory.join("cpu.max");
                if !path.is_file() {
                    return Ok(None);
                }
                parse_cpu_max(&read(&path)?)
                    .map(CpuLimit::cpus)
                    .ok_or_else(|| malformed(&path))
            }
            CgroupVersion::V1 => {
                let quota_path = self.directory.join("cpu.cfs_quota_us");
                let period_path = self.directory.join("cpu.cfs_period_us");
                if !quota_path.is_file() || !period_path.is_file() {
                    return Ok(None);
                }
                let quota = read(&quota_path)?;
                let period = read(&period_path)?;
                parse_cfs_quota(&quota, &period)
                    .map(CpuLimit::cpus)
                    .ok_or_else(|| malformed(&quota_path))
            }
        }
    }
}

/// Throttling between two counter snapshots.
#[must_use]
pub fn throttling(
    cgroup: &CpuCgroup,
    quota_cpus: Option<f64>,
    before: CpuCounters,
    after: CpuCounters,
) -> CgroupCpuThrottling {
    CgroupCpuThrottling {
        version: cgroup.version,
        cgroup_path: cgroup.path.clone(),
        quota_cpus,
        periods: after.periods.saturating_sub(before.periods),
        throttled_periods: after
            .throttled_periods
            .saturating_sub(before.throttled_periods),
        throttled_ns: after.throttled_ns.saturating_sub(before.throttled_ns),
    }
}

fn read(path: &Path) -> Result<String, InspectError> {
    fs::read_to_string(path).map_err(|source| InspectError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn malformed(path: &Path) -> InspectError {
    InspectError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidData, "malformed CPU limit"),
    }
}

/// Missing keys read as zero: v2 omits bandwidth keys without the controller.
fn parse_cpu_stat(text: &str, version: CgroupVersion) -> CpuCounters {
    let mut counters = CpuCounters::default();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(key), Some(value)) = (
            fields.next(),
            fields.next().and_then(|v| v.parse::<u64>().ok()),
        ) else {
            continue;
        };
        match (version, key) {
            (_, "nr_periods") => counters.periods = value,
            (_, "nr_throttled") => counters.throttled_periods = value,
            (CgroupVersion::V2, "throttled_usec") => {
                counters.throttled_ns = value.saturating_mul(1_000);
            }
            (CgroupVersion::V1, "throttled_time") => counters.throttled_ns = value,
            _ => {}
        }
    }
    counters
}

#[allow(clippy::cast_precision_loss)]
fn parse_cpu_max(text: &str) -> Option<CpuLimit> {
    let mut fields = text.split_whitespace();
    let quota = fields.next()?;
    let period = fields
        .next()?
        .parse::<u64>()
        .ok()
        .filter(|period| *period > 0)?;
    if quota == "max" {
        return Some(CpuLimit::Unlimited);
    }
    Some(CpuLimit::Cpus(
        quota.parse::<u64>().ok()? as f64 / period as f64,
    ))
}

#[allow(clippy::cast_precision_loss)]
fn parse_cfs_quota(quota: &str, period: &str) -> Option<CpuLimit> {
    let quota = quota.trim().parse::<i64>().ok()?;
    let period = period
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|period| *period > 0)?;
    if quota < 0 {
        return Some(CpuLimit::Unlimited);
    }
    Some(CpuLimit::Cpus(quota as f64 / period as f64))
}

#[cfg(test)]
mod tests {
    use xprobe_protocol::CgroupVersion;

    use super::{
        CpuCounters, CpuLimit, cpu_cgroup_path, parse_cfs_quota, parse_cpu_max, parse_cpu_stat,
    };

    #[test]
    fn selects_v2_and_v1_cpu_paths() {
        assert_eq!(
            cpu_cgroup_path("0::/kubepods/pod1/abc\n"),
            Some((CgroupVersion::V2, "/kubepods/pod1/abc".to_owned()))
        );
        assert_eq!(
            cpu_cgroup_path("12:memory:/a\n4:cpu,cpuacct:/docker/x\n0::/\n"),
            Some((CgroupVersion::V1, "/docker/x".to_owned()))
        );
        assert_eq!(cpu_cgroup_path("5:memory:/a\n"), None);
    }

    #[test]
    fn parses_counters_and_limits() {
        let v2 = "usage_usec 1\nnr_periods 10\nnr_throttled 4\nthrottled_usec 2500\n";
        assert_eq!(
            parse_cpu_stat(v2, CgroupVersion::V2),
            CpuCounters {
                periods: 10,
                throttled_periods: 4,
                throttled_ns: 2_500_000
            }
        );
        let v1 = "nr_periods 3\nnr_throttled 1\nthrottled_time 777\n";
        assert_eq!(parse_cpu_stat(v1, CgroupVersion::V1).throttled_ns, 777);
        assert_eq!(
            parse_cpu_stat("usage_usec 5\n", CgroupVersion::V2),
            CpuCounters::default()
        );
        assert_eq!(parse_cpu_max("50000 100000\n"), Some(CpuLimit::Cpus(0.5)));
        assert_eq!(parse_cpu_max("max 100000\n"), Some(CpuLimit::Unlimited));
        assert_eq!(parse_cpu_max("garbage"), None);
        assert_eq!(
            parse_cfs_quota("-1\n", "100000\n"),
            Some(CpuLimit::Unlimited)
        );
        assert_eq!(
            parse_cfs_quota("200000\n", "100000\n"),
            Some(CpuLimit::Cpus(2.0))
        );
    }
}
