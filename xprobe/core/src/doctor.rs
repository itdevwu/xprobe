use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use xprobe_protocol::{
    Capabilities, CapabilityReport, CheckResult, CheckStatus, Environment, SchemaVersion,
    SystemChecks, Warning,
};

use crate::cupti_compat::{self, CuptiCompatibilityError};

const CAP_SYS_ADMIN: u32 = 21;
const CAP_SYS_PTRACE: u32 = 19;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

#[derive(Debug)]
pub enum DoctorError {
    Io { path: PathBuf, source: io::Error },
    InvalidValue { path: PathBuf, value: String },
    Command { program: String, detail: String },
    Cupti(CuptiCompatibilityError),
}

impl fmt::Display for DoctorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::InvalidValue { path, value } => {
                write!(formatter, "invalid value in {}: {value:?}", path.display())
            }
            Self::Command { program, detail } => write!(formatter, "{program} failed: {detail}"),
            Self::Cupti(error) => error.fmt(formatter),
        }
    }
}

impl Error for DoctorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Cupti(error) => Some(error),
            Self::InvalidValue { .. } | Self::Command { .. } => None,
        }
    }
}

/// Inspect the local kernel, tracing permissions, and NVIDIA tooling.
///
/// # Errors
///
/// Returns [`DoctorError`] when a required procfs value cannot be read or when
/// a kernel setting contains an invalid value.
#[must_use = "doctor failures must be reported to the caller"]
pub fn run() -> Result<CapabilityReport, DoctorError> {
    let proc_status = read_required("/proc/self/status")?;
    let effective_uid = parse_status_u32(&proc_status, "Uid:", "/proc/self/status")?;
    let effective_capabilities = parse_status_hex(&proc_status, "CapEff:", "/proc/self/status")?;
    let kernel_release = read_required("/proc/sys/kernel/osrelease")?;
    let pid_namespace = fs::read_link("/proc/self/ns/pid")
        .map_err(|source| io_error("/proc/self/ns/pid", source))?
        .to_string_lossy()
        .into_owned();

    let btf = path_check("/sys/kernel/btf/vmlinux")?;
    let perf_event_paranoid = integer_setting_check("/proc/sys/kernel/perf_event_paranoid", 1)?;
    let ptrace_scope = integer_setting_check("/proc/sys/kernel/yama/ptrace_scope", 0)?;
    let kernel_lockdown = lockdown_check()?;
    let ebpf_permissions = ebpf_permission_check(effective_uid, effective_capabilities);
    let nvidia_driver = nvidia_driver_check()?;
    let cuda_driver = cuda_driver_check(&nvidia_driver)?;
    let cuda_toolkit = cuda_toolkit_check()?;
    let cupti = cupti_check()?;

    let host_probe_available = ebpf_permissions.status == CheckStatus::Available
        && kernel_lockdown.status != CheckStatus::Restricted;
    let cuda_available = nvidia_driver.status == CheckStatus::Available
        && cuda_driver.status == CheckStatus::Available
        && cupti.status == CheckStatus::Available;
    let runtime_injection = cfg!(all(target_os = "linux", target_arch = "x86_64"))
        && (effective_uid == 0
            || has_capability(effective_capabilities, CAP_SYS_PTRACE)
            || ptrace_scope.status == CheckStatus::Available);

    let checks = SystemChecks {
        btf,
        ebpf_permissions,
        kernel_lockdown,
        perf_event_paranoid,
        ptrace_scope,
        nvidia_driver,
        cuda_driver,
        cuda_toolkit,
        cupti,
    };

    Ok(CapabilityReport {
        schema_version: SchemaVersion::current(),
        ok: true,
        capabilities: Capabilities {
            uprobe: host_probe_available,
            uretprobe: host_probe_available,
            tracepoint: host_probe_available,
            cuda_callback: cuda_available,
            cuda_activity: cuda_available,
            runtime_injection,
        },
        environment: Environment {
            operating_system: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            kernel_release,
            effective_uid,
            container: container_kind()?,
            pid_namespace,
        },
        warnings: warnings_for(&checks),
        checks,
    })
}

fn warning(code: &str, message: &str) -> Warning {
    Warning {
        code: code.to_owned(),
        message: message.to_owned(),
        details: BTreeMap::new(),
    }
}

fn warnings_for(checks: &SystemChecks) -> Vec<Warning> {
    let mut warnings = Vec::new();
    if checks.ebpf_permissions.status != CheckStatus::Available {
        warnings.push(warning(
            "BPF_PERMISSION_MISSING",
            "The current process cannot attach eBPF probes.",
        ));
    }
    if checks.nvidia_driver.status != CheckStatus::Available {
        warnings.push(warning(
            "NVIDIA_DRIVER_UNAVAILABLE",
            "The NVIDIA driver is unavailable from this execution environment.",
        ));
    }
    if checks.cupti.status != CheckStatus::Available {
        warnings.push(warning(
            "CUPTI_NOT_AVAILABLE",
            "CUPTI was not found in the dynamic linker cache or CUDA installation.",
        ));
    }
    if checks.kernel_lockdown.status == CheckStatus::Restricted {
        warnings.push(warning(
            "KERNEL_LOCKDOWN",
            "Kernel lockdown may prevent probe attachment.",
        ));
    }
    warnings
}

fn read_required(path: impl AsRef<Path>) -> Result<String, DoctorError> {
    let path = path.as_ref();
    fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .map_err(|source| io_error(path, source))
}

fn read_optional(path: impl AsRef<Path>) -> Result<Option<String>, DoctorError> {
    let path = path.as_ref();
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value.trim().to_owned())),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error(path, source)),
    }
}

fn io_error(path: impl AsRef<Path>, source: io::Error) -> DoctorError {
    DoctorError::Io {
        path: path.as_ref().to_owned(),
        source,
    }
}

fn parse_status_u32(status: &str, field: &str, path: &str) -> Result<u32, DoctorError> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .and_then(|value| value.split_whitespace().next())
        .ok_or_else(|| invalid_value(path, field))?;
    value.parse().map_err(|_| invalid_value(path, value))
}

fn parse_status_hex(status: &str, field: &str, path: &str) -> Result<u64, DoctorError> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .map(str::trim)
        .ok_or_else(|| invalid_value(path, field))?;
    u64::from_str_radix(value, 16).map_err(|_| invalid_value(path, value))
}

fn invalid_value(path: impl AsRef<Path>, value: &str) -> DoctorError {
    DoctorError::InvalidValue {
        path: path.as_ref().to_owned(),
        value: value.to_owned(),
    }
}

fn has_capability(capabilities: u64, capability: u32) -> bool {
    capabilities & (1_u64 << capability) != 0
}

fn ebpf_permission_check(effective_uid: u32, capabilities: u64) -> CheckResult {
    let allowed = effective_uid == 0
        || (has_capability(capabilities, CAP_BPF) && has_capability(capabilities, CAP_PERFMON))
        || has_capability(capabilities, CAP_SYS_ADMIN);
    if allowed {
        check(CheckStatus::Available, "effective BPF and perf privileges")
    } else {
        check(
            CheckStatus::Restricted,
            "requires root, CAP_BPF + CAP_PERFMON, or CAP_SYS_ADMIN",
        )
    }
}

fn path_check(path: &str) -> Result<CheckResult, DoctorError> {
    if path_exists(path)? {
        Ok(check(CheckStatus::Available, path))
    } else {
        Ok(check(CheckStatus::Unavailable, format!("{path} not found")))
    }
}

fn integer_setting_check(path: &str, maximum: i32) -> Result<CheckResult, DoctorError> {
    let Some(raw) = read_optional(path)? else {
        return Ok(check(CheckStatus::Unknown, format!("{path} not found")));
    };
    let value = raw.parse::<i32>().map_err(|_| invalid_value(path, &raw))?;
    let status = if value <= maximum {
        CheckStatus::Available
    } else {
        CheckStatus::Restricted
    };
    Ok(check(status, value.to_string()))
}

fn lockdown_check() -> Result<CheckResult, DoctorError> {
    let path = "/sys/kernel/security/lockdown";
    let Some(value) = read_optional(path)? else {
        return Ok(check(CheckStatus::Unknown, format!("{path} not found")));
    };
    let status = if value.contains("[none]") {
        CheckStatus::Available
    } else {
        CheckStatus::Restricted
    };
    Ok(check(status, value))
}

fn nvidia_driver_check() -> Result<CheckResult, DoctorError> {
    if let Some(version) = read_optional("/proc/driver/nvidia/version")? {
        return Ok(check(
            CheckStatus::Available,
            version.lines().next().unwrap_or_default(),
        ));
    }

    let Some(output) = optional_command(
        "nvidia-smi",
        &["--query-gpu=name,driver_version", "--format=csv,noheader"],
    )?
    else {
        return Ok(check(CheckStatus::Unavailable, "nvidia-smi not found"));
    };
    if output.status.success() {
        return Ok(check(
            CheckStatus::Available,
            String::from_utf8_lossy(&output.stdout).trim(),
        ));
    }

    let status = if path_exists("/dev/nvidiactl")? || path_exists("/usr/lib/wsl/lib/libcuda.so.1")?
    {
        CheckStatus::Restricted
    } else {
        CheckStatus::Unavailable
    };
    Ok(check(status, command_error_detail(&output)))
}

fn cuda_driver_check(nvidia_driver: &CheckResult) -> Result<CheckResult, DoctorError> {
    let library_present =
        linker_cache_contains("libcuda.so")? || path_exists("/usr/lib/wsl/lib/libcuda.so.1")?;
    if !library_present {
        return Ok(check(CheckStatus::Unavailable, "libcuda.so not found"));
    }
    if nvidia_driver.status == CheckStatus::Available {
        Ok(check(CheckStatus::Available, "libcuda.so found"))
    } else {
        Ok(check(
            CheckStatus::Restricted,
            "libcuda.so found, but the NVIDIA runtime is unavailable",
        ))
    }
}

fn cuda_toolkit_check() -> Result<CheckResult, DoctorError> {
    if let Some(output) = optional_command("nvcc", &["--version"])? {
        if output.status.success() {
            let detail = String::from_utf8_lossy(&output.stdout)
                .lines()
                .last()
                .unwrap_or("nvcc available")
                .to_owned();
            return Ok(check(CheckStatus::Available, detail));
        }
        return Ok(check(
            CheckStatus::Unavailable,
            command_error_detail(&output),
        ));
    }

    if path_exists("/usr/local/cuda/version.json")? {
        Ok(check(
            CheckStatus::Available,
            "/usr/local/cuda/version.json",
        ))
    } else {
        Ok(check(CheckStatus::Unavailable, "nvcc not found"))
    }
}

fn cupti_check() -> Result<CheckResult, DoctorError> {
    let libraries = cupti_compat::installed_libraries().map_err(DoctorError::Cupti)?;
    if libraries.is_empty() {
        return Ok(check(
            CheckStatus::Unavailable,
            "libcupti.so.12 and libcupti.so.13 not found",
        ));
    }
    let detail = libraries
        .iter()
        .map(|(major, path)| format!("CUDA {major}: {}", path.display()))
        .collect::<Vec<_>>()
        .join("; ");
    Ok(check(CheckStatus::Available, &detail))
}

fn linker_cache_contains(library: &str) -> Result<bool, DoctorError> {
    let Some(output) = optional_command("ldconfig", &["-p"])? else {
        return Ok(false);
    };
    if !output.status.success() {
        return Err(DoctorError::Command {
            program: "ldconfig".to_owned(),
            detail: command_error_detail(&output),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).contains(library))
}

fn optional_command(program: &str, arguments: &[&str]) -> Result<Option<Output>, DoctorError> {
    match Command::new(program).args(arguments).output() {
        Ok(output) => Ok(Some(output)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error(program, source)),
    }
}

fn command_error_detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if !stderr.is_empty() {
        return stderr;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !stdout.is_empty() {
        return stdout;
    }
    format!("command exited with {}", output.status)
}

fn container_kind() -> Result<Option<String>, DoctorError> {
    if path_exists("/.dockerenv")? {
        return Ok(Some("docker".to_owned()));
    }
    let cgroup = read_required("/proc/1/cgroup")?;
    for kind in ["kubepods", "containerd", "docker", "lxc"] {
        if cgroup.contains(kind) {
            return Ok(Some(kind.to_owned()));
        }
    }
    Ok(None)
}

fn path_exists(path: impl AsRef<Path>) -> Result<bool, DoctorError> {
    let path = path.as_ref();
    path.try_exists().map_err(|source| io_error(path, source))
}

fn check(status: CheckStatus, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        status,
        detail: Some(detail.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{has_capability, parse_status_hex, parse_status_u32};

    #[test]
    fn parses_proc_status_fields() {
        let status = "Name:\txprobe\nUid:\t1000\t1001\t1002\t1003\nCapEff:\t000000c000000000";
        assert_eq!(parse_status_u32(status, "Uid:", "fixture").unwrap(), 1000);
        assert_eq!(
            parse_status_hex(status, "CapEff:", "fixture").unwrap(),
            0x0000_00c0_0000_0000
        );
    }

    #[test]
    fn detects_linux_capability_bits() {
        assert!(has_capability(1_u64 << 39, 39));
        assert!(!has_capability(1_u64 << 38, 39));
    }
}
