use std::{
    error::Error,
    fmt, fs,
    io::{IoSlice, IoSliceMut},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    sys::{
        ptrace,
        signal::Signal,
        uio::{RemoteIoVec, process_vm_readv, process_vm_writev},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use xprobe_protocol::{ErrorCode, ProcessReport};

use crate::{
    inspect::{self, InspectError},
    resolve::{self, ResolveError},
};

const RTLD_NOW: u64 = 2;
const RTLD_LOCAL: u64 = 0;
const AGENT_START_SYMBOL: &str = "xprobe_cupti_agent_start";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionResult {
    pub socket_path: PathBuf,
    pub injected: bool,
}

#[derive(Debug)]
pub enum InjectError {
    Inspect(InspectError),
    Resolve(ResolveError),
    UnsupportedPlatform,
    DifferentMountNamespace,
    InvalidAgent(PathBuf),
    MissingRuntimeSymbol(&'static str),
    Operation {
        operation: &'static str,
        source: Errno,
    },
    UnexpectedStop(WaitStatus),
    TimedOut,
    RemoteCallTrap {
        instruction_pointer: u64,
    },
    ShortMemoryTransfer {
        expected: usize,
        actual: usize,
    },
    RemoteCallFailed {
        function: &'static str,
        result: u64,
    },
}

impl InjectError {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Inspect(error) => error.code(),
            Self::Resolve(error) => error.code(),
            Self::DifferentMountNamespace
            | Self::Operation { .. }
            | Self::UnexpectedStop(_)
            | Self::TimedOut => ErrorCode::PermissionDenied,
            Self::UnsupportedPlatform => ErrorCode::UnsupportedCudaVersion,
            Self::InvalidAgent(_)
            | Self::MissingRuntimeSymbol(_)
            | Self::ShortMemoryTransfer { .. }
            | Self::RemoteCallFailed { .. }
            | Self::RemoteCallTrap { .. } => ErrorCode::CuptiNotAvailable,
        }
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        !matches!(self, Self::ShortMemoryTransfer { .. })
    }
}

impl fmt::Display for InjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => error.fmt(formatter),
            Self::Resolve(error) => error.fmt(formatter),
            Self::UnsupportedPlatform => {
                formatter.write_str("online injection requires Linux x86_64")
            }
            Self::DifferentMountNamespace => formatter.write_str(
                "target uses a different mount namespace; the agent path is not safely addressable",
            ),
            Self::InvalidAgent(path) => {
                write!(
                    formatter,
                    "CUPTI agent is not a regular file: {}",
                    path.display()
                )
            }
            Self::MissingRuntimeSymbol(symbol) => {
                write!(formatter, "target runtime symbol {symbol:?} was not found")
            }
            Self::Operation { operation, source } => {
                write!(formatter, "{operation} failed: {source}")
            }
            Self::UnexpectedStop(status) => {
                write!(
                    formatter,
                    "target stopped unexpectedly during injection: {status:?}"
                )
            }
            Self::TimedOut => formatter.write_str("remote function call timed out"),
            Self::RemoteCallTrap {
                instruction_pointer,
            } => write!(
                formatter,
                "remote function trapped at {instruction_pointer:#x} before returning"
            ),
            Self::ShortMemoryTransfer { expected, actual } => write!(
                formatter,
                "remote memory transfer copied {actual} bytes, expected {expected}"
            ),
            Self::RemoteCallFailed { function, result } => {
                write!(formatter, "remote {function} returned {result:#x}")
            }
        }
    }
}

impl Error for InjectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inspect(error) => Some(error),
            Self::Resolve(error) => Some(error),
            Self::UnsupportedPlatform
            | Self::DifferentMountNamespace
            | Self::InvalidAgent(_)
            | Self::MissingRuntimeSymbol(_)
            | Self::Operation { .. }
            | Self::UnexpectedStop(_)
            | Self::TimedOut
            | Self::RemoteCallTrap { .. }
            | Self::ShortMemoryTransfer { .. }
            | Self::RemoteCallFailed { .. } => None,
        }
    }
}

impl From<InspectError> for InjectError {
    fn from(error: InspectError) -> Self {
        Self::Inspect(error)
    }
}

/// Load or reactivate the CUPTI agent in a running target process.
///
/// The target is stopped only while its own dynamic linker and agent entry
/// point execute. The shared object remains mapped after collection stops.
///
/// # Errors
///
/// Returns [`InjectError`] when process identity changes, ptrace is denied,
/// symbols cannot be resolved, or the remote agent fails to start.
pub fn activate(
    report: &ProcessReport,
    agent_path: &Path,
    socket_path: &Path,
    timeout: Duration,
) -> Result<InjectionResult, InjectError> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(InjectError::UnsupportedPlatform);
    }
    inspect::verify_target(&report.target)?;
    verify_mount_namespace(report)?;
    let malloc = resolve_runtime_symbol(report, "malloc")?;
    let free = resolve_runtime_symbol(report, "free")?;
    let mut remote = RemoteProcess::attach(report.target.pid, timeout)?;
    let socket_address =
        remote.copy_c_string(malloc, socket_path.as_os_str().as_encoded_bytes())?;
    let mut allocations = vec![socket_address];

    let (start_address, injected) = if report.cuda.xprobe_cupti_loaded {
        (resolve_agent_symbol(report, AGENT_START_SYMBOL)?, false)
    } else {
        let agent_path = fs::canonicalize(agent_path)
            .map_err(|_| InjectError::InvalidAgent(agent_path.to_owned()))?;
        if !agent_path.is_file() {
            return Err(InjectError::InvalidAgent(agent_path));
        }
        let dlopen = resolve_runtime_symbol(report, "dlopen")?;
        let dlsym = resolve_runtime_symbol(report, "dlsym")?;
        let path_address =
            remote.copy_c_string(malloc, agent_path.as_os_str().as_encoded_bytes())?;
        allocations.push(path_address);
        let handle = remote.call(dlopen, &[path_address, RTLD_NOW | RTLD_LOCAL])?;
        if handle == 0 {
            return Err(InjectError::RemoteCallFailed {
                function: "dlopen",
                result: handle,
            });
        }
        let symbol_address = remote.copy_c_string(malloc, AGENT_START_SYMBOL.as_bytes())?;
        allocations.push(symbol_address);
        let start = remote.call(dlsym, &[handle, symbol_address])?;
        if start == 0 {
            return Err(InjectError::RemoteCallFailed {
                function: "dlsym",
                result: start,
            });
        }
        (start, true)
    };

    let status = remote.call(start_address, &[socket_address])?;
    for address in allocations {
        let _ = remote.call(free, &[address])?;
    }
    remote.detach()?;
    inspect::verify_target(&report.target)?;
    if status != 0 {
        return Err(InjectError::RemoteCallFailed {
            function: AGENT_START_SYMBOL,
            result: status,
        });
    }
    Ok(InjectionResult {
        socket_path: socket_path.to_owned(),
        injected,
    })
}

fn verify_mount_namespace(report: &ProcessReport) -> Result<(), InjectError> {
    let local = fs::read_link("/proc/self/ns/mnt").map_err(|source| InjectError::Operation {
        operation: "read local mount namespace",
        source: Errno::from_raw(source.raw_os_error().unwrap_or(Errno::EIO as i32)),
    })?;
    if local.to_string_lossy() != report.mount_namespace {
        return Err(InjectError::DifferentMountNamespace);
    }
    Ok(())
}

fn resolve_runtime_symbol(
    report: &ProcessReport,
    symbol: &'static str,
) -> Result<u64, InjectError> {
    for path in &report.loaded_libraries {
        let name = Path::new(path)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if !name.starts_with("libc.so") && !name.starts_with("libdl.so") {
            continue;
        }
        if let Ok(probe) = resolve::run(report, &format!("uprobe:{path}:{symbol}:entry")) {
            return Ok(probe.runtime_address);
        }
    }
    Err(InjectError::MissingRuntimeSymbol(symbol))
}

fn resolve_agent_symbol(report: &ProcessReport, symbol: &'static str) -> Result<u64, InjectError> {
    let path = report
        .loaded_libraries
        .iter()
        .find(|path| {
            Path::new(path)
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.starts_with("libxprobe-cupti.so"))
        })
        .ok_or(InjectError::MissingRuntimeSymbol(symbol))?;
    resolve::run(report, &format!("uprobe:{path}:{symbol}:entry"))
        .map(|probe| probe.runtime_address)
        .map_err(InjectError::Resolve)
}

struct RemoteProcess {
    pid: Pid,
    timeout: Duration,
    attached: bool,
}

impl RemoteProcess {
    fn attach(pid: u32, timeout: Duration) -> Result<Self, InjectError> {
        let raw_pid = i32::try_from(pid).map_err(|_| InjectError::UnsupportedPlatform)?;
        let pid = Pid::from_raw(raw_pid);
        ptrace::seize(pid, ptrace::Options::empty()).map_err(|source| InjectError::Operation {
            operation: "ptrace seize",
            source,
        })?;
        let mut process = Self {
            pid,
            timeout,
            attached: true,
        };
        ptrace::interrupt(pid).map_err(|source| InjectError::Operation {
            operation: "ptrace interrupt",
            source,
        })?;
        process.wait_for_stop()?;
        Ok(process)
    }

    fn copy_c_string(&mut self, malloc: u64, bytes: &[u8]) -> Result<u64, InjectError> {
        let length = bytes
            .len()
            .checked_add(1)
            .ok_or(InjectError::ShortMemoryTransfer {
                expected: usize::MAX,
                actual: bytes.len(),
            })?;
        let address = self.call(malloc, &[length as u64])?;
        if address == 0 {
            return Err(InjectError::RemoteCallFailed {
                function: "malloc",
                result: 0,
            });
        }
        let mut terminated = Vec::with_capacity(length);
        terminated.extend_from_slice(bytes);
        terminated.push(0);
        self.write_memory(address, &terminated)?;
        Ok(address)
    }

    fn call(&mut self, function: u64, arguments: &[u64]) -> Result<u64, InjectError> {
        if arguments.len() > 6 {
            return Err(InjectError::RemoteCallFailed {
                function: "function with more than six arguments",
                result: arguments.len() as u64,
            });
        }
        let saved = ptrace::getregs(self.pid).map_err(|source| InjectError::Operation {
            operation: "read target registers",
            source,
        })?;
        let stack_pointer = ((saved.rsp - 256) & !0xf) - 8;
        let mut saved_stack = [0_u8; 8];
        self.read_memory(stack_pointer, &mut saved_stack)?;
        self.write_memory(stack_pointer, &[0_u8; 8])?;

        let mut registers = saved;
        registers.rip = function;
        registers.rsp = stack_pointer;
        registers.rax = 0;
        let mut padded = [0_u64; 6];
        padded[..arguments.len()].copy_from_slice(arguments);
        registers.rdi = padded[0];
        registers.rsi = padded[1];
        registers.rdx = padded[2];
        registers.rcx = padded[3];
        registers.r8 = padded[4];
        registers.r9 = padded[5];
        if let Err(source) = ptrace::setregs(self.pid, registers) {
            self.restore_call_state(stack_pointer, saved_stack, saved)?;
            return Err(InjectError::Operation {
                operation: "write target registers",
                source,
            });
        }
        if let Err(source) = ptrace::cont(self.pid, None) {
            self.restore_call_state(stack_pointer, saved_stack, saved)?;
            return Err(InjectError::Operation {
                operation: "continue target for remote call",
                source,
            });
        }

        let execution = self.wait_for_call().and_then(|()| {
            let result = ptrace::getregs(self.pid).map_err(|source| InjectError::Operation {
                operation: "read remote call result",
                source,
            })?;
            if result.rip != 0 {
                return Err(InjectError::RemoteCallTrap {
                    instruction_pointer: result.rip,
                });
            }
            Ok(result.rax)
        });
        if matches!(&execution, Err(InjectError::TimedOut)) {
            self.ensure_stopped()?;
        }
        self.restore_call_state(stack_pointer, saved_stack, saved)?;
        execution
    }

    fn restore_call_state(
        &self,
        stack_pointer: u64,
        saved_stack: [u8; 8],
        saved_registers: nix::libc::user_regs_struct,
    ) -> Result<(), InjectError> {
        self.write_memory(stack_pointer, &saved_stack)?;
        ptrace::setregs(self.pid, saved_registers).map_err(|source| InjectError::Operation {
            operation: "restore target registers",
            source,
        })
    }

    fn read_memory(&self, address: u64, buffer: &mut [u8]) -> Result<(), InjectError> {
        let expected = buffer.len();
        let address = usize::try_from(address).map_err(|_| InjectError::UnsupportedPlatform)?;
        let mut local = [IoSliceMut::new(buffer)];
        let remote = [RemoteIoVec {
            base: address,
            len: expected,
        }];
        let actual = process_vm_readv(self.pid, &mut local, &remote).map_err(|source| {
            InjectError::Operation {
                operation: "read target memory",
                source,
            }
        })?;
        if actual != expected {
            return Err(InjectError::ShortMemoryTransfer { expected, actual });
        }
        Ok(())
    }

    fn write_memory(&self, address: u64, buffer: &[u8]) -> Result<(), InjectError> {
        let expected = buffer.len();
        let address = usize::try_from(address).map_err(|_| InjectError::UnsupportedPlatform)?;
        let local = [IoSlice::new(buffer)];
        let remote = [RemoteIoVec {
            base: address,
            len: expected,
        }];
        let actual = process_vm_writev(self.pid, &local, &remote).map_err(|source| {
            InjectError::Operation {
                operation: "write target memory",
                source,
            }
        })?;
        if actual != expected {
            return Err(InjectError::ShortMemoryTransfer { expected, actual });
        }
        Ok(())
    }

    fn wait_for_stop(&mut self) -> Result<(), InjectError> {
        match self.wait_status()? {
            WaitStatus::Stopped(_, _) | WaitStatus::PtraceEvent(_, _, _) => Ok(()),
            status => Err(InjectError::UnexpectedStop(status)),
        }
    }

    fn wait_for_call(&mut self) -> Result<(), InjectError> {
        match self.wait_status()? {
            WaitStatus::Stopped(_, Signal::SIGSEGV) => Ok(()),
            status => Err(InjectError::UnexpectedStop(status)),
        }
    }

    fn wait_status(&mut self) -> Result<WaitStatus, InjectError> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(InjectError::TimedOut)?;
        loop {
            let status = waitpid(self.pid, Some(WaitPidFlag::WNOHANG)).map_err(|source| {
                InjectError::Operation {
                    operation: "wait for target",
                    source,
                }
            })?;
            if status != WaitStatus::StillAlive {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(InjectError::TimedOut);
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn ensure_stopped(&mut self) -> Result<(), InjectError> {
        ptrace::interrupt(self.pid).map_err(|source| InjectError::Operation {
            operation: "interrupt timed out target",
            source,
        })?;
        self.wait_for_stop()
    }

    fn detach(&mut self) -> Result<(), InjectError> {
        ptrace::detach(self.pid, None).map_err(|source| InjectError::Operation {
            operation: "ptrace detach",
            source,
        })?;
        self.attached = false;
        Ok(())
    }
}

impl Drop for RemoteProcess {
    fn drop(&mut self) {
        if self.attached {
            let _ = ptrace::detach(self.pid, None);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{process::Command, thread, time::Duration};

    use super::{InjectError, RemoteProcess, resolve_runtime_symbol};
    use crate::inspect;

    #[test]
    fn remote_call_restores_a_child_process() {
        let mut child = Command::new("sleep").arg("10").spawn().unwrap();
        thread::sleep(Duration::from_millis(20));
        let report = inspect::run(child.id()).unwrap();
        let getpid = resolve_runtime_symbol(&report, "getpid").unwrap();
        let mut remote = RemoteProcess::attach(child.id(), Duration::from_secs(2)).unwrap();
        assert_eq!(remote.call(getpid, &[]).unwrap(), u64::from(child.id()));
        assert!(matches!(
            remote.call(1, &[]),
            Err(InjectError::RemoteCallTrap {
                instruction_pointer: 1
            })
        ));
        assert_eq!(remote.call(getpid, &[]).unwrap(), u64::from(child.id()));
        remote.detach().unwrap();
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
