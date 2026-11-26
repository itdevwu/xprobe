//! External, read-only CPython stack sampling.
//!
//! The sampler reads interpreter state with `process_vm_readv` and never stops
//! or injects into the target. Without stopping, a stack can change while it
//! is read; every frame's code object is type-checked and the innermost frame
//! is read again afterwards, so a torn read is discarded and counted rather
//! than reported. The GIL holder is sampled at a high rate, because only it
//! runs Python code; every thread is sampled at a lower rate.

use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::IoSliceMut;
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::time::{ClockId, clock_gettime};
use nix::unistd::Pid;
use xprobe_core::python_layout::{FramePath, GilPath, PythonLayout, PythonRuntime};
pub use xprobe_core::python_sampling::{
    Code, NativeLeaf, PythonCapture, PythonSample, SamplerCounters, Stack, TidSource,
    parse_task_syscall,
};

/// Longest string read from an interpreter object, in code points.
const MAX_STRING_CHARS: u64 = 4096;
/// Bound on threads walked per interpreter.
const MAX_THREADS: usize = 4096;
/// Bytes of `struct pthread` searched for its TID (CPython before 3.11).
const PTHREAD_SEARCH_BYTES: usize = 2048;
/// Bytes below the innermost frame read at once (3.11+): frames of one
/// thread sit together on its data stack, so most of a stack is one read.
const FRAME_WINDOW_BYTES: u64 = 16 * 1024;
/// Segments per `process_vm_readv` call (`IOV_MAX`).
const MAX_SEGMENTS: usize = 1024;

/// Why a remote read failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// The address is not mapped, or the read was partial.
    Fault,
    /// ptrace access to the target is denied.
    Permission,
    /// The target exited.
    Gone,
    /// Any other `process_vm_readv` failure, by errno.
    Other(i32),
}

/// Read-only access to a target's memory.
pub trait RemoteMemory {
    /// Fill `out` from `address`.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] when the range cannot be read completely.
    fn read(&self, address: u64, out: &mut [u8]) -> Result<(), ReadError>;

    /// Fill several buffers, each from its own address, in as few system
    /// calls as possible.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] when any range cannot be read completely.
    fn read_many(&self, reads: &mut [(u64, &mut [u8])]) -> Result<(), ReadError> {
        for (address, out) in reads {
            self.read(*address, out)?;
        }
        Ok(())
    }
}

/// A live process read through `process_vm_readv`.
pub struct ProcessMemory {
    pid: Pid,
}

impl ProcessMemory {
    #[must_use]
    pub fn new(pid: u32) -> Self {
        Self {
            pid: Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX)),
        }
    }
}

impl RemoteMemory for ProcessMemory {
    fn read(&self, address: u64, out: &mut [u8]) -> Result<(), ReadError> {
        let base = usize::try_from(address).map_err(|_| ReadError::Fault)?;
        let remote = [RemoteIoVec {
            base,
            len: out.len(),
        }];
        let expected = out.len();
        let mut local = [IoSliceMut::new(out)];
        transfer(process_vm_readv(self.pid, &mut local, &remote), expected)
    }

    fn read_many(&self, reads: &mut [(u64, &mut [u8])]) -> Result<(), ReadError> {
        for chunk in reads.chunks_mut(MAX_SEGMENTS) {
            let remote = chunk
                .iter()
                .map(|(address, out)| {
                    Ok(RemoteIoVec {
                        base: usize::try_from(*address).map_err(|_| ReadError::Fault)?,
                        len: out.len(),
                    })
                })
                .collect::<Result<Vec<_>, ReadError>>()?;
            let expected = remote.iter().map(|segment| segment.len).sum::<usize>();
            let mut local = chunk
                .iter_mut()
                .map(|(_, out)| IoSliceMut::new(out))
                .collect::<Vec<_>>();
            transfer(process_vm_readv(self.pid, &mut local, &remote), expected)?;
        }
        Ok(())
    }
}

/// A complete transfer, or why it failed; a partial one is a fault.
fn transfer(result: nix::Result<usize>, expected: usize) -> Result<(), ReadError> {
    match result {
        Ok(read) if read == expected => Ok(()),
        Err(Errno::EPERM | Errno::EACCES) => Err(ReadError::Permission),
        Err(Errno::ESRCH) => Err(ReadError::Gone),
        Ok(_) | Err(Errno::EFAULT) => Err(ReadError::Fault),
        Err(errno) => Err(ReadError::Other(errno as i32)),
    }
}

/// Why sampling stopped or could not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamplerError {
    Read {
        what: &'static str,
        error: ReadError,
    },
    /// `_Py_DebugOffsets` disagrees with the built-in layout.
    LayoutMismatch {
        field: &'static str,
        expected: u64,
        found: u64,
    },
    NotDebugOffsets,
    FreeThreaded,
    NoInterpreter,
    Clock(String),
}

impl fmt::Display for SamplerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { what, error } => write!(formatter, "failed to read {what}: {error:?}"),
            Self::LayoutMismatch {
                field,
                expected,
                found,
            } => write!(
                formatter,
                "the interpreter's _Py_DebugOffsets reports {field} = {found}, expected {expected}; this CPython build has an unsupported layout"
            ),
            Self::NotDebugOffsets => write!(
                formatter,
                "_PyRuntime does not start with _Py_DebugOffsets; this CPython build has an unsupported layout"
            ),
            Self::FreeThreaded => write!(
                formatter,
                "free-threaded CPython builds have a different object layout and are not supported"
            ),
            Self::NoInterpreter => write!(formatter, "the CPython runtime has no interpreter"),
            Self::Clock(error) => write!(formatter, "failed to read CLOCK_MONOTONIC: {error}"),
        }
    }
}

impl Error for SamplerError {}

/// Why one stack read was discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discard {
    /// The stack changed while it was read.
    Inconsistent,
    Fatal(ReadError),
}

impl From<ReadError> for Discard {
    fn from(error: ReadError) -> Self {
        match error {
            // Frames are freed while a running thread is read.
            ReadError::Fault => Self::Inconsistent,
            ReadError::Permission | ReadError::Gone | ReadError::Other(_) => Self::Fatal(error),
        }
    }
}

/// The GIL at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GilState {
    /// The thread state holding it, or `None` while it is released.
    pub holder: Option<u64>,
    /// The thread state that took it last, even while it is released.
    pub last_holder: u64,
    /// Handoffs so far; it changes whenever another thread takes the GIL.
    pub switches: u64,
}

/// Walks interpreter state; resolved code objects are cached and shared by
/// every sample.
pub struct Walker<'m, M: RemoteMemory> {
    memory: &'m M,
    runtime: PythonRuntime,
    max_depth: usize,
    codes: Vec<Code>,
    /// Code address to (its identifying header fields, index into `codes`).
    by_address: HashMap<u64, ([u8; 32], u32)>,
}

impl<'m, M: RemoteMemory> Walker<'m, M> {
    #[must_use]
    pub fn new(memory: &'m M, runtime: PythonRuntime, max_depth: usize) -> Self {
        Self {
            memory,
            runtime,
            max_depth,
            codes: Vec::new(),
            by_address: HashMap::new(),
        }
    }

    const fn layout(&self) -> &'static PythonLayout {
        self.runtime.layout
    }

    fn u64_at(&self, address: u64) -> Result<u64, ReadError> {
        let mut buffer = [0_u8; 8];
        self.memory.read(address, &mut buffer)?;
        Ok(u64::from_le_bytes(buffer))
    }

    fn u32_at(&self, address: u64) -> Result<u32, ReadError> {
        let mut buffer = [0_u8; 4];
        self.memory.read(address, &mut buffer)?;
        Ok(u32::from_le_bytes(buffer))
    }

    /// Check `_Py_DebugOffsets` (3.13+) against the built-in layout.
    ///
    /// # Errors
    ///
    /// Returns [`SamplerError`] when the runtime is unreadable, free-threaded,
    /// or laid out differently.
    pub fn verify(&self) -> Result<(), SamplerError> {
        let layout = self.layout();
        let Some(debug) = layout.debug else {
            return Ok(());
        };
        let base = self.runtime.runtime_address;
        let read = |offset: u64, what| {
            self.u64_at(base + offset)
                .map_err(|error| SamplerError::Read { what, error })
        };
        let mut cookie = [0_u8; 8];
        self.memory
            .read(base, &mut cookie)
            .map_err(|error| SamplerError::Read {
                what: "the _Py_DebugOffsets cookie",
                error,
            })?;
        if &cookie != b"xdebugpy" {
            return Err(SamplerError::NotDebugOffsets);
        }
        if read(16, "the free-threaded flag")? != 0 {
            return Err(SamplerError::FreeThreaded);
        }
        let current_frame = match layout.frame {
            FramePath::Direct { tstate_frame } => tstate_frame,
            FramePath::CFrame { .. } => return Err(SamplerError::NotDebugOffsets),
        };
        for (field, position, expected) in [
            (
                "runtime_state.interpreters_head",
                debug.runtime_interpreters_head,
                layout.runtime_interpreters_head,
            ),
            (
                "interpreter_state.threads_head",
                debug.interp_threads_head,
                layout.interp_threads_head,
            ),
            ("thread_state.next", debug.tstate_next, layout.tstate_next),
            (
                "thread_state.native_thread_id",
                debug.tstate_native_thread_id,
                layout.tstate_native_thread_id.unwrap_or(u64::MAX),
            ),
            (
                "thread_state.current_frame",
                debug.tstate_current_frame,
                current_frame,
            ),
            (
                "interpreter_frame.previous",
                debug.frame_back,
                layout.frame_back,
            ),
            (
                "interpreter_frame.executable",
                debug.frame_code,
                layout.frame_code,
            ),
            (
                "interpreter_frame.owner",
                debug.frame_owner,
                layout.frame_owner.unwrap_or(u64::MAX),
            ),
            (
                "code_object.filename",
                debug.code_filename,
                layout.code_filename,
            ),
            (
                "code_object.qualname",
                debug.code_qualname,
                layout.code_qualname.unwrap_or(u64::MAX),
            ),
            (
                "code_object.firstlineno",
                debug.code_firstlineno,
                layout.code_firstlineno,
            ),
            ("pyobject.ob_type", debug.object_type, layout.object_type),
        ] {
            let found = read(position, field)?;
            if found != expected {
                return Err(SamplerError::LayoutMismatch {
                    field,
                    expected,
                    found,
                });
            }
        }
        Ok(())
    }

    /// The main interpreter.
    ///
    /// # Errors
    ///
    /// Returns [`SamplerError`] when the runtime is unreadable or empty.
    pub fn interpreter(&self) -> Result<u64, SamplerError> {
        let interpreter = self
            .u64_at(self.runtime.runtime_address + self.layout().runtime_interpreters_head)
            .map_err(|error| SamplerError::Read {
                what: "the interpreter list",
                error,
            })?;
        if interpreter == 0 {
            return Err(SamplerError::NoInterpreter);
        }
        Ok(interpreter)
    }

    /// Thread states of an interpreter.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] when the thread list is unreadable.
    pub fn threads(&self, interpreter: u64) -> Result<Vec<u64>, ReadError> {
        let mut threads = Vec::new();
        let mut thread = self.u64_at(interpreter + self.layout().interp_threads_head)?;
        while thread != 0 && threads.len() < MAX_THREADS && !threads.contains(&thread) {
            threads.push(thread);
            thread = self.u64_at(thread + self.layout().tstate_next)?;
        }
        Ok(threads)
    }

    /// The GIL's holder and handoff count, read at once.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] when the GIL state is unreadable.
    pub fn gil_state(&self, interpreter: u64) -> Result<GilState, ReadError> {
        let (gil, last_holder, locked, switch_number) = match self.layout().gil {
            GilPath::Runtime {
                last_holder,
                locked,
                switch_number,
            } => (
                self.runtime.runtime_address,
                last_holder,
                locked,
                switch_number,
            ),
            GilPath::Interpreter {
                interp_gil,
                last_holder,
                locked,
                switch_number,
            } => (
                self.u64_at(interpreter + interp_gil)?,
                last_holder,
                locked,
                switch_number,
            ),
        };
        if gil == 0 {
            return Ok(GilState {
                holder: None,
                last_holder: 0,
                switches: 0,
            });
        }
        // The three fields sit together at the start of the GIL state.
        let first = last_holder.min(locked).min(switch_number);
        let end = last_holder.max(locked).max(switch_number) + 8;
        let mut block = [0_u8; 64];
        let block = block
            .get_mut(..usize::try_from(end - first).map_err(|_| ReadError::Fault)?)
            .ok_or(ReadError::Fault)?;
        self.memory.read(gil + first, block)?;
        let field = |offset: u64, width: usize| -> Result<u64, ReadError> {
            let start = usize::try_from(offset - first).map_err(|_| ReadError::Fault)?;
            let mut bytes = [0_u8; 8];
            bytes[..width]
                .copy_from_slice(block.get(start..start + width).ok_or(ReadError::Fault)?);
            Ok(u64::from_le_bytes(bytes))
        };
        let holder = field(last_holder, 8)?;
        Ok(GilState {
            holder: (field(locked, 4)? != 0 && holder != 0).then_some(holder),
            last_holder: holder,
            switches: field(switch_number, 8)?,
        })
    }

    /// The thread state holding the GIL, or `None` while it is released.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] when the GIL state is unreadable.
    pub fn gil_holder(&self, interpreter: u64) -> Result<Option<u64>, ReadError> {
        Ok(self.gil_state(interpreter)?.holder)
    }

    /// What identifies the OS thread behind a thread state: its TID from
    /// 3.11, its `pthread_t` before.
    fn identity(&self, thread: u64) -> Result<u64, ReadError> {
        match self.layout().tstate_native_thread_id {
            Some(offset) => self.u64_at(thread + offset),
            None => self.pthread(thread),
        }
    }

    /// The Linux TID a thread state records (3.11+).
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] when the thread state is unreadable.
    pub fn native_thread_id(&self, thread: u64) -> Result<Option<u32>, ReadError> {
        let Some(offset) = self.layout().tstate_native_thread_id else {
            return Ok(None);
        };
        Ok(u32::try_from(self.u64_at(thread + offset)?).ok())
    }

    /// The `pthread_t` a thread state records.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] when the thread state is unreadable.
    pub fn pthread(&self, thread: u64) -> Result<u64, ReadError> {
        self.u64_at(thread + self.layout().tstate_thread_id)
    }

    fn top_frame(&self, thread: u64) -> Result<u64, ReadError> {
        match self.layout().frame {
            FramePath::Direct { tstate_frame } => self.u64_at(thread + tstate_frame),
            FramePath::CFrame {
                tstate_cframe,
                cframe_current_frame,
            } => {
                let cframe = self.u64_at(thread + tstate_cframe)?;
                if cframe == 0 {
                    return Ok(0);
                }
                self.u64_at(cframe + cframe_current_frame)
            }
        }
    }

    /// Bytes of a frame the walker reads.
    fn frame_bytes(&self) -> u64 {
        let layout = self.layout();
        [
            Some(layout.frame_back),
            Some(layout.frame_code),
            layout.frame_owner,
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(0)
            + 8
    }

    /// Bytes of a code object the walker reads.
    fn code_header_bytes(&self) -> u64 {
        let layout = self.layout();
        [
            layout.object_type,
            layout.code_filename,
            layout.code_name,
            layout.code_qualname.unwrap_or(layout.code_name),
        ]
        .into_iter()
        .max()
        .unwrap_or(0)
        .max(layout.code_firstlineno)
            + 8
    }

    /// Read one thread's stack: walk the frames, then read every frame's
    /// code object in one batch.
    fn stack(&mut self, thread: u64) -> Result<Stack, Discard> {
        let layout = self.layout();
        let top = self.top_frame(thread)?;
        let frame_bytes = self.frame_bytes();
        // 3.11+ frames sit together on the thread's data stack; read the
        // span below the innermost one at once and fall back per frame.
        let window = if layout.frame_owner.is_some() && top != 0 {
            let start = top.saturating_sub(FRAME_WINDOW_BYTES);
            let mut bytes = vec![0_u8; usize::try_from(top - start + frame_bytes).unwrap_or(0)];
            // The window may reach below the data stack's mapping; only a
            // fault falls back to per-frame reads.
            match self.memory.read(start, &mut bytes) {
                Ok(()) => Some((start, bytes)),
                Err(ReadError::Fault) => None,
                Err(error) => return Err(Discard::Fatal(error)),
            }
        } else {
            None
        };
        let mut single = vec![0_u8; usize::try_from(frame_bytes).unwrap_or(usize::MAX)];
        let mut codes = Vec::new();
        let mut frame = top;
        let mut visited = 0_usize;
        let mut truncated = false;
        while frame != 0 {
            if codes.len() == self.max_depth || visited > self.max_depth * 2 {
                truncated = true;
                break;
            }
            visited += 1;
            let bytes: &[u8] = match window.as_ref() {
                Some((start, bytes))
                    if frame >= *start && frame - start + frame_bytes <= bytes.len() as u64 =>
                {
                    let offset = usize::try_from(frame - start).unwrap_or(usize::MAX);
                    &bytes[offset..]
                }
                _ => {
                    self.memory.read(frame, &mut single)?;
                    &single
                }
            };
            let field = |offset: u64| {
                let start = usize::try_from(offset).unwrap_or(usize::MAX);
                u64::from_le_bytes(bytes[start..start + 8].try_into().expect("eight bytes"))
            };
            let back = field(layout.frame_back);
            // Interpreter entry frames and C-stack shims are not Python code.
            let shim = layout
                .frame_owner
                .zip(layout.first_non_python_owner)
                .is_some_and(|(offset, first)| {
                    bytes[usize::try_from(offset).unwrap_or(usize::MAX)] >= first
                });
            if !shim {
                let mut code = field(layout.frame_code);
                if layout.code_tagged {
                    code &= !1;
                }
                codes.push(code);
            }
            frame = back;
        }
        let frames = self.codes(&codes)?;
        if self.top_frame(thread)? != top {
            return Err(Discard::Inconsistent);
        }
        Ok(Stack { frames, truncated })
    }

    /// Resolve code objects with one batched header read, reusing cached
    /// ones whose identifying fields are unchanged.
    fn codes(&mut self, addresses: &[u64]) -> Result<Vec<u32>, Discard> {
        let layout = self.layout();
        let mut unique = addresses.to_vec();
        unique.sort_unstable();
        unique.dedup();
        let length = usize::try_from(self.code_header_bytes()).unwrap_or(usize::MAX);
        let mut headers = vec![vec![0_u8; length]; unique.len()];
        let mut reads = unique
            .iter()
            .zip(headers.iter_mut())
            .map(|(address, header)| (*address, header.as_mut_slice()))
            .collect::<Vec<_>>();
        self.memory.read_many(&mut reads)?;
        let mut resolved = HashMap::with_capacity(unique.len());
        for (address, header) in unique.iter().zip(&headers) {
            let pointer = |offset: u64| {
                let start = usize::try_from(offset).unwrap_or(usize::MAX);
                u64::from_le_bytes(header[start..start + 8].try_into().expect("eight bytes"))
            };
            if pointer(layout.object_type) != self.runtime.code_type_address {
                return Err(Discard::Inconsistent);
            }
            let start = usize::try_from(layout.code_firstlineno).unwrap_or(usize::MAX);
            let first_line =
                i32::from_le_bytes(header[start..start + 4].try_into().expect("four bytes"));
            let filename = pointer(layout.code_filename);
            let name = pointer(layout.code_qualname.unwrap_or(layout.code_name));
            let mut identity = [0_u8; 32];
            identity[0..8].copy_from_slice(&filename.to_le_bytes());
            identity[8..16].copy_from_slice(&name.to_le_bytes());
            identity[16..20].copy_from_slice(&first_line.to_le_bytes());
            let index = match self.by_address.get(address) {
                Some((cached, index)) if *cached == identity => *index,
                _ => {
                    let code = Code {
                        function: self.string(name)?,
                        file: self.string(filename)?,
                        first_line: u32::try_from(first_line).unwrap_or(0),
                    };
                    let index = u32::try_from(self.codes.len()).unwrap_or(u32::MAX);
                    self.codes.push(code);
                    self.by_address.insert(*address, (identity, index));
                    index
                }
            };
            resolved.insert(*address, index);
        }
        Ok(addresses.iter().map(|address| resolved[address]).collect())
    }

    /// Decode a compact `str` object.
    fn string(&self, address: u64) -> Result<String, Discard> {
        let layout = self.layout();
        let mut header = vec![0_u8; usize::try_from(layout.compact_size).unwrap_or(usize::MAX)];
        self.memory.read(address, &mut header)?;
        let at = |offset: u64, width: usize| {
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            header[start..start + width].to_vec()
        };
        let state = u32::from_le_bytes(at(layout.ascii_state, 4).try_into().expect("four bytes"));
        let length =
            u64::from_le_bytes(at(layout.ascii_length, 8).try_into().expect("eight bytes"));
        let kind = (state >> 2) & 0b111;
        let compact = (state >> 5) & 1 == 1;
        let ascii = (state >> 6) & 1 == 1;
        if !compact || !matches!(kind, 1 | 2 | 4) || length > MAX_STRING_CHARS {
            return Err(Discard::Inconsistent);
        }
        let data = if ascii {
            layout.ascii_size
        } else {
            layout.compact_size
        };
        let width = u64::from(kind);
        let mut bytes = vec![0_u8; usize::try_from(length * width).unwrap_or(usize::MAX)];
        self.memory.read(address + data, &mut bytes)?;
        let characters: Option<String> = match kind {
            1 => Some(bytes.iter().map(|byte| char::from(*byte)).collect()),
            2 => bytes
                .chunks_exact(2)
                .map(|unit| char::from_u32(u32::from(u16::from_le_bytes([unit[0], unit[1]]))))
                .collect(),
            _ => bytes
                .chunks_exact(4)
                .map(|unit| {
                    char::from_u32(u32::from_le_bytes([unit[0], unit[1], unit[2], unit[3]]))
                })
                .collect(),
        };
        characters.ok_or(Discard::Inconsistent)
    }

    /// The functions referenced by sample frames.
    #[must_use]
    pub fn into_codes(self) -> Vec<Code> {
        self.codes
    }
}

/// Find where `struct pthread` stores its TID (CPython before 3.11 records
/// only `pthread_t`). Every thread state must agree on one offset that maps
/// it to a distinct TID of the target; otherwise threads stay unmapped.
///
/// A thread that exits during the search leaves it undecided for this sweep.
fn pthread_tid_offset<M: RemoteMemory>(
    walker: &Walker<'_, M>,
    threads: &[u64],
    tids: &BTreeSet<u32>,
) -> Result<Option<u64>, ReadError> {
    match search_pthread_tid_offset(walker, threads, tids) {
        Err(ReadError::Fault) => Ok(None),
        other => other,
    }
}

fn search_pthread_tid_offset<M: RemoteMemory>(
    walker: &Walker<'_, M>,
    threads: &[u64],
    tids: &BTreeSet<u32>,
) -> Result<Option<u64>, ReadError> {
    let mut candidates: Option<BTreeSet<u64>> = None;
    for thread in threads {
        let pthread = walker.pthread(*thread)?;
        let mut bytes = vec![0_u8; PTHREAD_SEARCH_BYTES];
        walker.memory.read(pthread, &mut bytes)?;
        let found = bytes
            .chunks_exact(4)
            .zip((0_u64..).step_by(4))
            .filter(|(word, _)| {
                tids.contains(&u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
            })
            .map(|(_, offset)| offset)
            .collect::<BTreeSet<_>>();
        candidates = Some(match candidates {
            None => found,
            Some(previous) => previous.intersection(&found).copied().collect(),
        });
    }
    // Keep offsets that map every thread to a distinct TID; several are
    // acceptable only when they agree on every thread.
    let mut chosen: Option<(u64, Vec<u32>)> = None;
    for offset in candidates.unwrap_or_default() {
        let mapped = threads
            .iter()
            .map(|thread| walker.u32_at(walker.pthread(*thread)? + offset))
            .collect::<Result<Vec<_>, _>>()?;
        if mapped.iter().collect::<BTreeSet<_>>().len() != threads.len() {
            continue;
        }
        match &chosen {
            None => chosen = Some((offset, mapped)),
            Some((_, previous)) if *previous == mapped => {}
            Some(_) => return Ok(None),
        }
    }
    Ok(chosen.map(|(offset, _)| offset))
}

/// When and how much to sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplerConfig {
    pub duration: Duration,
    /// Period of GIL-holder samples, or `None` to sample only all threads.
    pub gil_period: Option<Duration>,
    /// Period of samples of every thread.
    pub threads_period: Duration,
    pub max_samples: usize,
    pub max_depth: usize,
}

fn monotonic_ns() -> Result<u64, SamplerError> {
    let now = clock_gettime(ClockId::CLOCK_MONOTONIC)
        .map_err(|error| SamplerError::Clock(error.to_string()))?;
    let seconds =
        u64::try_from(now.tv_sec()).map_err(|error| SamplerError::Clock(error.to_string()))?;
    let nanoseconds =
        u64::try_from(now.tv_nsec()).map_err(|error| SamplerError::Clock(error.to_string()))?;
    Ok(seconds * 1_000_000_000 + nanoseconds)
}

/// The target's TIDs. A thread that exits mid-listing is skipped; a target
/// that is gone or unreadable is an error.
fn task_ids(pid: u32) -> Result<BTreeSet<u32>, SamplerError> {
    let failure = |error: &std::io::Error| SamplerError::Read {
        what: "the target's thread list",
        error: match error.kind() {
            std::io::ErrorKind::NotFound => ReadError::Gone,
            std::io::ErrorKind::PermissionDenied => ReadError::Permission,
            _ => ReadError::Other(error.raw_os_error().unwrap_or(0)),
        },
    };
    let mut tids = BTreeSet::new();
    for entry in fs::read_dir(format!("/proc/{pid}/task")).map_err(|error| failure(&error))? {
        let entry = entry.map_err(|error| failure(&error))?;
        if let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        {
            tids.insert(tid);
        }
    }
    Ok(tids)
}

struct Run<'w, 'm, M: RemoteMemory> {
    walker: &'w mut Walker<'m, M>,
    pid: u32,
    interpreter: u64,
    config: SamplerConfig,
    capture: PythonCapture,
    /// Where `struct pthread` stores the TID, once found (before 3.11).
    pthread_offset: Option<u64>,
}

impl<M: RemoteMemory> Run<'_, '_, M> {
    /// Sample one thread's stack. A GIL sample passes the GIL state it saw;
    /// the sample is kept only if no other thread took the GIL meanwhile,
    /// and any sample only if its thread state named one OS thread
    /// throughout, since an exited thread's state can be reused.
    fn read(&mut self, thread: u64, gil: Option<GilState>) -> Result<(), SamplerError> {
        if self.capture.samples.len() >= self.config.max_samples {
            self.capture.counters.over_capacity += 1;
            return Ok(());
        }
        let timestamp_ns = monotonic_ns()?;
        let started = Instant::now();
        let outcome = self.consistent_stack(thread, gil);
        let (stack, tid) = match outcome {
            Ok(read) => read,
            Err(Discard::Inconsistent) => {
                self.capture.counters.inconsistent += 1;
                return Ok(());
            }
            Err(Discard::Fatal(error)) => {
                return Err(SamplerError::Read {
                    what: "a thread stack",
                    error,
                });
            }
        };
        self.capture
            .read_ns
            .push(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        self.capture.threads.extend(tid);
        // The GIL holder runs Python; a swept thread may be blocked.
        let native = match tid.filter(|_| gil.is_none()) {
            Some(tid) => self.native_leaf(tid),
            None => None,
        };
        self.capture.samples.push(PythonSample {
            timestamp_ns,
            tid,
            gil: gil.is_some(),
            stack,
            native,
        });
        Ok(())
    }

    fn consistent_stack(
        &mut self,
        thread: u64,
        gil: Option<GilState>,
    ) -> Result<(Stack, Option<u32>), Discard> {
        let identity = self.identity(thread)?;
        let stack = self.walker.stack(thread)?;
        if let Some(before) = gil {
            // Another thread taking the GIL during the read, even if it came
            // back, makes part of it that thread's time. The holder dropping
            // and retaking it does not count as a switch.
            let after = self.walker.gil_state(self.interpreter)?;
            if after.last_holder != thread || after.switches != before.switches {
                return Err(Discard::Inconsistent);
            }
        }
        if self.identity(thread)? != identity {
            return Err(Discard::Inconsistent);
        }
        Ok((stack, identity.1))
    }

    /// The OS thread behind a thread state: what the thread state records
    /// (its TID from 3.11, its `pthread_t` before) and the TID it maps to.
    /// Before 3.11 the TID is read through the `pthread_t` each time, since
    /// an exited thread's `struct pthread` can be reused.
    fn identity(&self, thread: u64) -> Result<(u64, Option<u32>), Discard> {
        let recorded = self.walker.identity(thread)?;
        if self.walker.layout().tstate_native_thread_id.is_some() {
            return Ok((
                recorded,
                u32::try_from(recorded).ok().filter(|tid| *tid != 0),
            ));
        }
        match self.pthread_offset {
            Some(offset) => Ok((recorded, Some(self.walker.u32_at(recorded + offset)?))),
            None => Ok((recorded, None)),
        }
    }

    /// Where a blocked thread waits; an unreadable or unparsable state is
    /// counted rather than mistaken for a running thread.
    fn native_leaf(&mut self, tid: u32) -> Option<NativeLeaf> {
        let Ok(text) = fs::read_to_string(format!("/proc/{}/task/{tid}/syscall", self.pid)) else {
            self.capture.counters.native_unreadable += 1;
            return None;
        };
        let leaf = parse_task_syscall(&text);
        if leaf.is_none() && text.trim() != "running" {
            self.capture.counters.native_unreadable += 1;
        }
        leaf
    }

    /// Refresh the thread list and its TIDs, then sample every thread.
    fn sweep(&mut self) -> Result<(), SamplerError> {
        let threads =
            self.walker
                .threads(self.interpreter)
                .map_err(|error| SamplerError::Read {
                    what: "the thread list",
                    error,
                })?;
        // Until an offset is found, every sweep searches again.
        if self.walker.layout().tstate_native_thread_id.is_none() && self.pthread_offset.is_none() {
            self.pthread_offset = pthread_tid_offset(self.walker, &threads, &task_ids(self.pid)?)
                .map_err(|error| SamplerError::Read {
                what: "a thread's pthread",
                error,
            })?;
            self.capture.tid_source = self
                .pthread_offset
                .map_or(TidSource::Unmapped, TidSource::Pthread);
        }
        self.capture.counters.thread_sweeps += 1;
        for thread in threads {
            self.read(thread, None)?;
        }
        Ok(())
    }
}

/// Sample a CPython process for `config.duration`.
///
/// # Errors
///
/// Returns [`SamplerError`] when the runtime cannot be read or verified, the
/// target denies access, or it exits.
pub fn sample<M: RemoteMemory>(
    walker: &mut Walker<'_, M>,
    pid: u32,
    config: SamplerConfig,
) -> Result<PythonCapture, SamplerError> {
    walker.verify()?;
    let interpreter = walker.interpreter()?;
    let native_tids = walker.layout().tstate_native_thread_id.is_some();
    let mut run = Run {
        walker,
        pid,
        interpreter,
        config,
        capture: PythonCapture {
            samples: Vec::new(),
            codes: Vec::new(),
            counters: SamplerCounters::default(),
            read_ns: Vec::new(),
            elapsed: Duration::ZERO,
            tid_source: if native_tids {
                TidSource::Native
            } else {
                TidSource::Unmapped
            },
            threads: BTreeSet::new(),
        },
        pthread_offset: None,
    };
    let start = Instant::now();
    let end = start + config.duration;
    let mut next_sweep = start;
    let mut next_gil = start;
    loop {
        let now = Instant::now();
        if now >= end {
            break;
        }
        if now >= next_sweep {
            run.sweep()?;
            next_sweep = advance(
                next_sweep,
                config.threads_period,
                now,
                &mut run.capture.counters,
            );
        }
        if let Some(period) = config.gil_period
            && now >= next_gil
        {
            run.capture.counters.gil_ticks += 1;
            match run.walker.gil_state(interpreter) {
                Ok(
                    state @ GilState {
                        holder: Some(holder),
                        ..
                    },
                ) => run.read(holder, Some(state))?,
                Ok(GilState { holder: None, .. }) => run.capture.counters.gil_idle += 1,
                Err(ReadError::Fault) => run.capture.counters.inconsistent += 1,
                Err(error) => {
                    return Err(SamplerError::Read {
                        what: "the GIL",
                        error,
                    });
                }
            }
            next_gil = advance(next_gil, period, now, &mut run.capture.counters);
        }
        let wake = config
            .gil_period
            .map_or(next_sweep, |_| next_gil.min(next_sweep))
            .min(end);
        let now = Instant::now();
        if wake > now {
            thread::sleep(wake - now);
        }
    }
    let mut capture = run.capture;
    capture.elapsed = start.elapsed();
    capture.codes = std::mem::take(&mut run.walker.codes);
    Ok(capture)
}

/// The next deadline after `deadline`; a missed one restarts from now
/// instead of bursting to catch up.
fn advance(
    deadline: Instant,
    period: Duration,
    now: Instant,
    counters: &mut SamplerCounters,
) -> Instant {
    let next = deadline + period;
    if next <= now {
        counters.late_ticks += 1;
        now + period
    } else {
        next
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use xprobe_core::python_layout::{PythonRuntime, layout};

    use super::{Code, Discard, ReadError, RemoteMemory, Walker};

    /// Sparse little-endian memory; unmapped reads fault.
    #[derive(Default)]
    struct Memory {
        bytes: RefCell<BTreeMap<u64, u8>>,
    }

    impl Memory {
        fn put(&self, address: u64, bytes: &[u8]) {
            let mut memory = self.bytes.borrow_mut();
            for (offset, byte) in bytes.iter().enumerate() {
                memory.insert(address + offset as u64, *byte);
            }
        }

        fn u64(&self, address: u64, value: u64) {
            self.put(address, &value.to_le_bytes());
        }

        /// A compact string object with CPython's narrowest kind.
        fn string(&self, address: u64, minor: u8, text: &str) {
            let layout = layout(minor).unwrap();
            let ascii = text.is_ascii();
            let widest = text.chars().map(u32::from).max().unwrap_or(0);
            let kind: u32 = match widest {
                0..=0xff => 1,
                0x100..=0xffff => 2,
                _ => 4,
            };
            let state = (kind << 2) | (1 << 5) | (u32::from(ascii) << 6);
            self.put(
                address,
                &vec![0; usize::try_from(layout.compact_size).unwrap()],
            );
            self.u64(address + layout.ascii_length, text.chars().count() as u64);
            self.put(address + layout.ascii_state, &state.to_le_bytes());
            let data = if ascii {
                layout.ascii_size
            } else {
                layout.compact_size
            };
            let encoded: Vec<u8> = match kind {
                1 => text
                    .chars()
                    .map(|c| u8::try_from(u32::from(c)).unwrap())
                    .collect(),
                2 => text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
                _ => text
                    .chars()
                    .flat_map(|c| u32::from(c).to_le_bytes())
                    .collect(),
            };
            self.put(address + data, &encoded);
        }

        /// A code object with zeroed fields up to its qualname.
        fn code(
            &self,
            address: u64,
            minor: u8,
            names: (u64, u64),
            first_line: i32,
            code_type: u64,
        ) {
            let layout = layout(minor).unwrap();
            self.put(address, &[0; 144]);
            self.u64(address + layout.object_type, code_type);
            self.u64(address + layout.code_filename, names.0);
            self.u64(address + layout.code_name, names.1);
            if let Some(qualname) = layout.code_qualname {
                self.u64(address + qualname, names.1);
            }
            self.put(address + layout.code_firstlineno, &first_line.to_le_bytes());
        }
    }

    impl RemoteMemory for Memory {
        fn read(&self, address: u64, out: &mut [u8]) -> Result<(), ReadError> {
            let memory = self.bytes.borrow();
            for (offset, byte) in out.iter_mut().enumerate() {
                *byte = *memory
                    .get(&(address + offset as u64))
                    .ok_or(ReadError::Fault)?;
            }
            Ok(())
        }
    }

    const CODE_TYPE: u64 = 0x9000;

    fn runtime(minor: u8) -> PythonRuntime {
        PythonRuntime {
            binary: PathBuf::from("/usr/bin/python3"),
            minor,
            layout: layout(minor).unwrap(),
            runtime_address: 0x1000,
            code_type_address: CODE_TYPE,
        }
    }

    /// A 3.12 interpreter whose one thread holds the GIL and runs
    /// `outer -> <shim> -> inner`.
    fn python_312() -> Memory {
        let layout = layout(12).unwrap();
        let memory = Memory::default();
        memory.u64(0x1000 + layout.runtime_interpreters_head, 0x2000);
        memory.u64(0x2000 + layout.interp_threads_head, 0x3000);
        memory.u64(0x3000 + layout.tstate_next, 0);
        memory.u64(0x3000 + layout.tstate_native_thread_id.unwrap(), 4242);
        memory.u64(0x3000 + 56, 0x3100);
        memory.u64(0x3100, 0x4000);
        memory.u64(0x2000 + 384, 0x7000);
        memory.u64(0x7000 + 8, 0x3000);
        memory.put(0x7000 + 16, &[1, 0, 0, 0, 0, 0, 0, 0]);
        memory.u64(0x7000 + 24, 5);
        for (frame, code, back, owner) in [
            (0x4000, 0x5000, 0x4100, 0_u8),
            (0x4100, 0, 0x4200, 3),
            (0x4200, 0x5100, 0, 0),
        ] {
            memory.put(frame, &[0; 80]);
            memory.u64(frame + layout.frame_code, code);
            memory.u64(frame + layout.frame_back, back);
            memory.put(frame + layout.frame_owner.unwrap(), &[owner]);
        }
        memory.code(0x5000, 12, (0x6000, 0x6100), 10, CODE_TYPE);
        memory.code(0x5100, 12, (0x6000, 0x6200), 3, CODE_TYPE);
        memory.string(0x6000, 12, "app.py");
        memory.string(0x6100, 12, "inner");
        memory.string(0x6200, 12, "Model.forward");
        memory
    }

    #[test]
    fn walks_a_312_stack_and_skips_shim_frames() {
        let memory = python_312();
        let mut walker = Walker::new(&memory, runtime(12), 64);
        let interpreter = walker.interpreter().unwrap();
        assert_eq!(walker.threads(interpreter).unwrap(), [0x3000]);
        assert_eq!(walker.gil_holder(interpreter).unwrap(), Some(0x3000));
        assert_eq!(walker.native_thread_id(0x3000).unwrap(), Some(4242));

        let stack = walker.stack(0x3000).unwrap();
        assert_eq!(stack.frames.len(), 2);
        assert!(!stack.truncated);
        // Reading again reuses the resolved code objects.
        assert_eq!(walker.stack(0x3000).unwrap(), stack);
        let codes = walker.into_codes();
        assert_eq!(
            codes,
            [
                Code {
                    function: "inner".to_owned(),
                    file: "app.py".to_owned(),
                    first_line: 10
                },
                Code {
                    function: "Model.forward".to_owned(),
                    file: "app.py".to_owned(),
                    first_line: 3
                },
            ]
        );
    }

    #[test]
    fn reads_data_stack_frames_in_one_window() {
        // Frames grow upward on a thread's data stack: the innermost frame
        // is highest and its callers sit below it inside one window.
        let layout = layout(12).unwrap();
        let memory = python_312();
        memory.put(0x10000 - super::FRAME_WINDOW_BYTES, &vec![0; 0x4100]);
        memory.u64(0x3100, 0x10000);
        for (frame, code, back) in [(0x10000, 0x5000, 0xff00), (0xff00, 0x5100, 0)] {
            memory.u64(frame + layout.frame_code, code);
            memory.u64(frame + layout.frame_back, back);
        }
        let mut walker = Walker::new(&memory, runtime(12), 64);
        assert_eq!(walker.stack(0x3000).unwrap().frames, [0, 1]);
    }

    #[test]
    fn a_released_gil_has_no_holder() {
        let memory = python_312();
        memory.put(0x7000 + 16, &0_u32.to_le_bytes());
        let walker = Walker::new(&memory, runtime(12), 64);
        assert_eq!(walker.gil_holder(0x2000).unwrap(), None);
    }

    fn run<'w, 'm>(walker: &'w mut Walker<'m, Memory>) -> super::Run<'w, 'm, Memory> {
        let interpreter = walker.interpreter().unwrap();
        super::Run {
            walker,
            pid: 1,
            interpreter,
            config: super::SamplerConfig {
                duration: std::time::Duration::from_secs(1),
                gil_period: None,
                threads_period: std::time::Duration::from_secs(1),
                max_samples: 16,
                max_depth: 64,
            },
            capture: xprobe_core::python_sampling::PythonCapture {
                samples: Vec::new(),
                codes: Vec::new(),
                counters: xprobe_core::python_sampling::SamplerCounters::default(),
                read_ns: Vec::new(),
                elapsed: std::time::Duration::ZERO,
                tid_source: xprobe_core::python_sampling::TidSource::Native,
                threads: std::collections::BTreeSet::new(),
            },
            pthread_offset: None,
        }
    }

    #[test]
    fn a_gil_sample_needs_the_same_holder_throughout() {
        let memory = python_312();
        let mut walker = Walker::new(&memory, runtime(12), 64);
        let before = walker.gil_state(0x2000).unwrap();
        assert_eq!((before.holder, before.switches), (Some(0x3000), 5));
        let mut run = run(&mut walker);
        run.read(0x3000, Some(before)).unwrap();
        assert_eq!(run.capture.samples.len(), 1);
        assert_eq!(run.capture.samples[0].tid, Some(4242));

        // The holder released the GIL during the read without a switch.
        memory.put(0x7000 + 16, &[0, 0, 0, 0, 0, 0, 0, 0]);
        run.read(0x3000, Some(before)).unwrap();
        assert_eq!(run.capture.samples.len(), 2);

        // The GIL went to another thread and came back during the read.
        run.read(
            0x3000,
            Some(super::GilState {
                switches: 3,
                ..before
            }),
        )
        .unwrap();
        assert_eq!(run.capture.samples.len(), 2);
        assert_eq!(run.capture.counters.inconsistent, 1);
    }

    #[test]
    fn torn_stacks_are_discarded() {
        // A frame whose code pointer no longer points at a code object.
        let memory = python_312();
        memory.u64(0x5100 + 8, 0xdead);
        let mut walker = Walker::new(&memory, runtime(12), 64);
        assert_eq!(walker.stack(0x3000), Err(Discard::Inconsistent));

        // A frame freed while it was read.
        let memory = python_312();
        memory.u64(0x4200 + layout(12).unwrap().frame_back, 0xbad0);
        let mut walker = Walker::new(&memory, runtime(12), 64);
        assert_eq!(walker.stack(0x3000), Err(Discard::Inconsistent));
    }

    #[test]
    fn deep_stacks_are_truncated_at_the_depth_bound() {
        let memory = python_312();
        let mut walker = Walker::new(&memory, runtime(12), 1);
        let stack = walker.stack(0x3000).unwrap();
        assert_eq!(stack.frames.len(), 1);
        assert!(stack.truncated);
    }

    #[test]
    fn decodes_every_string_kind() {
        // Latin-1 (one byte but not ASCII), UCS-2, and UCS-4.
        let memory = Memory::default();
        memory.string(0x6000, 10, "naïve_step");
        memory.string(0x7000, 12, "推理");
        memory.string(0x8000, 13, "step_🚀");
        for (address, minor, text) in [
            (0x6000, 10, "naïve_step"),
            (0x7000, 12, "推理"),
            (0x8000, 13, "step_🚀"),
        ] {
            let walker = Walker::new(&memory, runtime(minor), 1);
            assert_eq!(walker.string(address).unwrap(), text);
        }
    }

    #[test]
    fn walks_a_310_frame_chain() {
        let layout = layout(10).unwrap();
        let memory = Memory::default();
        memory.u64(0x3000 + 24, 0x4000);
        for (frame, code, back) in [(0x4000, 0x5000, 0x4100), (0x4100, 0x5100, 0)] {
            memory.put(frame, &[0; 48]);
            memory.u64(frame + layout.frame_code, code);
            memory.u64(frame + layout.frame_back, back);
        }
        memory.code(0x5000, 10, (0x6000, 0x6100), 7, CODE_TYPE);
        memory.code(0x5100, 10, (0x6000, 0x6200), 1, CODE_TYPE);
        memory.string(0x6000, 10, "train.py");
        memory.string(0x6100, 10, "step");
        memory.string(0x6200, 10, "<module>");
        let mut walker = Walker::new(&memory, runtime(10), 64);
        assert_eq!(walker.stack(0x3000).unwrap().frames, [0, 1]);
        let codes = walker.into_codes();
        assert_eq!(codes[0].function, "step");
        assert_eq!(codes[1].function, "<module>");
    }
}
