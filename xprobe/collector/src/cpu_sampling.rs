use std::{
    error::Error,
    fmt, io, thread,
    time::{Duration, Instant},
};

use perf_event_open::{
    config::{CallChain as CallChainConfig, Cpu, Opts, Priv as ExcludedPriv, Proc, SampleOn},
    count::Counter,
    event::sw::Software,
    sample::{
        Sampler,
        record::{Record, sample::CallChain},
    },
};
const RING_PAGE_EXPONENT: u8 = 3;
const DRAIN_INTERVAL: Duration = Duration::from_millis(10);
const ESRCH: i32 = 3;

#[derive(Debug, Clone)]
pub struct CpuSamplingRequest {
    pub thread_ids: Vec<u32>,
    pub frequency_hz: u64,
    pub duration: Duration,
    pub timeout: Duration,
    pub max_samples: usize,
    pub max_threads: usize,
    pub stack_depth: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCpuStack {
    pub thread_id: u32,
    pub addresses: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuSampleCapture {
    pub stacks: Vec<RawCpuStack>,
    pub observed_samples: u64,
    pub lost_samples: u64,
    pub truncated_stacks: u64,
    pub throttled_records: u64,
    pub threads_observed: usize,
    pub threads_attached: usize,
    pub skipped_threads: Vec<u32>,
    pub capacity_reached: bool,
    pub elapsed: Duration,
}

#[derive(Debug)]
pub enum CpuSamplingError {
    InvalidRequest(&'static str),
    Open { thread_id: u32, source: io::Error },
    Ring { thread_id: u32, source: io::Error },
    Arm { thread_id: u32, source: io::Error },
    Cleanup { failures: Vec<String> },
    Timeout,
    NoThreadsAttached { skipped_threads: Vec<u32> },
}

impl fmt::Display for CpuSamplingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid CPU sampling request: {message}")
            }
            Self::Open { thread_id, source } => {
                write!(
                    formatter,
                    "failed to open perf event for thread {thread_id}: {source}"
                )
            }
            Self::Ring { thread_id, source } => {
                write!(
                    formatter,
                    "failed to map perf ring for thread {thread_id}: {source}"
                )
            }
            Self::Arm { thread_id, source } => {
                write!(
                    formatter,
                    "failed to enable perf event for thread {thread_id}: {source}"
                )
            }
            Self::Cleanup { failures } => {
                write!(
                    formatter,
                    "failed to disable perf events: {}",
                    failures.join("; ")
                )
            }
            Self::Timeout => formatter.write_str("CPU sampling timed out"),
            Self::NoThreadsAttached { skipped_threads } => write!(
                formatter,
                "no target threads remained attachable; exited threads: {skipped_threads:?}"
            ),
        }
    }
}

impl Error for CpuSamplingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Ring { source, .. } | Self::Arm { source, .. } => {
                Some(source)
            }
            Self::InvalidRequest(_)
            | Self::Cleanup { .. }
            | Self::Timeout
            | Self::NoThreadsAttached { .. } => None,
        }
    }
}

struct ThreadSampler {
    thread_id: u32,
    counter: Counter,
    sampler: Sampler,
}

/// Collect bounded user-space CPU call chains from a fixed target thread snapshot.
///
/// # Errors
///
/// Returns [`CpuSamplingError`] for invalid bounds, perf setup failures, timeout,
/// or deterministic cleanup failures.
pub fn collect(request: &CpuSamplingRequest) -> Result<CpuSampleCapture, CpuSamplingError> {
    validate_request(request)?;
    let started = Instant::now();
    let deadline = started
        .checked_add(request.timeout)
        .ok_or(CpuSamplingError::InvalidRequest(
            "timeout overflows the monotonic clock",
        ))?;
    let observed = request.thread_ids.len();
    let selected = request.thread_ids.iter().copied().take(request.max_threads);
    let mut skipped_threads = request
        .thread_ids
        .iter()
        .copied()
        .skip(request.max_threads)
        .collect::<Vec<_>>();
    let opts = sampling_options(request);
    let mut samplers = Vec::new();

    for thread_id in selected {
        if Instant::now() >= deadline {
            return Err(CpuSamplingError::Timeout);
        }
        let counter = match Counter::new(Software::CpuClock, (Proc(thread_id), Cpu::ALL), &opts) {
            Ok(counter) => counter,
            Err(source) if source.raw_os_error() == Some(ESRCH) => {
                skipped_threads.push(thread_id);
                continue;
            }
            Err(source) => return Err(CpuSamplingError::Open { thread_id, source }),
        };
        let sampler = counter
            .sampler(RING_PAGE_EXPONENT)
            .map_err(|source| CpuSamplingError::Ring { thread_id, source })?;
        samplers.push(ThreadSampler {
            thread_id,
            counter,
            sampler,
        });
    }
    if samplers.is_empty() {
        return Err(CpuSamplingError::NoThreadsAttached { skipped_threads });
    }

    arm_all(&samplers)?;
    let capture_started = Instant::now();
    let capture_deadline =
        capture_started
            .checked_add(request.duration)
            .ok_or(CpuSamplingError::InvalidRequest(
                "duration overflows the monotonic clock",
            ))?;
    let mut capture = CpuSampleCapture {
        stacks: Vec::with_capacity(request.max_samples.min(4096)),
        observed_samples: 0,
        lost_samples: 0,
        truncated_stacks: 0,
        throttled_records: 0,
        threads_observed: observed,
        threads_attached: samplers.len(),
        skipped_threads,
        capacity_reached: false,
        elapsed: Duration::ZERO,
    };

    while Instant::now() < capture_deadline && capture.observed_samples < request.max_samples as u64
    {
        if Instant::now() >= deadline {
            disable_all(&samplers)?;
            return Err(CpuSamplingError::Timeout);
        }
        drain(&samplers, request, &mut capture);
        let now = Instant::now();
        if now < capture_deadline && capture.observed_samples < request.max_samples as u64 {
            thread::sleep(DRAIN_INTERVAL.min(capture_deadline.duration_since(now)));
        }
    }

    disable_all(&samplers)?;
    drain(&samplers, request, &mut capture);
    capture.capacity_reached = capture.observed_samples >= request.max_samples as u64;
    capture.elapsed = capture_started.elapsed();
    Ok(capture)
}

fn validate_request(request: &CpuSamplingRequest) -> Result<(), CpuSamplingError> {
    if request.thread_ids.is_empty() {
        return Err(CpuSamplingError::InvalidRequest(
            "thread_ids must not be empty",
        ));
    }
    if request.frequency_hz == 0 {
        return Err(CpuSamplingError::InvalidRequest(
            "frequency_hz must be positive",
        ));
    }
    if request.duration.is_zero() {
        return Err(CpuSamplingError::InvalidRequest(
            "duration must be positive",
        ));
    }
    if request.timeout < request.duration {
        return Err(CpuSamplingError::InvalidRequest(
            "timeout must be at least the capture duration",
        ));
    }
    if request.max_samples == 0 {
        return Err(CpuSamplingError::InvalidRequest(
            "max_samples must be positive",
        ));
    }
    if request.max_threads == 0 {
        return Err(CpuSamplingError::InvalidRequest(
            "max_threads must be positive",
        ));
    }
    if request.stack_depth == 0 {
        return Err(CpuSamplingError::InvalidRequest(
            "stack_depth must be positive",
        ));
    }
    Ok(())
}

fn sampling_options(request: &CpuSamplingRequest) -> Opts {
    let mut opts = Opts {
        sample_on: SampleOn::Freq(request.frequency_hz),
        exclude: ExcludedPriv {
            kernel: true,
            hv: true,
            host: false,
            guest: true,
            idle: true,
            user: false,
        },
        ..Opts::default()
    };
    opts.sample_format.code_addr = true;
    opts.sample_format.call_chain = Some(CallChainConfig {
        exclude_user: false,
        exclude_kernel: true,
        defer_user: false,
        max_stack_frames: request.stack_depth,
    });
    opts
}

fn arm_all(samplers: &[ThreadSampler]) -> Result<(), CpuSamplingError> {
    for (index, sampler) in samplers.iter().enumerate() {
        if let Err(source) = sampler.counter.enable() {
            let mut cleanup = disable_subset(&samplers[..index]);
            if cleanup.is_empty() {
                return Err(CpuSamplingError::Arm {
                    thread_id: sampler.thread_id,
                    source,
                });
            }
            cleanup.push(format!(
                "original enable failure for thread {}: {source}",
                sampler.thread_id
            ));
            return Err(CpuSamplingError::Cleanup { failures: cleanup });
        }
    }
    Ok(())
}

fn disable_all(samplers: &[ThreadSampler]) -> Result<(), CpuSamplingError> {
    let failures = disable_subset(samplers);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(CpuSamplingError::Cleanup { failures })
    }
}

fn disable_subset(samplers: &[ThreadSampler]) -> Vec<String> {
    samplers
        .iter()
        .filter_map(|sampler| {
            sampler
                .counter
                .disable()
                .err()
                .map(|error| format!("thread {}: {error}", sampler.thread_id))
        })
        .collect()
}

fn drain(samplers: &[ThreadSampler], request: &CpuSamplingRequest, capture: &mut CpuSampleCapture) {
    for sampler in samplers {
        for (_, record) in sampler.sampler.iter() {
            match record {
                Record::Sample(sample) if capture.observed_samples < request.max_samples as u64 => {
                    capture.observed_samples += 1;
                    if let Some((addresses, truncated)) =
                        user_addresses(&sample, request.stack_depth)
                    {
                        capture.truncated_stacks += u64::from(truncated);
                        capture.stacks.push(RawCpuStack {
                            thread_id: sampler.thread_id,
                            addresses,
                        });
                    }
                }
                Record::Sample(_) => {
                    capture.capacity_reached = true;
                    return;
                }
                Record::LostRecords(lost) => {
                    capture.lost_samples = capture.lost_samples.saturating_add(lost.lost_records);
                }
                Record::LostSamples(lost) => {
                    capture.lost_samples = capture.lost_samples.saturating_add(lost.lost_samples);
                }
                Record::Throttle(_) => {
                    capture.throttled_records = capture.throttled_records.saturating_add(1);
                }
                _ => {}
            }
            if capture.observed_samples >= request.max_samples as u64 {
                capture.capacity_reached = true;
                return;
            }
        }
    }
}

fn user_addresses(
    sample: &perf_event_open::sample::record::sample::Sample,
    stack_depth: u16,
) -> Option<(Vec<u64>, bool)> {
    let mut addresses = sample
        .call_chain
        .as_ref()
        .and_then(|chains| {
            chains.iter().find_map(|chain| match chain {
                CallChain::User(addresses) => Some(addresses.clone()),
                _ => None,
            })
        })
        .unwrap_or_default();
    if addresses.is_empty() {
        addresses.extend(sample.code_addr.map(|(address, _)| address));
    }
    addresses.retain(|address| *address != 0);
    let truncated = addresses.len() >= usize::from(stack_depth);
    addresses.truncate(usize::from(stack_depth));
    (!addresses.is_empty()).then_some((addresses, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> CpuSamplingRequest {
        CpuSamplingRequest {
            thread_ids: vec![1],
            frequency_hz: 99,
            duration: Duration::from_millis(10),
            timeout: Duration::from_millis(20),
            max_samples: 100,
            max_threads: 8,
            stack_depth: 64,
        }
    }

    #[test]
    fn rejects_zero_resource_bounds() {
        let mut value = request();
        value.max_samples = 0;
        assert!(matches!(
            validate_request(&value),
            Err(CpuSamplingError::InvalidRequest(_))
        ));

        value = request();
        value.stack_depth = 0;
        assert!(matches!(
            validate_request(&value),
            Err(CpuSamplingError::InvalidRequest(_))
        ));
    }

    #[test]
    fn rejects_a_timeout_shorter_than_capture() {
        let mut value = request();
        value.timeout = Duration::from_millis(9);
        assert!(matches!(
            validate_request(&value),
            Err(CpuSamplingError::InvalidRequest(_))
        ));
    }
}
