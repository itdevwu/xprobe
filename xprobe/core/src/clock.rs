//! Host clock readings shared with captured event timestamps.

use nix::time::{ClockId, clock_gettime};

/// Current `CLOCK_MONOTONIC` time in nanoseconds, the clock host events and
/// normalized CUPTI timestamps use.
///
/// # Errors
///
/// Returns the `clock_gettime` failure.
pub fn monotonic_ns() -> Result<u64, nix::Error> {
    let now = clock_gettime(ClockId::CLOCK_MONOTONIC)?;
    // CLOCK_MONOTONIC is non-negative and fits u64 nanoseconds for centuries.
    let seconds = u64::try_from(now.tv_sec()).map_err(|_| nix::Error::EOVERFLOW)?;
    let nanoseconds = u64::try_from(now.tv_nsec()).map_err(|_| nix::Error::EOVERFLOW)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(nix::Error::EOVERFLOW)
}

#[cfg(test)]
mod tests {
    #[test]
    fn monotonic_time_advances() {
        let first = super::monotonic_ns().unwrap();
        let second = super::monotonic_ns().unwrap();
        assert!(first > 0 && second >= first);
    }
}
