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

/// Reads of each clock pair; the tightest bracket is kept.
const ANCHOR_READS: usize = 5;

fn realtime_ns() -> Result<u64, nix::Error> {
    let now = clock_gettime(ClockId::CLOCK_REALTIME)?;
    let seconds = u64::try_from(now.tv_sec()).map_err(|_| nix::Error::EOVERFLOW)?;
    let nanoseconds = u64::try_from(now.tv_nsec()).map_err(|_| nix::Error::EOVERFLOW)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(nix::Error::EOVERFLOW)
}

/// `CLOCK_REALTIME` against `CLOCK_MONOTONIC`: the wall clock is read between
/// two monotonic reads, and the tightest of a few brackets is kept.
///
/// # Errors
///
/// Returns the `clock_gettime` failure.
pub fn clock_anchor() -> Result<xprobe_protocol::ClockAnchor, nix::Error> {
    let read = || -> Result<xprobe_protocol::ClockAnchor, nix::Error> {
        let before = monotonic_ns()?;
        let realtime = realtime_ns()?;
        let after = monotonic_ns()?;
        Ok(xprobe_protocol::ClockAnchor {
            monotonic_ns: before + (after - before) / 2,
            realtime_ns: realtime,
            uncertainty_ns: (after - before).div_ceil(2),
        })
    };
    let mut best = read()?;
    for _ in 1..ANCHOR_READS {
        let anchor = read()?;
        if anchor.uncertainty_ns < best.uncertainty_ns {
            best = anchor;
        }
    }
    Ok(best)
}

#[cfg(test)]
mod tests {
    #[test]
    fn anchors_pair_wall_time_with_monotonic_time() {
        let anchor = super::clock_anchor().unwrap();
        let later = super::monotonic_ns().unwrap();
        assert!(anchor.monotonic_ns <= later);
        // Some time after 2020 and a bracket well under a millisecond.
        assert!(anchor.realtime_ns > 1_577_836_800_000_000_000);
        assert!(anchor.uncertainty_ns < 1_000_000);
    }

    #[test]
    fn monotonic_time_advances() {
        let first = super::monotonic_ns().unwrap();
        let second = super::monotonic_ns().unwrap();
        assert!(first > 0 && second >= first);
    }
}
