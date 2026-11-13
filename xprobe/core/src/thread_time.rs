//! Per-thread on-CPU, runqueue, and blocked time from procfs `schedstat`.

use std::{collections::BTreeMap, fs, io, path::Path};

use xprobe_protocol::{ThreadTime, ThreadTimeBreakdown};

use crate::inspect::InspectError;

/// One thread's cumulative scheduler counters at a point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadCounters {
    pub tid: u32,
    /// procfs start time in clock ticks; distinguishes a reused TID.
    pub start_time: u64,
    pub name: String,
    pub cpu_ns: u64,
    pub runqueue_ns: u64,
}

/// Read every current thread of `pid`.
///
/// Threads that exit while being read are skipped; the caller's target
/// identity check covers the process itself.
///
/// # Errors
///
/// Returns [`InspectError`] when the task directory cannot be listed or a
/// present thread has malformed or unreadable counters.
pub fn snapshot(pid: u32) -> Result<Vec<ThreadCounters>, InspectError> {
    let task_dir = format!("/proc/{pid}/task");
    let entries = fs::read_dir(&task_dir).map_err(|source| match source.kind() {
        io::ErrorKind::NotFound => InspectError::TargetExited { pid },
        io::ErrorKind::PermissionDenied => InspectError::PermissionDenied {
            pid,
            path: task_dir.clone().into(),
        },
        _ => InspectError::Io {
            path: task_dir.clone().into(),
            source,
        },
    })?;
    let mut threads = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| InspectError::Io {
            path: task_dir.clone().into(),
            source,
        })?;
        let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        match read_thread(&entry.path(), tid) {
            Ok(Some(thread)) => threads.push(thread),
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }
    threads.sort_by_key(|thread| thread.tid);
    Ok(threads)
}

fn read_thread(dir: &Path, tid: u32) -> Result<Option<ThreadCounters>, InspectError> {
    let read = |entry: &str| -> Result<Option<String>, InspectError> {
        let path = dir.join(entry);
        match fs::read_to_string(&path) {
            Ok(text) => Ok(Some(text)),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(InspectError::Io { path, source }),
        }
    };
    let (Some(schedstat), Some(stat), Some(comm)) =
        (read("schedstat")?, read("stat")?, read("comm")?)
    else {
        return Ok(None);
    };
    let (cpu_ns, runqueue_ns) = parse_schedstat(&schedstat)
        .ok_or_else(|| malformed(dir, "schedstat", "expected three integer fields"))?;
    let start_time =
        parse_start_time(&stat).ok_or_else(|| malformed(dir, "stat", "missing start time"))?;
    Ok(Some(ThreadCounters {
        tid,
        start_time,
        name: comm.trim_end().to_owned(),
        cpu_ns,
        runqueue_ns,
    }))
}

fn malformed(dir: &Path, entry: &str, reason: &str) -> InspectError {
    InspectError::Io {
        path: dir.join(entry),
        source: io::Error::new(io::ErrorKind::InvalidData, reason.to_owned()),
    }
}

/// Parse `cpu_ns runqueue_ns timeslices` from a `schedstat` line.
fn parse_schedstat(text: &str) -> Option<(u64, u64)> {
    let mut fields = text.split_whitespace();
    let cpu = fields.next()?.parse().ok()?;
    let runqueue = fields.next()?.parse().ok()?;
    fields.next()?.parse::<u64>().ok()?;
    fields.next().is_none().then_some((cpu, runqueue))
}

/// Field 22 of `/proc/<pid>/task/<tid>/stat`, after the parenthesized name.
fn parse_start_time(stat: &str) -> Option<u64> {
    stat.get(stat.rfind(')')? + 1..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// Split each whole-window thread's time into on-CPU, runqueue, and blocked.
///
/// A thread counts as whole-window only when the same TID and start time
/// appear in both snapshots; others are counted as started or exited.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn breakdown(
    before: &[ThreadCounters],
    after: &[ThreadCounters],
    window_ns: u64,
    top: usize,
) -> ThreadTimeBreakdown {
    let key = |thread: &ThreadCounters| (thread.tid, thread.start_time);
    let earlier = before
        .iter()
        .map(|thread| (key(thread), thread))
        .collect::<BTreeMap<_, _>>();
    let later = after
        .iter()
        .map(|thread| (key(thread), thread))
        .collect::<BTreeMap<_, _>>();
    let mut threads = Vec::new();
    for (thread_key, end) in &later {
        let Some(start) = earlier.get(thread_key) else {
            continue;
        };
        let on_cpu_ns = end.cpu_ns.saturating_sub(start.cpu_ns).min(window_ns);
        let runqueue_ns = end
            .runqueue_ns
            .saturating_sub(start.runqueue_ns)
            .min(window_ns - on_cpu_ns);
        let blocked_ns = window_ns - on_cpu_ns - runqueue_ns;
        let share = |value: u64| {
            if window_ns == 0 {
                0.0
            } else {
                value as f64 / window_ns as f64
            }
        };
        threads.push(ThreadTime {
            tid: end.tid,
            name: end.name.clone(),
            on_cpu_ns,
            runqueue_ns,
            blocked_ns,
            on_cpu_share: share(on_cpu_ns),
            runqueue_share: share(runqueue_ns),
            blocked_share: share(blocked_ns),
        });
    }
    let observed = threads.len() as u64;
    let started = later
        .keys()
        .filter(|key| !earlier.contains_key(key))
        .count() as u64;
    let exited = earlier
        .keys()
        .filter(|key| !later.contains_key(key))
        .count() as u64;
    let on_cpu_ns = threads.iter().map(|thread| thread.on_cpu_ns).sum();
    let runqueue_ns = threads.iter().map(|thread| thread.runqueue_ns).sum();
    let blocked_ns = threads.iter().map(|thread| thread.blocked_ns).sum();
    threads.sort_by(|left, right| {
        (right.on_cpu_ns + right.runqueue_ns)
            .cmp(&(left.on_cpu_ns + left.runqueue_ns))
            .then(left.tid.cmp(&right.tid))
    });
    threads.truncate(top);
    ThreadTimeBreakdown {
        window_ns,
        threads_observed: observed,
        threads_started: started,
        threads_exited: exited,
        on_cpu_ns,
        runqueue_ns,
        blocked_ns,
        top_threads: threads,
    }
}

#[cfg(test)]
mod tests {
    use super::{ThreadCounters, breakdown, parse_schedstat, parse_start_time, snapshot};

    fn thread(tid: u32, start_time: u64, cpu_ns: u64, runqueue_ns: u64) -> ThreadCounters {
        ThreadCounters {
            tid,
            start_time,
            name: format!("t{tid}"),
            cpu_ns,
            runqueue_ns,
        }
    }

    #[test]
    fn parses_schedstat_and_stat_fields() {
        assert_eq!(
            parse_schedstat("23392057514 158397840 51596\n"),
            Some((23_392_057_514, 158_397_840))
        );
        assert_eq!(parse_schedstat("1 2"), None);
        assert_eq!(parse_schedstat("1 2 3 4"), None);
        let stat = "42 (a) b) S 1 42 42 0 -1 4194560 1 0 0 0 5 6 0 0 20 0 1 0 98765 1 2";
        assert_eq!(parse_start_time(stat), Some(98_765));
    }

    #[test]
    fn splits_whole_window_threads_and_counts_churn() {
        let before = [
            thread(1, 10, 1_000, 0),
            thread(2, 10, 0, 0),
            thread(3, 10, 0, 0),
            thread(4, 10, 0, 0),
        ];
        let after = [
            thread(1, 10, 701_000, 100_000),
            thread(2, 10, 100_000, 0),
            thread(3, 20, 5, 0),
            thread(5, 30, 5, 0),
        ];
        let split = breakdown(&before, &after, 1_000_000, 1);
        assert_eq!(split.threads_observed, 2);
        assert_eq!(split.threads_started, 2);
        assert_eq!(split.threads_exited, 2);
        assert_eq!(split.on_cpu_ns, 800_000);
        assert_eq!(split.runqueue_ns, 100_000);
        assert_eq!(split.blocked_ns, 1_100_000);
        assert_eq!(split.top_threads.len(), 1);
        let busiest = &split.top_threads[0];
        assert_eq!(
            (
                busiest.tid,
                busiest.on_cpu_ns,
                busiest.runqueue_ns,
                busiest.blocked_ns
            ),
            (1, 700_000, 100_000, 200_000)
        );
        assert!((busiest.blocked_share - 0.2).abs() < 1e-9);
    }

    #[test]
    fn clamps_counter_deltas_to_the_window() {
        let split = breakdown(&[thread(1, 1, 0, 0)], &[thread(1, 1, 900, 900)], 1_000, 4);
        let only = &split.top_threads[0];
        assert_eq!(
            (only.on_cpu_ns, only.runqueue_ns, only.blocked_ns),
            (900, 100, 0)
        );
    }

    #[test]
    fn reads_the_current_process() {
        let threads = snapshot(std::process::id()).expect("own threads are readable");
        assert!(
            threads
                .iter()
                .any(|thread| thread.tid == std::process::id())
        );
    }
}
