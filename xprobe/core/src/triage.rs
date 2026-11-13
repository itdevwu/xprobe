//! Deterministic triage findings from one bounded window of evidence.
//!
//! Every rule reads already-collected summaries, estimates the share of the
//! window it accounts for, and proposes the next exact measurement or an
//! environment action. Shares are estimates; findings never claim causality.

use xprobe_protocol::{
    AggregateActivity, AggregateGroup, CgroupCpuThrottling, CpuHotspot, GpuDeviceHealth,
    MatchPolicy, MeasurementMode, MeasurementSpec, SchemaVersion, SyscallAggregateGroup,
    TargetIdentity, ThreadTimeBreakdown, TriageFinding, TriageNextKind, TriageNextStep,
};

/// Throttled time at or above this share of the window is reported.
pub const THROTTLED_SHARE: f64 = 0.02;
/// Runnable-but-waiting share of the busiest thread that is reported.
pub const RUNQUEUE_SHARE: f64 = 0.10;
/// On-CPU share of the busiest thread before hotspots are attributed.
pub const ON_CPU_SHARE: f64 = 0.30;
/// Minimum exclusive sample share for a hotspot finding.
pub const HOTSPOT_SHARE: f64 = 0.05;
/// Blocked share of the busiest thread that is reported.
pub const BLOCKED_SHARE: f64 = 0.50;
/// Summed syscall duration share of the window that is reported.
pub const SYSCALL_SHARE: f64 = 0.10;
/// Mean NVML utilization below which a GPU-using target is underutilized.
pub const GPU_BUSY_PCT: f64 = 50.0;
/// Samples requested by proposed exact measurements.
pub const NEXT_SAMPLES: u64 = 100;

const SLOWDOWN_REASONS: [&str; 5] = [
    "sw_power_cap",
    "hw_slowdown",
    "sw_thermal_slowdown",
    "hw_thermal_slowdown",
    "hw_power_brake_slowdown",
];

/// Collected triage evidence. Absent sources are `None` or empty.
#[derive(Debug, Clone, Copy)]
pub struct TriageEvidence<'a> {
    pub target: &'a TargetIdentity,
    pub threads: &'a ThreadTimeBreakdown,
    pub cgroup: Option<&'a CgroupCpuThrottling>,
    pub cpu_hotspots: &'a [CpuHotspot],
    pub syscalls: &'a [SyscallAggregateGroup],
    pub gpu_devices: &'a [GpuDeviceHealth],
    /// Present when CUDA activity was collected for the target.
    pub gpu_activity: Option<&'a [AggregateGroup]>,
}

/// Evaluate every rule and rank findings by estimated impact.
#[must_use]
pub fn findings(evidence: &TriageEvidence<'_>) -> Vec<TriageFinding> {
    let mut found = Vec::new();
    cgroup_throttled(evidence, &mut found);
    thread_rules(evidence, &mut found);
    syscall_time(evidence, &mut found);
    gpu_rules(evidence, &mut found);
    found.sort_by(|left, right| {
        right
            .impact_share
            .total_cmp(&left.impact_share)
            .then_with(|| left.code.cmp(&right.code))
    });
    for (rank, finding) in found.iter_mut().enumerate() {
        finding.rank = u32::try_from(rank + 1).unwrap_or(u32::MAX);
    }
    found
}

#[allow(clippy::cast_precision_loss)]
fn window_share(value_ns: u64, window_ns: u64) -> f64 {
    if window_ns == 0 {
        0.0
    } else {
        (value_ns as f64 / window_ns as f64).min(1.0)
    }
}

fn percent(share: f64) -> String {
    format!("{:.0}%", share * 100.0)
}

fn finding(
    code: &str,
    impact_share: f64,
    summary: String,
    next: Option<TriageNextStep>,
) -> TriageFinding {
    TriageFinding {
        rank: 0,
        code: code.to_owned(),
        impact_share: impact_share.clamp(0.0, 1.0),
        summary,
        next,
    }
}

fn environment(description: String) -> TriageNextStep {
    TriageNextStep {
        kind: TriageNextKind::Environment,
        description,
        spec: None,
    }
}

fn measure(
    target: &TargetIdentity,
    name: &str,
    from: &str,
    to: &str,
    policy: MatchPolicy,
    description: String,
) -> TriageNextStep {
    TriageNextStep {
        kind: TriageNextKind::Measure,
        description,
        spec: Some(MeasurementSpec {
            schema_version: SchemaVersion::current(),
            name: Some(name.to_owned()),
            target: target.clone(),
            start_selector: from.to_owned(),
            end_selector: to.to_owned(),
            match_policy: policy,
            samples: Some(NEXT_SAMPLES),
            duration_ms: None,
            timeout_ms: 30_000,
            max_events: Some(NEXT_SAMPLES * 4),
            measurement_mode: MeasurementMode::Exact,
            max_groups: None,
        }),
    }
}

fn cgroup_throttled(evidence: &TriageEvidence<'_>, found: &mut Vec<TriageFinding>) {
    let Some(cgroup) = evidence.cgroup else {
        return;
    };
    let share = window_share(cgroup.throttled_ns, evidence.threads.window_ns);
    if cgroup.throttled_periods == 0 || share < THROTTLED_SHARE {
        return;
    }
    let quota = cgroup.quota_cpus.map_or_else(
        || "its CPU quota".to_owned(),
        |cpus| format!("a {cpus:.2}-CPU quota"),
    );
    found.push(finding(
        "CGROUP_THROTTLED",
        share,
        format!(
            "cgroup {} was throttled by {quota} for {} of the window ({} periods)",
            cgroup.cgroup_path,
            percent(share),
            cgroup.throttled_periods
        ),
        Some(environment(
            "raise the CPU limit or reduce parallelism before profiling code".to_owned(),
        )),
    ));
}

fn thread_rules(evidence: &TriageEvidence<'_>, found: &mut Vec<TriageFinding>) {
    let Some(busiest) = evidence.threads.top_threads.first() else {
        return;
    };
    if busiest.runqueue_share >= RUNQUEUE_SHARE {
        found.push(finding(
            "RUNQUEUE_WAIT",
            busiest.runqueue_share,
            format!(
                "busiest thread {} ({}) was runnable but waiting for a CPU {} of the window",
                busiest.tid,
                busiest.name,
                percent(busiest.runqueue_share)
            ),
            Some(environment(
                "check CPU oversubscription, affinity, and competing workloads on the host"
                    .to_owned(),
            )),
        ));
    }
    if busiest.on_cpu_share >= ON_CPU_SHARE {
        let hotspot = evidence
            .cpu_hotspots
            .iter()
            .filter(|hotspot| hotspot.exclusive_proportion >= HOTSPOT_SHARE)
            .max_by(|left, right| {
                left.exclusive_proportion
                    .total_cmp(&right.exclusive_proportion)
            });
        if let Some(hotspot) = hotspot {
            let symbol = hotspot
                .frame
                .symbol
                .as_deref()
                .unwrap_or("an unresolved frame");
            let impact = busiest.on_cpu_share * hotspot.exclusive_proportion;
            let next = match (&hotspot.entry_selector_hint, &hotspot.return_selector_hint) {
                (Some(entry), Some(exit)) => Some(measure(
                    evidence.target,
                    "hotspot_duration",
                    entry,
                    exit,
                    MatchPolicy::StackNested,
                    format!("measure each call of {symbol}"),
                )),
                _ => None,
            };
            found.push(finding(
                "CPU_HOTSPOT",
                impact,
                format!(
                    "busiest thread {} was on CPU {} of the window; {symbol} holds {} of sampled stacks exclusively (sampled estimate)",
                    busiest.tid,
                    percent(busiest.on_cpu_share),
                    percent(hotspot.exclusive_proportion)
                ),
                next,
            ));
        }
    }
    if busiest.blocked_share >= BLOCKED_SHARE {
        let next = top_syscall(evidence).and_then(|(group, share)| {
            (share >= SYSCALL_SHARE)
                .then(|| syscall_next(evidence, group))
                .flatten()
        });
        found.push(finding(
            "THREAD_BLOCKED",
            busiest.blocked_share,
            format!(
                "busiest thread {} ({}) was blocked {} of the window; where it waits needs off-CPU stacks, which this triage does not collect",
                busiest.tid,
                busiest.name,
                percent(busiest.blocked_share)
            ),
            next,
        ));
    }
}

fn top_syscall<'a>(evidence: &TriageEvidence<'a>) -> Option<(&'a SyscallAggregateGroup, f64)> {
    evidence
        .syscalls
        .iter()
        .max_by_key(|group| group.duration_ns.total)
        .map(|group| {
            (
                group,
                window_share(group.duration_ns.total, evidence.threads.window_ns),
            )
        })
}

fn syscall_next(
    evidence: &TriageEvidence<'_>,
    group: &SyscallAggregateGroup,
) -> Option<TriageNextStep> {
    let (Some(entry), Some(exit)) = (&group.entry_selector_hint, &group.exit_selector_hint) else {
        return None;
    };
    let name = group
        .syscall_name
        .clone()
        .unwrap_or_else(|| format!("syscall {}", group.syscall_number));
    Some(measure(
        evidence.target,
        "syscall_duration",
        entry,
        exit,
        MatchPolicy::Exact,
        format!("measure each {name} call"),
    ))
}

fn syscall_time(evidence: &TriageEvidence<'_>, found: &mut Vec<TriageFinding>) {
    let Some((group, share)) = top_syscall(evidence) else {
        return;
    };
    if share < SYSCALL_SHARE {
        return;
    }
    let name = group
        .syscall_name
        .clone()
        .unwrap_or_else(|| format!("syscall {}", group.syscall_number));
    found.push(finding(
        "SYSCALL_TIME",
        share,
        format!(
            "{name} accumulated {} of the window across {} calls ({} errors), summed over threads",
            percent(share),
            group.count,
            group.errors
        ),
        syscall_next(evidence, group),
    ));
}

#[allow(clippy::cast_precision_loss)]
fn gpu_rules(evidence: &TriageEvidence<'_>, found: &mut Vec<TriageFinding>) {
    let activity = evidence.gpu_activity;
    for device in evidence.gpu_devices {
        let Some(mean) = device.utilization_mean_pct else {
            continue;
        };
        let loaded = device.utilization_max_pct.is_some_and(|max| max > 0);
        let uses_gpu = activity.is_some_and(|groups| !groups.is_empty());
        if uses_gpu && mean < GPU_BUSY_PCT {
            found.push(finding(
                "GPU_UNDERUTILIZED",
                1.0 - mean / 100.0,
                format!(
                    "GPU {} was busy {mean:.0}% of sampled time (device-wide NVML estimate) while the target submitted work; CPU-side or launch-bound time likely limits it",
                    device.index
                ),
                Some(measure(
                    evidence.target,
                    "launch_to_kernel",
                    "cuda:runtime_api:cudaLaunchKernel:exit",
                    "cuda:kernel_start",
                    MatchPolicy::Exact,
                    "measure launch-to-kernel latency for each launch".to_owned(),
                )),
            ));
        }
        if uses_gpu && mean >= GPU_BUSY_PCT {
            kernel_dominant(evidence, device, mean, activity.unwrap_or_default(), found);
        }
        let slowdowns = device
            .clock_event_reasons
            .iter()
            .filter(|reason| SLOWDOWN_REASONS.contains(&reason.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if loaded && !slowdowns.is_empty() {
            found.push(finding(
                "GPU_CLOCK_LIMITED",
                mean / 100.0,
                format!(
                    "GPU {} reported clock slowdowns under load: {}",
                    device.index,
                    slowdowns.join(", ")
                ),
                Some(environment(
                    "check cooling, power limits, and clock policy".to_owned(),
                )),
            ));
        }
        if let Some(link) = device.pcie.as_ref().filter(|link| {
            loaded && (link.width_min < link.width_max || link.generation_min < link.generation_max)
        }) {
            found.push(finding(
                "PCIE_LINK_REDUCED",
                0.0,
                format!(
                    "GPU {} PCIe link ran as low as gen {} x{} of gen {} x{}; idle power saving also lowers it, so compare against transfer measurements",
                    device.index,
                    link.generation_min,
                    link.width_min,
                    link.generation_max,
                    link.width_max
                ),
                None,
            ));
        }
    }
}

#[allow(clippy::cast_precision_loss)]
fn kernel_dominant(
    evidence: &TriageEvidence<'_>,
    device: &GpuDeviceHealth,
    mean: f64,
    groups: &[AggregateGroup],
    found: &mut Vec<TriageFinding>,
) {
    let kernels = groups
        .iter()
        .filter(|group| group.activity == AggregateActivity::Kernel)
        .collect::<Vec<_>>();
    let total = kernels
        .iter()
        .map(|group| group.duration_ns.total)
        .sum::<u64>();
    let Some(top) = kernels.iter().max_by_key(|group| group.duration_ns.total) else {
        return;
    };
    if total == 0 {
        return;
    }
    let kernel_share = top.duration_ns.total as f64 / total as f64;
    let name = top.name.as_deref().unwrap_or("an unnamed kernel");
    found.push(finding(
        "GPU_KERNEL_DOMINANT",
        mean / 100.0 * kernel_share,
        format!(
            "GPU {} was busy {mean:.0}% of sampled time; {name} is {} of summed kernel time over {} launches",
            device.index,
            percent(kernel_share),
            top.count
        ),
        Some(measure(
            evidence.target,
            "kernel_duration",
            &top.start_selector_hint,
            &top.end_selector_hint,
            MatchPolicy::Exact,
            format!("measure each {name} execution"),
        )),
    ));
}

#[cfg(test)]
mod tests {
    use xprobe_protocol::{
        AggregateActivity, AggregateDuration, AggregateGroup, CgroupCpuThrottling, CgroupVersion,
        CpuFrameLanguage, CpuHotspot, CpuStackFrame, GpuDeviceHealth, MatchPolicy, PcieLink,
        SyscallAggregateGroup, TargetIdentity, ThreadTime, ThreadTimeBreakdown, TriageNextKind,
    };

    use super::{TriageEvidence, findings};

    const WINDOW: u64 = 1_000_000_000;

    fn thread(on_cpu: f64, runqueue: f64) -> ThreadTime {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let ns = |share: f64| (share * 1e9) as u64;
        ThreadTime {
            tid: 7,
            name: "worker".to_owned(),
            on_cpu_ns: ns(on_cpu),
            runqueue_ns: ns(runqueue),
            blocked_ns: ns(1.0 - on_cpu - runqueue),
            on_cpu_share: on_cpu,
            runqueue_share: runqueue,
            blocked_share: 1.0 - on_cpu - runqueue,
        }
    }

    fn threads(busiest: ThreadTime) -> ThreadTimeBreakdown {
        ThreadTimeBreakdown {
            window_ns: WINDOW,
            threads_observed: 1,
            threads_started: 0,
            threads_exited: 0,
            on_cpu_ns: busiest.on_cpu_ns,
            runqueue_ns: busiest.runqueue_ns,
            blocked_ns: busiest.blocked_ns,
            top_threads: vec![busiest],
        }
    }

    fn hotspot(symbol: &str, exclusive: f64) -> CpuHotspot {
        CpuHotspot {
            frame: CpuStackFrame {
                address: 0x1000,
                module_path: Some("/srv/app".to_owned()),
                build_id: None,
                file_offset: Some(0x1000),
                symbol: Some(symbol.to_owned()),
                symbol_offset: Some(0),
                language: CpuFrameLanguage::Native,
                source_path: None,
                line: None,
            },
            inclusive_samples: 10,
            exclusive_samples: 10,
            inclusive_proportion: exclusive,
            exclusive_proportion: exclusive,
            entry_selector_hint: Some(format!("uprobe:/srv/app:{symbol}:entry")),
            return_selector_hint: Some(format!("uprobe:/srv/app:{symbol}:return")),
        }
    }

    fn gpu(mean: f64, reasons: &[&str]) -> GpuDeviceHealth {
        GpuDeviceHealth {
            index: 0,
            uuid: "GPU-a".to_owned(),
            samples: 4,
            utilization_mean_pct: Some(mean),
            utilization_max_pct: Some(90),
            memory_utilization_mean_pct: Some(10.0),
            clock_event_reasons: reasons.iter().map(|reason| (*reason).to_owned()).collect(),
            temperature_max_c: Some(70),
            power_max_w: Some(80.0),
            pcie: Some(PcieLink {
                generation_min: 4,
                generation_max: 4,
                width_min: 16,
                width_max: 16,
            }),
        }
    }

    fn kernel(name: &str, total: u64) -> AggregateGroup {
        AggregateGroup {
            activity: AggregateActivity::Kernel,
            name: Some(name.to_owned()),
            name_complete: Some(true),
            device_id: Some(0),
            memcpy_kind: None,
            start_selector_hint: format!("cuda:kernel_start:name~^{name}$"),
            end_selector_hint: format!("cuda:kernel_end:name~^{name}$"),
            count: 10,
            duration_ns: AggregateDuration {
                min: 1,
                mean: 1.0,
                max: 1,
                total,
            },
            total_bytes: None,
        }
    }

    fn target() -> TargetIdentity {
        TargetIdentity {
            pid: 42,
            process_start_time: 9,
        }
    }

    #[test]
    fn cpu_bound_target_points_at_its_hotspot() {
        let target = target();
        let threads = threads(thread(0.9, 0.02));
        let hotspots = [hotspot("parse", 0.4), hotspot("hash", 0.03)];
        let evidence = TriageEvidence {
            target: &target,
            threads: &threads,
            cgroup: None,
            cpu_hotspots: &hotspots,
            syscalls: &[],
            gpu_devices: &[],
            gpu_activity: None,
        };
        let found = findings(&evidence);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].code, "CPU_HOTSPOT");
        assert_eq!(found[0].rank, 1);
        assert!((found[0].impact_share - 0.36).abs() < 1e-9);
        let spec = found[0].next.as_ref().unwrap().spec.as_ref().unwrap();
        assert_eq!(spec.start_selector, "uprobe:/srv/app:parse:entry");
        assert_eq!(spec.match_policy, MatchPolicy::StackNested);
        assert_eq!(spec.target, target);
    }

    #[test]
    fn ranks_throttling_runqueue_and_blocked_syscalls() {
        let target = target();
        let threads = threads(thread(0.05, 0.15));
        let cgroup = CgroupCpuThrottling {
            version: CgroupVersion::V2,
            cgroup_path: "/kubepods/x".to_owned(),
            quota_cpus: Some(0.5),
            periods: 10,
            throttled_periods: 6,
            throttled_ns: 300_000_000,
        };
        let syscalls = [SyscallAggregateGroup {
            syscall_number: 202,
            syscall_name: Some("futex".to_owned()),
            count: 900,
            errors: 3,
            duration_ns: AggregateDuration {
                min: 1,
                mean: 1.0,
                max: 1,
                total: 600_000_000,
            },
            entry_selector_hint: Some("syscall:futex:entry".to_owned()),
            exit_selector_hint: Some("syscall:futex:exit".to_owned()),
        }];
        let evidence = TriageEvidence {
            target: &target,
            threads: &threads,
            cgroup: Some(&cgroup),
            cpu_hotspots: &[],
            syscalls: &syscalls,
            gpu_devices: &[],
            gpu_activity: None,
        };
        let codes = findings(&evidence)
            .into_iter()
            .map(|finding| (finding.code, finding.next.map(|next| next.kind)))
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            [
                ("THREAD_BLOCKED".to_owned(), Some(TriageNextKind::Measure)),
                ("SYSCALL_TIME".to_owned(), Some(TriageNextKind::Measure)),
                (
                    "CGROUP_THROTTLED".to_owned(),
                    Some(TriageNextKind::Environment)
                ),
                (
                    "RUNQUEUE_WAIT".to_owned(),
                    Some(TriageNextKind::Environment)
                ),
            ]
        );
    }

    #[test]
    fn gpu_rules_need_target_activity_and_load() {
        let target = target();
        let threads = threads(thread(0.1, 0.0));
        let idle_gpu = [gpu(20.0, &["gpu_idle"])];
        let kernels = [kernel("gemm", 900), kernel("relu", 100)];
        let base = TriageEvidence {
            target: &target,
            threads: &threads,
            cgroup: None,
            cpu_hotspots: &[],
            syscalls: &[],
            gpu_devices: &idle_gpu,
            gpu_activity: None,
        };
        assert!(
            findings(&base)
                .iter()
                .all(|finding| !finding.code.starts_with("GPU"))
        );

        let underfed = TriageEvidence {
            gpu_activity: Some(&kernels),
            ..base
        };
        let found = findings(&underfed);
        assert!(
            found
                .iter()
                .any(|finding| finding.code == "GPU_UNDERUTILIZED")
        );

        let busy_gpu = [gpu(90.0, &["sw_thermal_slowdown"])];
        let busy = TriageEvidence {
            gpu_devices: &busy_gpu,
            gpu_activity: Some(&kernels),
            ..base
        };
        let found = findings(&busy);
        let dominant = found
            .iter()
            .find(|finding| finding.code == "GPU_KERNEL_DOMINANT")
            .unwrap();
        assert!((dominant.impact_share - 0.81).abs() < 1e-9);
        assert_eq!(
            dominant
                .next
                .as_ref()
                .unwrap()
                .spec
                .as_ref()
                .unwrap()
                .start_selector,
            "cuda:kernel_start:name~^gemm$"
        );
        assert!(
            found
                .iter()
                .any(|finding| finding.code == "GPU_CLOCK_LIMITED")
        );
    }
}
