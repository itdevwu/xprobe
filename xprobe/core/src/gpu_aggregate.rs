//! Deterministic normalization of bounded CUPTI aggregate captures.

use std::{error::Error, fmt};

use xprobe_protocol::{
    AggregateActivity, AggregateCollectionSummary, AggregateDuration, AggregateGroup,
    AggregateInventory, AggregateInventoryResult, CaptureCompleteness, ErrorCode, MemcpyKind,
    MemoryKind, SchemaVersion3, SessionStatus,
};

/// One Agent aggregate table slot. Several slots may describe the same group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawGpuAggregateGroup {
    pub activity: AggregateActivity,
    pub name: Option<String>,
    pub name_complete: Option<bool>,
    pub device_id: Option<u32>,
    pub memcpy_kind: Option<MemcpyKind>,
    pub src_memory: Option<MemoryKind>,
    pub dst_memory: Option<MemoryKind>,
    pub count: u64,
    pub total_duration_ns: u64,
    pub min_duration_ns: u64,
    pub max_duration_ns: u64,
    pub total_bytes: Option<u64>,
}

/// A completed aggregate capture whose collector lifecycle was already checked.
#[derive(Debug, Clone)]
pub struct GpuAggregateCapture {
    pub groups: Vec<RawGpuAggregateGroup>,
    pub observed_activities: u64,
    pub group_capacity: u64,
}

/// Identity of the inventory request echoed into the result.
#[derive(Debug, Clone)]
pub struct GpuAggregateRequest {
    pub session_id: String,
    pub name: Option<String>,
    pub start_selector: String,
    pub end_selector: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpuAggregateError {
    CountOverflow,
    DurationOverflow,
    ByteOverflow,
    InconsistentBytes,
    InconsistentActivityCount { grouped: u64, observed: u64 },
    UnnamedKernel,
    EmptyGroup,
}

impl GpuAggregateError {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::TraceExportFailed
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        false
    }
}

impl fmt::Display for GpuAggregateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CountOverflow => formatter.write_str("aggregate activity count overflowed"),
            Self::DurationOverflow => formatter.write_str("aggregate duration overflowed"),
            Self::ByteOverflow => formatter.write_str("aggregate byte count overflowed"),
            Self::InconsistentBytes => {
                formatter.write_str("aggregate byte counters are inconsistent")
            }
            Self::InconsistentActivityCount { grouped, observed } => write!(
                formatter,
                "aggregate activity counters are inconsistent: grouped={grouped}, observed={observed}"
            ),
            Self::UnnamedKernel => formatter.write_str("aggregate kernel group has no name"),
            Self::EmptyGroup => formatter.write_str("aggregate group has zero activities"),
        }
    }
}

impl Error for GpuAggregateError {}

/// Merge Agent aggregate slots into deterministic groups with selector hints.
///
/// # Errors
///
/// Returns [`GpuAggregateError`] when counters overflow, disagree with the
/// observed activity count, or describe a malformed group.
pub fn analyze(
    request: GpuAggregateRequest,
    capture: GpuAggregateCapture,
) -> Result<AggregateInventoryResult, GpuAggregateError> {
    let occupied_slots =
        u64::try_from(capture.groups.len()).map_err(|_| GpuAggregateError::CountOverflow)?;
    let groups = merge_groups(capture.groups)?;
    let grouped_activities = groups.iter().try_fold(0_u64, |total, group| {
        total
            .checked_add(group.count)
            .ok_or(GpuAggregateError::CountOverflow)
    })?;
    if grouped_activities != capture.observed_activities {
        return Err(GpuAggregateError::InconsistentActivityCount {
            grouped: grouped_activities,
            observed: capture.observed_activities,
        });
    }
    let distinct_groups =
        u64::try_from(groups.len()).map_err(|_| GpuAggregateError::CountOverflow)?;
    let groups = groups
        .into_iter()
        .map(protocol_group)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AggregateInventoryResult {
        schema_version: SchemaVersion3::current(),
        ok: true,
        session_id: request.session_id,
        status: SessionStatus::Completed,
        inventory: AggregateInventory {
            name: request.name,
            start_selector: request.start_selector,
            end_selector: request.end_selector,
            groups,
        },
        collection: AggregateCollectionSummary {
            completeness: CaptureCompleteness::Complete,
            observed_activities: capture.observed_activities,
            grouped_activities,
            dropped_activities: 0,
            group_capacity: capture.group_capacity,
            groups: distinct_groups,
            occupied_slots,
            table_utilization: utilization(occupied_slots, capture.group_capacity),
        },
        warnings: Vec::new(),
    })
}

fn merge_groups(
    mut groups: Vec<RawGpuAggregateGroup>,
) -> Result<Vec<RawGpuAggregateGroup>, GpuAggregateError> {
    groups.sort_by(|left, right| {
        activity_rank(left.activity)
            .cmp(&activity_rank(right.activity))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.device_id.cmp(&right.device_id))
            .then_with(|| {
                memcpy_kind_rank(left.memcpy_kind.as_ref())
                    .cmp(&memcpy_kind_rank(right.memcpy_kind.as_ref()))
            })
            .then_with(|| left.src_memory.cmp(&right.src_memory))
            .then_with(|| left.dst_memory.cmp(&right.dst_memory))
    });
    let mut merged: Vec<RawGpuAggregateGroup> = Vec::with_capacity(groups.len());
    for group in groups {
        let Some(previous) = merged.last_mut() else {
            merged.push(group);
            continue;
        };
        if previous.activity != group.activity
            || previous.name != group.name
            || previous.device_id != group.device_id
            || previous.memcpy_kind != group.memcpy_kind
            || previous.src_memory != group.src_memory
            || previous.dst_memory != group.dst_memory
        {
            merged.push(group);
            continue;
        }
        previous.count = previous
            .count
            .checked_add(group.count)
            .ok_or(GpuAggregateError::CountOverflow)?;
        previous.total_duration_ns = previous
            .total_duration_ns
            .checked_add(group.total_duration_ns)
            .ok_or(GpuAggregateError::DurationOverflow)?;
        previous.min_duration_ns = previous.min_duration_ns.min(group.min_duration_ns);
        previous.max_duration_ns = previous.max_duration_ns.max(group.max_duration_ns);
        previous.total_bytes = match (previous.total_bytes, group.total_bytes) {
            (Some(left), Some(right)) => Some(
                left.checked_add(right)
                    .ok_or(GpuAggregateError::ByteOverflow)?,
            ),
            (None, None) => None,
            _ => return Err(GpuAggregateError::InconsistentBytes),
        };
    }
    Ok(merged)
}

const fn activity_rank(activity: AggregateActivity) -> u8 {
    match activity {
        AggregateActivity::Kernel => 0,
        AggregateActivity::Memcpy => 1,
        AggregateActivity::Memset => 2,
    }
}

const fn memcpy_kind_rank(kind: Option<&MemcpyKind>) -> u8 {
    match kind {
        None => 0,
        Some(&MemcpyKind::Unknown) => 1,
        Some(&MemcpyKind::HostToDevice) => 2,
        Some(&MemcpyKind::DeviceToHost) => 3,
        Some(&MemcpyKind::DeviceToDevice) => 4,
        Some(&MemcpyKind::HostToHost) => 5,
        Some(&MemcpyKind::PeerToPeer) => 6,
    }
}

#[allow(clippy::cast_precision_loss)]
fn protocol_group(group: RawGpuAggregateGroup) -> Result<AggregateGroup, GpuAggregateError> {
    if group.count == 0 {
        return Err(GpuAggregateError::EmptyGroup);
    }
    let (start_selector_hint, end_selector_hint) = selector_hints(&group)?;
    Ok(AggregateGroup {
        activity: group.activity,
        name: group.name,
        name_complete: group.name_complete,
        device_id: group.device_id,
        memcpy_kind: group.memcpy_kind,
        src_memory: group.src_memory,
        dst_memory: group.dst_memory,
        start_selector_hint,
        end_selector_hint,
        count: group.count,
        duration_ns: AggregateDuration {
            min: group.min_duration_ns,
            mean: group.total_duration_ns as f64 / group.count as f64,
            max: group.max_duration_ns,
            total: group.total_duration_ns,
        },
        total_bytes: group.total_bytes,
    })
}

fn selector_hints(group: &RawGpuAggregateGroup) -> Result<(String, String), GpuAggregateError> {
    Ok(match group.activity {
        AggregateActivity::Kernel => {
            let name = group
                .name
                .as_deref()
                .ok_or(GpuAggregateError::UnnamedKernel)?;
            let escaped = escape_selector_regex(name);
            let suffix = if group.name_complete == Some(true) {
                "$"
            } else {
                ""
            };
            (
                format!("cuda:kernel_start:name~^{escaped}{suffix}"),
                format!("cuda:kernel_end:name~^{escaped}{suffix}"),
            )
        }
        AggregateActivity::Memcpy => {
            let kind = match group.memcpy_kind.as_ref() {
                Some(MemcpyKind::HostToDevice) => Some("HtoD"),
                Some(MemcpyKind::DeviceToHost) => Some("DtoH"),
                Some(MemcpyKind::DeviceToDevice) => Some("DtoD"),
                Some(MemcpyKind::HostToHost) => Some("HtoH"),
                Some(MemcpyKind::PeerToPeer) => Some("PtoP"),
                Some(MemcpyKind::Unknown) | None => None,
            };
            kind.map_or_else(
                || ("cuda:memcpy_start".to_owned(), "cuda:memcpy_end".to_owned()),
                |kind| {
                    (
                        format!("cuda:memcpy_start:kind={kind}"),
                        format!("cuda:memcpy_end:kind={kind}"),
                    )
                },
            )
        }
        AggregateActivity::Memset => ("cuda:memset_start".to_owned(), "cuda:memset_end".to_owned()),
    })
}

fn escape_selector_regex(name: &str) -> String {
    let mut escaped = String::with_capacity(name.len());
    for character in name.chars() {
        if "\\.^$|?*+()[]{}".contains(character) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

#[allow(clippy::cast_precision_loss)]
fn utilization(occupied: u64, capacity: u64) -> f64 {
    if capacity == 0 {
        0.0
    } else {
        occupied as f64 / capacity as f64
    }
}

#[cfg(test)]
mod tests {
    use xprobe_protocol::{AggregateActivity, MemcpyKind, MemoryKind};

    use super::{
        GpuAggregateCapture, GpuAggregateError, GpuAggregateRequest, RawGpuAggregateGroup, analyze,
        selector_hints,
    };

    fn kernel(name: &str, complete: bool, count: u64, total: u64) -> RawGpuAggregateGroup {
        RawGpuAggregateGroup {
            activity: AggregateActivity::Kernel,
            name: Some(name.to_owned()),
            name_complete: Some(complete),
            device_id: Some(0),
            memcpy_kind: None,
            src_memory: None,
            dst_memory: None,
            count,
            total_duration_ns: total,
            min_duration_ns: total / count,
            max_duration_ns: total / count,
            total_bytes: None,
        }
    }

    fn memcpy(kind: MemcpyKind, count: u64, bytes: Option<u64>) -> RawGpuAggregateGroup {
        RawGpuAggregateGroup {
            activity: AggregateActivity::Memcpy,
            name: None,
            name_complete: None,
            device_id: Some(0),
            memcpy_kind: Some(kind),
            src_memory: None,
            dst_memory: None,
            count,
            total_duration_ns: 10 * count,
            min_duration_ns: 10,
            max_duration_ns: 10,
            total_bytes: bytes,
        }
    }

    fn request() -> GpuAggregateRequest {
        GpuAggregateRequest {
            session_id: "s".to_owned(),
            name: None,
            start_selector: "cuda:kernel_start".to_owned(),
            end_selector: "cuda:kernel_end".to_owned(),
        }
    }

    #[test]
    fn merges_duplicate_slots_deterministically() {
        let capture = GpuAggregateCapture {
            groups: vec![
                memcpy(MemcpyKind::HostToDevice, 1, Some(64)),
                kernel("b", true, 2, 40),
                kernel("a", true, 1, 10),
                kernel("b", true, 1, 50),
            ],
            observed_activities: 5,
            group_capacity: 8,
        };
        let result = analyze(request(), capture).expect("consistent capture");
        let groups = &result.inventory.groups;
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].name.as_deref(), Some("a"));
        assert_eq!(groups[1].name.as_deref(), Some("b"));
        assert_eq!(groups[1].count, 3);
        assert_eq!(groups[1].duration_ns.total, 90);
        assert_eq!(groups[1].duration_ns.min, 20);
        assert_eq!(groups[1].duration_ns.max, 50);
        assert_eq!(groups[2].activity, AggregateActivity::Memcpy);
        assert_eq!(groups[2].start_selector_hint, "cuda:memcpy_start:kind=HtoD");
        assert_eq!(result.collection.groups, 3);
        assert_eq!(result.collection.occupied_slots, 4);
        assert!((result.collection.table_utilization - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn keeps_pageable_and_pinned_copies_apart() {
        let mut pageable = memcpy(MemcpyKind::HostToDevice, 2, Some(64));
        pageable.src_memory = Some(MemoryKind::Pageable);
        pageable.dst_memory = Some(MemoryKind::Device);
        let mut pinned = pageable.clone();
        pinned.src_memory = Some(MemoryKind::Pinned);
        let capture = GpuAggregateCapture {
            groups: vec![pinned, pageable.clone(), pageable],
            observed_activities: 6,
            group_capacity: 8,
        };
        let groups = analyze(request(), capture).unwrap().inventory.groups;
        let kinds = groups
            .iter()
            .map(|group| (group.src_memory, group.count))
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            [
                (Some(MemoryKind::Pageable), 4),
                (Some(MemoryKind::Pinned), 2)
            ]
        );
    }

    #[test]
    fn rejects_inconsistent_counters() {
        let capture = GpuAggregateCapture {
            groups: vec![kernel("a", true, 2, 20)],
            observed_activities: 3,
            group_capacity: 8,
        };
        assert_eq!(
            analyze(request(), capture),
            Err(GpuAggregateError::InconsistentActivityCount {
                grouped: 2,
                observed: 3
            })
        );

        let capture = GpuAggregateCapture {
            groups: vec![
                memcpy(MemcpyKind::DeviceToHost, 1, Some(8)),
                memcpy(MemcpyKind::DeviceToHost, 1, None),
            ],
            observed_activities: 2,
            group_capacity: 8,
        };
        assert_eq!(
            analyze(request(), capture),
            Err(GpuAggregateError::InconsistentBytes)
        );
    }

    #[test]
    fn rejects_malformed_groups_instead_of_panicking() {
        let mut unnamed = kernel("a", true, 1, 10);
        unnamed.name = None;
        let capture = GpuAggregateCapture {
            groups: vec![unnamed],
            observed_activities: 1,
            group_capacity: 8,
        };
        assert_eq!(
            analyze(request(), capture),
            Err(GpuAggregateError::UnnamedKernel)
        );

        let mut empty = kernel("a", true, 1, 10);
        empty.count = 0;
        let capture = GpuAggregateCapture {
            groups: vec![empty],
            observed_activities: 0,
            group_capacity: 8,
        };
        assert_eq!(
            analyze(request(), capture),
            Err(GpuAggregateError::EmptyGroup)
        );
    }

    #[test]
    fn hints_escape_names_and_use_prefixes_for_incomplete_names() {
        assert_eq!(
            selector_hints(&kernel("long_kernel_prefix", false, 1, 10)),
            Ok((
                "cuda:kernel_start:name~^long_kernel_prefix".to_owned(),
                "cuda:kernel_end:name~^long_kernel_prefix".to_owned(),
            ))
        );
        assert_eq!(
            selector_hints(&kernel("void k<1>(float*)", true, 1, 10)),
            Ok((
                "cuda:kernel_start:name~^void k<1>\\(float\\*\\)$".to_owned(),
                "cuda:kernel_end:name~^void k<1>\\(float\\*\\)$".to_owned(),
            ))
        );
    }
}
