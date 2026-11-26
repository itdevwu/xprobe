//! Triggered capture: keep a ring of recent GPU activity and write a window
//! around each span that crosses a threshold.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ClockDomain, EvidenceArtifact, MatchPolicy, MatchedEventPair, SchemaVersion3, SessionStatus,
    TargetIdentity, Warning,
};

/// What a trigger measures on each span it evaluates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    /// Idle time on a stream: an activity end to the next kernel, copy, or
    /// memset start on that stream.
    Gap,
    /// One kernel, copy, or memset from start to end.
    Duration,
    /// One edge between two selectors under a correlation policy.
    Latency,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriggerCondition {
    pub kind: TriggerKind,
    /// A span fires when it lasts at least this long.
    pub threshold_ns: u64,
    /// Edge selectors and policy of a latency trigger.
    pub start_selector: Option<String>,
    pub end_selector: Option<String>,
    pub match_policy: Option<MatchPolicy>,
    /// Context kept before the firing span's start and after its end.
    pub pre_ns: u64,
    pub post_ns: u64,
    /// Windows to write before stopping; later windows start after the
    /// previous one ends.
    pub windows: u32,
}

/// Result of `measure --trigger-*`, schema `3.0`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriggerResult {
    pub schema_version: SchemaVersion3,
    pub ok: bool,
    pub session_id: String,
    /// `completed` after every requested window; `timed_out` with fewer.
    pub status: SessionStatus,
    pub target: TargetIdentity,
    pub trigger: TriggerCondition,
    pub observed: TriggerObservation,
    pub windows: Vec<TriggerWindow>,
    pub collection: TriggerCollection,
    pub warnings: Vec<Warning>,
}

/// Every span evaluated while waiting, fired or not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriggerObservation {
    pub spans: u64,
    pub over_threshold: u64,
    /// The longest span seen, whether or not its window could be written.
    pub longest: Option<MatchedEventPair>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriggerWindow {
    pub index: u32,
    /// The span that crossed the threshold.
    pub fired: MatchedEventPair,
    /// Window bounds in the events' clock, clipped to what was captured.
    pub start_ns: u64,
    pub end_ns: u64,
    pub clock_domain: ClockDomain,
    /// The capture began after `pre_ns` before the span or ended before
    /// `post_ns` after it, so the window is shorter than requested.
    pub truncated: bool,
    /// The longest spans of the trigger's kind inside the window.
    pub longest: Vec<MatchedEventPair>,
    pub artifact: EvidenceArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriggerCollection {
    /// Agent ring and CLI retention bound, in records.
    pub ring_capacity: u64,
    pub observed_records: u64,
    /// Records the ring overwrote before they were read.
    pub overwritten_records: u64,
    pub dropped_records: u64,
    /// Windows discarded because records inside them were lost.
    pub lost_windows: u32,
    /// Windows discarded because their firing span no longer crossed the
    /// threshold once every record had arrived.
    pub revoked_windows: u32,
}
