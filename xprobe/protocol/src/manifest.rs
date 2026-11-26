//! Coverage manifests written beside Event JSONL artifacts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ExportFormat, TargetIdentity};

/// Version of the capture manifest contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ManifestVersion {
    #[serde(rename = "1.0")]
    V1,
}

impl ManifestVersion {
    #[must_use]
    pub const fn current() -> Self {
        Self::V1
    }
}

/// What one bounded capture covered, written to `<artifact>.manifest.json`.
///
/// Event JSONL records only events. The manifest records how they were
/// collected, so offline correlation can tell "not observed" from "not
/// captured" and keep losses that the live command reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureManifest {
    pub schema_version: ManifestVersion,
    /// The artifact this manifest describes; a mismatch makes it stale.
    pub artifact: ManifestArtifact,
    pub target: TargetIdentity,
    /// `CLOCK_MONOTONIC` nanoseconds from the first collector armed to the
    /// final collection.
    pub window: CaptureWindow,
    /// Endpoint selectors the collectors were armed for.
    pub selectors: Vec<String>,
    /// Every kernel, copy, and memset on the target was recorded, not only
    /// the selected endpoints.
    pub all_gpu_activity: bool,
    /// Peer-to-peer copies were recorded with other copies.
    pub peer_copies: bool,
    pub dropped_records: u64,
    pub unknown_records: u64,
    /// The configured record limit that stopped the capture, if any.
    pub record_limit_reached: Option<u64>,
    /// A collector entered a failed state.
    pub capture_failed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManifestArtifact {
    pub format: ExportFormat,
    pub events: u64,
    pub bytes: u64,
    /// Lowercase hexadecimal SHA-256 of the artifact bytes.
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// `CLOCK_MONOTONIC` interval the capture's coverage holds for: from the
/// collector's ARM acknowledgment until after its final read. Activity that
/// was already running at ARM may begin before `start_ns`.
pub struct CaptureWindow {
    pub start_ns: u64,
    pub end_ns: u64,
}

impl CaptureWindow {
    /// Whether two windows share any instant.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start_ns <= other.end_ns && other.start_ns <= self.end_ns
    }
}

/// The sidecar manifest path for an artifact path.
#[must_use]
pub fn manifest_path(artifact: &std::path::Path) -> std::path::PathBuf {
    let mut path = artifact.as_os_str().to_owned();
    path.push(".manifest.json");
    path.into()
}

#[cfg(test)]
mod tests {
    use super::{CaptureWindow, manifest_path};

    #[test]
    fn windows_overlap_when_they_share_an_instant() {
        let window = CaptureWindow {
            start_ns: 10,
            end_ns: 20,
        };
        assert!(window.overlaps(&CaptureWindow {
            start_ns: 20,
            end_ns: 30
        }));
        assert!(!window.overlaps(&CaptureWindow {
            start_ns: 21,
            end_ns: 30
        }));
    }

    #[test]
    fn manifests_sit_beside_their_artifact() {
        assert_eq!(
            manifest_path(std::path::Path::new("/tmp/run/events.jsonl")),
            std::path::Path::new("/tmp/run/events.jsonl.manifest.json")
        );
    }
}
