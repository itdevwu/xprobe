//! Coverage manifests written beside Event JSONL artifacts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

impl ManifestArtifact {
    /// Describe artifact bytes holding `events` events.
    #[must_use]
    pub fn of(format: ExportFormat, events: u64, bytes: &[u8]) -> Self {
        Self {
            format,
            events,
            bytes: bytes.len() as u64,
            sha256: sha256_hex(bytes),
        }
    }

    /// Whether `bytes` are the artifact this describes.
    #[must_use]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.bytes == bytes.len() as u64 && self.sha256 == sha256_hex(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
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

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
            hex
        })
}

#[cfg(test)]
mod tests {
    use super::{CaptureWindow, ManifestArtifact, manifest_path};
    use crate::ExportFormat;

    #[test]
    fn describes_artifact_bytes_by_length_and_sha256() {
        let artifact = ManifestArtifact::of(ExportFormat::Jsonl, 0, b"abc");
        assert_eq!(
            artifact.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(artifact.matches(b"abc"));
        assert!(!artifact.matches(b"abd"));
        assert!(!artifact.matches(b"abcd"));
    }

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
