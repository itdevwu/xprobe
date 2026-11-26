//! Capture coverage: what live collection recorded, kept in a manifest beside
//! the Event JSONL artifact and read back for offline correlation.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use xprobe_collector::completed::CompletedCapture;
use xprobe_protocol::{
    CaptureCoverage, CaptureManifest, CaptureWindow, CoverageSource, ErrorCode, ManifestArtifact,
    ManifestVersion, TargetIdentity, manifest_path,
};

use crate::failure::CommandFailure;
use crate::live::{LiveCollection, monotonic_now};

/// How one capture was collected, independent of where its events are written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaptureRecord {
    pub(crate) target: TargetIdentity,
    pub(crate) window: CaptureWindow,
    pub(crate) selectors: Vec<String>,
    pub(crate) all_gpu_activity: bool,
    pub(crate) peer_copies: bool,
    pub(crate) dropped_records: u64,
    pub(crate) unknown_records: u64,
    pub(crate) record_limit_reached: Option<u64>,
    pub(crate) capture_failed: bool,
}

impl CaptureRecord {
    /// The record of a live collection whose sources merged into `capture`.
    pub(crate) fn live(
        collection: &LiveCollection,
        capture: &CompletedCapture,
    ) -> Result<Self, CommandFailure> {
        let peer_copies = collection
            .latest_cuda
            .as_ref()
            .is_some_and(|cuda| cuda.peer_memcpy_captured);
        Ok(Self {
            target: collection.report.target.clone(),
            window: CaptureWindow {
                start_ns: collection.capture_plan.start_ns,
                end_ns: monotonic_now()?,
            },
            selectors: collection.capture_plan.selectors.clone(),
            // Stream order armed unfiltered start and end filters for every
            // activity family; copies cover peers only when MEMCPY2 ran.
            all_gpu_activity: collection.capture_plan.stream_order && peer_copies,
            peer_copies,
            dropped_records: capture.dropped_records,
            unknown_records: capture.unknown_records,
            record_limit_reached: capture.record_limit_reached,
            capture_failed: capture.capture_failed,
        })
    }

    pub(crate) const fn live_coverage(&self) -> CaptureCoverage {
        CaptureCoverage {
            source: CoverageSource::Live,
            all_gpu_activity: self.all_gpu_activity,
        }
    }

    fn manifest(&self, artifact: ManifestArtifact) -> CaptureManifest {
        CaptureManifest {
            schema_version: ManifestVersion::current(),
            artifact,
            target: self.target.clone(),
            window: self.window,
            selectors: self.selectors.clone(),
            all_gpu_activity: self.all_gpu_activity,
            peer_copies: self.peer_copies,
            dropped_records: self.dropped_records,
            unknown_records: self.unknown_records,
            record_limit_reached: self.record_limit_reached,
            capture_failed: self.capture_failed,
        }
    }

    pub(crate) fn from_manifest(manifest: &CaptureManifest) -> Self {
        Self {
            target: manifest.target.clone(),
            window: manifest.window,
            selectors: manifest.selectors.clone(),
            all_gpu_activity: manifest.all_gpu_activity,
            peer_copies: manifest.peer_copies,
            dropped_records: manifest.dropped_records,
            unknown_records: manifest.unknown_records,
            record_limit_reached: manifest.record_limit_reached,
            capture_failed: manifest.capture_failed,
        }
    }
}

/// Write `<artifact>.manifest.json` for an artifact just written, or remove a
/// stale one when the artifact has no known coverage.
pub(crate) fn write_manifest(
    artifact_path: &Path,
    described: Option<(&CaptureRecord, ManifestArtifact)>,
) -> Result<(), CommandFailure> {
    let path = manifest_path(artifact_path);
    let failure = |action: &str, error: &dyn std::fmt::Display| {
        CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!("failed to {action} {}: {error}", path.display()),
            false,
        )
    };
    let Some((record, artifact)) = described else {
        return match fs::remove_file(&path) {
            Err(error) if error.kind() != ErrorKind::NotFound => {
                Err(failure("remove stale manifest", &error))
            }
            _ => Ok(()),
        };
    };
    let mut text = serde_json::to_string_pretty(&record.manifest(artifact))
        .map_err(|error| failure("serialize", &error))?;
    text.push('\n');
    crate::dev::write_export_file(&path, text.as_bytes()).map_err(|error| failure("write", &error))
}

/// Read and check the manifest beside an input artifact, if there is one.
pub(crate) fn read_manifest(
    artifact_path: &Path,
    bytes: &[u8],
) -> Result<Option<CaptureManifest>, CommandFailure> {
    let path = manifest_path(artifact_path);
    let text = match fs::read(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CommandFailure::new(
                ErrorCode::TraceExportFailed,
                format!("failed to read {}: {error}", path.display()),
                false,
            ));
        }
    };
    let manifest: CaptureManifest = serde_json::from_slice(&text).map_err(|error| {
        CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!(
                "{} does not match schemas/capture-manifest.schema.json: {error}",
                path.display()
            ),
            false,
        )
    })?;
    if !xprobe_exporter::artifact_matches(&manifest.artifact, bytes) {
        return Err(CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!(
                "{} describes a different artifact than {}",
                path.display(),
                artifact_path.display()
            ),
            true,
        )
        .with_detail("manifest_path", path.display().to_string())
        .with_hint(
            "the events changed after capture; delete the stale manifest to analyze them without coverage",
        ));
    }
    Ok(Some(manifest))
}

/// Coverage of inputs read together. Manifests prove coverage only when they
/// all describe one target and their windows share an instant.
pub(crate) fn offline_coverage(manifests: &[Option<CaptureManifest>]) -> CaptureCoverage {
    let known = manifests.iter().flatten().collect::<Vec<_>>();
    let unverified = CaptureCoverage {
        source: if manifests.len() > 1 {
            CoverageSource::UnverifiedMerge
        } else {
            CoverageSource::Unverified
        },
        all_gpu_activity: false,
    };
    if known.len() != manifests.len() || known.is_empty() {
        return unverified;
    }
    let one_window = known.iter().all(|manifest| {
        manifest.target == known[0].target
            && known
                .iter()
                .all(|other| manifest.window.overlaps(&other.window))
    });
    if !one_window {
        return unverified;
    }
    // A capture of every GPU activity proves adjacency for the merge only
    // when its window holds every other input's.
    let all_gpu_activity = known.iter().any(|wide| {
        wide.all_gpu_activity
            && known.iter().all(|other| {
                wide.window.start_ns <= other.window.start_ns
                    && other.window.end_ns <= wide.window.end_ns
            })
    });
    CaptureCoverage {
        source: CoverageSource::Manifest,
        all_gpu_activity,
    }
}

/// Check a manifest against the events decoded from its artifact.
pub(crate) fn check_manifest(
    artifact_path: &Path,
    manifest: &CaptureManifest,
    events: &[xprobe_protocol::Event],
) -> Result<(), CommandFailure> {
    let failure = |problem: String| {
        Err(CommandFailure::new(
            ErrorCode::TraceExportFailed,
            format!("the manifest beside {} {problem}", artifact_path.display()),
            false,
        ))
    };
    if manifest.artifact.format != xprobe_protocol::ExportFormat::Jsonl {
        return failure("describes a non-JSONL artifact".to_owned());
    }
    if manifest.artifact.events != events.len() as u64 {
        return failure(format!(
            "counts {} events but the artifact holds {}",
            manifest.artifact.events,
            events.len()
        ));
    }
    if manifest.window.start_ns > manifest.window.end_ns {
        return failure("has a window that ends before it starts".to_owned());
    }
    let foreign = events.iter().find(|event| {
        event.pid != manifest.target.pid
            || event
                .process_start_time
                .is_some_and(|start| start != manifest.target.process_start_time)
    });
    if let Some(event) = foreign {
        return failure(format!(
            "names process {} started at {} but holds an event of PID {}",
            manifest.target.pid, manifest.target.process_start_time, event.pid
        ));
    }
    Ok(())
}

/// Apply the losses and stop state a manifest records to its decoded events.
pub(crate) fn apply_manifest(capture: &mut CompletedCapture, manifest: &CaptureManifest) {
    capture.dropped_records = capture.dropped_records.max(manifest.dropped_records);
    capture.unknown_records = capture.unknown_records.max(manifest.unknown_records);
    capture.record_limit_reached = capture
        .record_limit_reached
        .max(manifest.record_limit_reached);
    capture.capture_failed |= manifest.capture_failed;
}

#[cfg(test)]
mod tests {
    use xprobe_protocol::{
        CaptureManifest, CaptureWindow, CoverageSource, ExportFormat, ManifestVersion,
        TargetIdentity,
    };

    use super::offline_coverage;

    fn manifest(pid: u32, window: (u64, u64), all_gpu_activity: bool) -> CaptureManifest {
        CaptureManifest {
            schema_version: ManifestVersion::current(),
            artifact: xprobe_exporter::manifest_artifact(ExportFormat::Jsonl, 0, b""),
            target: TargetIdentity {
                pid,
                process_start_time: 7,
            },
            window: CaptureWindow {
                start_ns: window.0,
                end_ns: window.1,
            },
            selectors: Vec::new(),
            all_gpu_activity,
            peer_copies: all_gpu_activity,
            dropped_records: 0,
            unknown_records: 0,
            record_limit_reached: None,
            capture_failed: false,
        }
    }

    #[test]
    fn manifests_prove_coverage_only_for_one_window_of_one_target() {
        let gpu = manifest(1, (10, 30), true);
        let host = manifest(1, (12, 25), false);
        let covered = offline_coverage(&[Some(gpu.clone()), Some(host.clone())]);
        assert_eq!(covered.source, CoverageSource::Manifest);
        assert!(covered.all_gpu_activity);
        // A wide capture of 10-30 says nothing about a narrower one past it.
        let past = manifest(1, (12, 40), false);
        let partial = offline_coverage(&[Some(gpu.clone()), Some(past)]);
        assert_eq!(partial.source, CoverageSource::Manifest);
        assert!(!partial.all_gpu_activity);

        let later = manifest(1, (31, 40), false);
        let other = manifest(2, (10, 20), false);
        for inputs in [
            vec![Some(gpu.clone()), Some(later)],
            vec![Some(gpu.clone()), Some(other)],
            vec![Some(gpu.clone()), None],
        ] {
            let coverage = offline_coverage(&inputs);
            assert_eq!(coverage.source, CoverageSource::UnverifiedMerge);
            assert!(!coverage.all_gpu_activity);
        }
        assert_eq!(offline_coverage(&[None]).source, CoverageSource::Unverified);
        assert_eq!(
            offline_coverage(&[Some(host)]).source,
            CoverageSource::Manifest
        );
    }
}
