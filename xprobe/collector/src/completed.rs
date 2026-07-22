use std::{error::Error, fmt};

use serde_json::Value;
use xprobe_protocol::{Event, HostCaptureResult};

use crate::cupti::{self, CuptiCaptureState, CuptiDecodeError};

#[derive(Debug, Clone, PartialEq)]
pub struct CompletedCuptiStatistics {
    pub complete: bool,
    pub record_capacity: u64,
    pub observed_records: u64,
    pub dropped_records: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompletedCapture {
    pub dropped_records: u64,
    pub unknown_records: u64,
    pub record_limit_reached: Option<u64>,
    pub capture_failed: bool,
    pub cupti: Option<CompletedCuptiStatistics>,
    pub events: Vec<Event>,
}

#[derive(Debug)]
pub enum CompletedCaptureError {
    EmptyInput,
    Cupti(CuptiDecodeError),
    Json(serde_json::Error),
    HostCaptureFollowedByAnotherDocument,
    HostCaptureInsideEventStream,
    CounterOverflow,
    TargetMismatch { expected: u32, actual: u32 },
}

impl fmt::Display for CompletedCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => formatter.write_str("completed capture input is empty"),
            Self::Cupti(error) => error.fmt(formatter),
            Self::Json(error) => write!(formatter, "completed capture JSON is invalid: {error}"),
            Self::HostCaptureFollowedByAnotherDocument => formatter
                .write_str("a host capture result must be the only JSON document in its input"),
            Self::HostCaptureInsideEventStream => formatter
                .write_str("a host capture result cannot appear inside an Event JSON stream"),
            Self::CounterOverflow => {
                formatter.write_str("completed capture counters exceed the supported range")
            }
            Self::TargetMismatch { expected, actual } => write!(
                formatter,
                "completed capture mixes target PIDs {expected} and {actual}"
            ),
        }
    }
}

impl Error for CompletedCaptureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cupti(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::EmptyInput
            | Self::HostCaptureFollowedByAnotherDocument
            | Self::HostCaptureInsideEventStream
            | Self::CounterOverflow
            | Self::TargetMismatch { .. } => None,
        }
    }
}

impl From<CuptiDecodeError> for CompletedCaptureError {
    fn from(error: CuptiDecodeError) -> Self {
        Self::Cupti(error)
    }
}

impl From<serde_json::Error> for CompletedCaptureError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// Decode one completed CUPTI binary, host capture JSON, or Event JSON stream.
///
/// # Errors
///
/// Returns [`CompletedCaptureError`] when the input is empty, malformed, or
/// mixes a host capture envelope with Event documents.
pub fn decode(bytes: &[u8], session_id: &str) -> Result<CompletedCapture, CompletedCaptureError> {
    let first = bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        .ok_or(CompletedCaptureError::EmptyInput)?;
    if first == b'{' {
        decode_json(bytes)
    } else {
        let capture = cupti::decode_capture(bytes, session_id)?;
        Ok(CompletedCapture {
            dropped_records: capture.dropped_records,
            unknown_records: capture.unknown_records,
            record_limit_reached: (capture.state == CuptiCaptureState::LimitReached)
                .then_some(capture.record_capacity),
            capture_failed: matches!(
                capture.state,
                CuptiCaptureState::Idle | CuptiCaptureState::Failed
            ),
            cupti: Some(CompletedCuptiStatistics {
                complete: capture.state == CuptiCaptureState::Stopped,
                record_capacity: capture.record_capacity,
                observed_records: capture.observed_records,
                dropped_records: capture.dropped_records,
            }),
            events: capture.events,
        })
    }
}

fn decode_json(bytes: &[u8]) -> Result<CompletedCapture, CompletedCaptureError> {
    let mut documents = serde_json::Deserializer::from_slice(bytes).into_iter::<Value>();
    let first = documents
        .next()
        .ok_or(CompletedCaptureError::EmptyInput)??;
    if first.get("events").is_some() {
        if documents.next().transpose()?.is_some() {
            return Err(CompletedCaptureError::HostCaptureFollowedByAnotherDocument);
        }
        let capture: HostCaptureResult = serde_json::from_value(first)?;
        return Ok(CompletedCapture {
            dropped_records: capture.dropped,
            unknown_records: 0,
            record_limit_reached: None,
            capture_failed: false,
            cupti: None,
            events: capture.events,
        });
    }

    let mut events = vec![serde_json::from_value(first)?];
    for document in documents {
        let document = document?;
        if document.get("events").is_some() {
            return Err(CompletedCaptureError::HostCaptureInsideEventStream);
        }
        events.push(serde_json::from_value(document)?);
    }
    Ok(CompletedCapture {
        dropped_records: 0,
        unknown_records: 0,
        record_limit_reached: None,
        capture_failed: false,
        cupti: None,
        events,
    })
}

/// Merge captures for one target into a deterministic measurement event stream.
///
/// # Errors
///
/// Returns [`CompletedCaptureError`] when counters overflow or events belong to
/// different process IDs.
pub fn merge(
    captures: Vec<CompletedCapture>,
    session_id: &str,
) -> Result<CompletedCapture, CompletedCaptureError> {
    let mut merged = CompletedCapture {
        dropped_records: 0,
        unknown_records: 0,
        record_limit_reached: None,
        capture_failed: false,
        cupti: None,
        events: Vec::new(),
    };
    let mut target_pid = None;
    for capture in captures {
        merged.dropped_records = merged
            .dropped_records
            .checked_add(capture.dropped_records)
            .ok_or(CompletedCaptureError::CounterOverflow)?;
        merged.unknown_records = merged
            .unknown_records
            .checked_add(capture.unknown_records)
            .ok_or(CompletedCaptureError::CounterOverflow)?;
        merged.record_limit_reached = merged
            .record_limit_reached
            .max(capture.record_limit_reached);
        merged.capture_failed |= capture.capture_failed;
        if let Some(cupti) = capture.cupti {
            if let Some(existing) = merged.cupti.as_mut() {
                existing.complete &= cupti.complete;
                existing.record_capacity = existing
                    .record_capacity
                    .checked_add(cupti.record_capacity)
                    .ok_or(CompletedCaptureError::CounterOverflow)?;
                existing.observed_records = existing
                    .observed_records
                    .checked_add(cupti.observed_records)
                    .ok_or(CompletedCaptureError::CounterOverflow)?;
                existing.dropped_records = existing
                    .dropped_records
                    .checked_add(cupti.dropped_records)
                    .ok_or(CompletedCaptureError::CounterOverflow)?;
            } else {
                merged.cupti = Some(cupti);
            }
        }
        for event in capture.events {
            if let Some(expected) = target_pid {
                if event.pid != expected {
                    return Err(CompletedCaptureError::TargetMismatch {
                        expected,
                        actual: event.pid,
                    });
                }
            } else {
                target_pid = Some(event.pid);
            }
            merged.events.push(event);
        }
    }
    merged.events.sort_by_key(|event| event.timestamp_ns);
    for (index, event) in merged.events.iter_mut().enumerate() {
        let sequence = u64::try_from(index).map_err(|_| CompletedCaptureError::CounterOverflow)?;
        session_id.clone_into(&mut event.session_id);
        event.sequence = sequence;
        event.event_id = format!("evt_{sequence}");
    }
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use xprobe_protocol::{
        ClockDomain, Event, EventSource, EventType, HostCaptureResult, SchemaVersion,
        TargetIdentity,
    };

    use super::{CompletedCapture, CompletedCaptureError, decode, merge};

    fn event(pid: u32, timestamp_ns: u64) -> Event {
        Event {
            schema_version: SchemaVersion::current(),
            session_id: "source".to_owned(),
            event_id: "source_event".to_owned(),
            sequence: 9,
            source: EventSource::Ebpf,
            event_type: EventType::HostFunctionEntry,
            pid,
            tid: pid,
            cpu: Some(0),
            timestamp_raw: timestamp_ns,
            timestamp_ns,
            clock_domain: ClockDomain::HostMonotonic,
            timestamp_error_ns: None,
            process_start_time: Some(10),
            host: None,
            cuda: None,
            attributes: BTreeMap::new(),
        }
    }

    #[test]
    fn decodes_event_json_stream() {
        let input = format!(
            "{}\n{}\n",
            serde_json::to_string(&event(12, 20)).unwrap(),
            serde_json::to_string(&event(12, 30)).unwrap()
        );
        let capture = decode(input.as_bytes(), "unused").unwrap();
        assert_eq!(capture.events.len(), 2);
        assert_eq!(capture.dropped_records, 0);
    }

    #[test]
    fn decodes_host_capture_and_preserves_drops() {
        let capture = HostCaptureResult {
            schema_version: SchemaVersion::current(),
            ok: true,
            session_id: "host".to_owned(),
            target: TargetIdentity {
                pid: 12,
                process_start_time: 10,
            },
            probe_id: 1,
            captured: 1,
            dropped: 3,
            timed_out: false,
            events: vec![event(12, 20)],
        };
        let input = serde_json::to_vec_pretty(&capture).unwrap();
        let decoded = decode(&input, "unused").unwrap();
        assert_eq!(decoded.dropped_records, 3);
        assert_eq!(decoded.events.len(), 1);
    }

    #[test]
    fn merges_and_reidentifies_events_in_timestamp_order() {
        let merged = merge(
            vec![
                CompletedCapture {
                    dropped_records: 2,
                    unknown_records: 0,
                    record_limit_reached: None,
                    capture_failed: false,
                    cupti: None,
                    events: vec![event(12, 30)],
                },
                CompletedCapture {
                    dropped_records: 1,
                    unknown_records: 0,
                    record_limit_reached: None,
                    capture_failed: false,
                    cupti: None,
                    events: vec![event(12, 20)],
                },
            ],
            "merged",
        )
        .unwrap();
        assert_eq!(merged.dropped_records, 3);
        assert_eq!(merged.events[0].timestamp_ns, 20);
        assert_eq!(merged.events[0].session_id, "merged");
        assert_eq!(merged.events[0].event_id, "evt_0");
    }

    #[test]
    fn rejects_mixed_target_pids() {
        let error = merge(
            vec![CompletedCapture {
                dropped_records: 0,
                unknown_records: 0,
                record_limit_reached: None,
                capture_failed: false,
                cupti: None,
                events: vec![event(12, 20), event(13, 30)],
            }],
            "merged",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CompletedCaptureError::TargetMismatch {
                expected: 12,
                actual: 13
            }
        ));
    }
}
