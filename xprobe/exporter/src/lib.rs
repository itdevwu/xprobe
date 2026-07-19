//! Structured result and trace exporters.

use xprobe_protocol::Event;

/// Serialize events as one compact, versioned JSON object per line.
///
/// # Errors
///
/// Returns a serialization error if an event cannot be encoded as JSON.
pub fn events_to_jsonl(events: &[Event]) -> Result<String, serde_json::Error> {
    let mut output = String::new();
    for event in events {
        output.push_str(&serde_json::to_string(event)?);
        output.push('\n');
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use xprobe_protocol::{ClockDomain, Event, EventSource, EventType, SchemaVersion};

    use super::events_to_jsonl;

    #[test]
    fn writes_one_event_per_line() {
        let event = Event {
            schema_version: SchemaVersion::current(),
            session_id: "xp_test".to_owned(),
            event_id: "evt_0".to_owned(),
            sequence: 0,
            source: EventSource::CuptiActivity,
            event_type: EventType::GpuKernelStart,
            pid: 1234,
            tid: 1234,
            cpu: None,
            timestamp_raw: 10,
            timestamp_ns: 10,
            clock_domain: ClockDomain::Cupti,
            timestamp_error_ns: None,
            process_start_time: None,
            host: None,
            cuda: None,
            attributes: BTreeMap::new(),
        };

        let output = events_to_jsonl(&[event.clone(), event]).expect("events must serialize");
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|line| !line.contains('\n')));
        assert!(output.ends_with('\n'));
    }
}
