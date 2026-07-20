//! Structured result and trace exporters.

use serde_json::{Value, json};
use xprobe_protocol::{Event, EventSource, EventType};

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

/// Serialize events as a Chrome Trace Event Format document.
///
/// Events are emitted as thread-scoped instants. The Chrome timestamp uses
/// integer microseconds; `timestamp_ns` in `args` preserves the source value.
///
/// # Errors
///
/// Returns a serialization error if the trace document cannot be encoded.
pub fn events_to_chrome_trace(events: &[Event]) -> Result<String, serde_json::Error> {
    let trace_events = events.iter().map(chrome_event).collect::<Vec<_>>();
    serde_json::to_string_pretty(&json!({
        "displayTimeUnit": "ns",
        "traceEvents": trace_events,
    }))
}

fn chrome_event(event: &Event) -> Value {
    let cuda = event.cuda.as_ref();
    json!({
        "name": event_name(event),
        "cat": event_category(&event.source),
        "ph": "i",
        "s": "t",
        "ts": event.timestamp_ns / 1_000,
        "pid": event.pid,
        "tid": cuda.and_then(|payload| payload.stream_id).unwrap_or(u64::from(event.tid)),
        "args": {
            "event_id": event.event_id,
            "event_type": event_type_name(&event.event_type),
            "timestamp_ns": event.timestamp_ns,
            "timestamp_raw": event.timestamp_raw,
            "clock_domain": event.clock_domain,
            "correlation_id": cuda.and_then(|payload| payload.correlation_id),
            "context_id": cuda.and_then(|payload| payload.context_id),
            "stream_id": cuda.and_then(|payload| payload.stream_id),
            "attributes": event.attributes,
        }
    })
}

fn event_name(event: &Event) -> &str {
    event
        .host
        .as_ref()
        .and_then(|host| host.symbol.as_deref())
        .or_else(|| {
            event
                .attributes
                .get("cuda_api_name")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            event
                .cuda
                .as_ref()
                .and_then(|cuda| cuda.kernel_name.as_deref())
        })
        .unwrap_or_else(|| event_type_name(&event.event_type))
}

const fn event_category(source: &EventSource) -> &'static str {
    match source {
        EventSource::Ebpf => "host",
        EventSource::CuptiCallback => "cuda.api",
        EventSource::CuptiActivity => "cuda.activity",
        EventSource::Marker => "marker",
    }
}

const fn event_type_name(event_type: &EventType) -> &'static str {
    match event_type {
        EventType::HostFunctionEntry => "host_function_entry",
        EventType::HostFunctionExit => "host_function_exit",
        EventType::KernelFunctionEntry => "kernel_function_entry",
        EventType::KernelFunctionExit => "kernel_function_exit",
        EventType::Tracepoint => "tracepoint",
        EventType::SyscallEntry => "syscall_entry",
        EventType::SyscallExit => "syscall_exit",
        EventType::CudaApiEntry => "cuda_api_entry",
        EventType::CudaApiExit => "cuda_api_exit",
        EventType::GpuKernelStart => "gpu_kernel_start",
        EventType::GpuKernelEnd => "gpu_kernel_end",
        EventType::GpuMemcpyStart => "gpu_memcpy_start",
        EventType::GpuMemcpyEnd => "gpu_memcpy_end",
        EventType::GpuMemsetStart => "gpu_memset_start",
        EventType::GpuMemsetEnd => "gpu_memset_end",
        EventType::Marker => "marker",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use xprobe_protocol::{ClockDomain, Event, EventSource, EventType, SchemaVersion};

    use super::{events_to_chrome_trace, events_to_jsonl};

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

    #[test]
    fn writes_chrome_trace_instants_with_nanosecond_metadata() {
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
            timestamp_raw: 10_999,
            timestamp_ns: 10_999,
            clock_domain: ClockDomain::Cupti,
            timestamp_error_ns: None,
            process_start_time: None,
            host: None,
            cuda: None,
            attributes: BTreeMap::new(),
        };

        let output = events_to_chrome_trace(&[event]).expect("trace must serialize");
        let document: serde_json::Value = serde_json::from_str(&output).expect("trace JSON");
        assert_eq!(document["displayTimeUnit"], "ns");
        assert_eq!(document["traceEvents"][0]["ph"], "i");
        assert_eq!(document["traceEvents"][0]["ts"], 10);
        assert_eq!(document["traceEvents"][0]["args"]["timestamp_ns"], 10_999);
    }
}
