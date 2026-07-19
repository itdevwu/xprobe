use std::{collections::BTreeMap, error::Error, fmt, str};

use serde_json::Value;
use xprobe_protocol::{ClockDomain, CudaEvent, Dim3, Event, EventSource, EventType, SchemaVersion};

const OUTPUT_MAGIC: &[u8; 8] = b"XPCUPTI\0";
const ABI_VERSION: u32 = 1;
const HEADER_SIZE: usize = 48;
const HEADER_SIZE_U32: u32 = 48;
const RECORD_SIZE: usize = 200;
const RECORD_SIZE_U32: u32 = 200;
const UNKNOWN_U32: u32 = u32::MAX;

#[derive(Debug, Clone, PartialEq)]
pub struct CuptiCapture {
    pub dropped_records: u64,
    pub unknown_records: u64,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CuptiDecodeError {
    HeaderTooShort { actual: usize },
    InvalidMagic,
    UnsupportedAbi(u32),
    InvalidHeaderSize(u32),
    InvalidRecordSize(u32),
    CaptureLengthOverflow,
    InvalidCaptureLength { expected: usize, actual: usize },
    UnknownRecordKind { index: usize, kind: u32 },
    InvalidName { index: usize },
}

impl fmt::Display for CuptiDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTooShort { actual } => write!(
                formatter,
                "CUPTI capture header requires {HEADER_SIZE} bytes, found {actual}"
            ),
            Self::InvalidMagic => formatter.write_str("CUPTI capture magic is invalid"),
            Self::UnsupportedAbi(version) => {
                write!(formatter, "unsupported CUPTI capture ABI version {version}")
            }
            Self::InvalidHeaderSize(size) => {
                write!(
                    formatter,
                    "CUPTI capture header size is {size}, expected {HEADER_SIZE}"
                )
            }
            Self::InvalidRecordSize(size) => {
                write!(
                    formatter,
                    "CUPTI capture record size is {size}, expected {RECORD_SIZE}"
                )
            }
            Self::CaptureLengthOverflow => {
                formatter.write_str("CUPTI capture record count exceeds addressable memory")
            }
            Self::InvalidCaptureLength { expected, actual } => write!(
                formatter,
                "CUPTI capture requires {expected} bytes, found {actual}"
            ),
            Self::UnknownRecordKind { index, kind } => {
                write!(formatter, "CUPTI record {index} has unknown kind {kind}")
            }
            Self::InvalidName { index } => {
                write!(formatter, "CUPTI record {index} name is not valid UTF-8")
            }
        }
    }
}

impl Error for CuptiDecodeError {}

/// Decode an xprobe CUPTI binary capture into versioned protocol events.
///
/// Events are ordered by raw nanosecond timestamp. The clock domain remains
/// explicit because clock normalization is a separate correlation step.
///
/// # Errors
///
/// Returns [`CuptiDecodeError`] when the capture header, size, record kind, or
/// bounded name does not match ABI version 1.
pub fn decode_capture(bytes: &[u8], session_id: &str) -> Result<CuptiCapture, CuptiDecodeError> {
    if bytes.len() < HEADER_SIZE {
        return Err(CuptiDecodeError::HeaderTooShort {
            actual: bytes.len(),
        });
    }
    if &bytes[0..8] != OUTPUT_MAGIC {
        return Err(CuptiDecodeError::InvalidMagic);
    }

    let abi_version = read_u32(bytes, 8);
    if abi_version != ABI_VERSION {
        return Err(CuptiDecodeError::UnsupportedAbi(abi_version));
    }
    let header_size = read_u32(bytes, 12);
    if header_size != HEADER_SIZE_U32 {
        return Err(CuptiDecodeError::InvalidHeaderSize(header_size));
    }
    let record_size = read_u32(bytes, 16);
    if record_size != RECORD_SIZE_U32 {
        return Err(CuptiDecodeError::InvalidRecordSize(record_size));
    }

    let record_count = usize::try_from(read_u64(bytes, 24))
        .map_err(|_| CuptiDecodeError::CaptureLengthOverflow)?;
    let payload_size = record_count
        .checked_mul(RECORD_SIZE)
        .ok_or(CuptiDecodeError::CaptureLengthOverflow)?;
    let expected_size = HEADER_SIZE
        .checked_add(payload_size)
        .ok_or(CuptiDecodeError::CaptureLengthOverflow)?;
    if bytes.len() != expected_size {
        return Err(CuptiDecodeError::InvalidCaptureLength {
            expected: expected_size,
            actual: bytes.len(),
        });
    }

    let mut events = Vec::with_capacity(record_count);
    for (index, record) in bytes[HEADER_SIZE..].chunks_exact(RECORD_SIZE).enumerate() {
        events.push(decode_record(record, index, session_id)?);
    }
    events.sort_by_key(|event| event.timestamp_ns);
    let mut sequence = 0_u64;
    for event in &mut events {
        event.sequence = sequence;
        event.event_id = format!("evt_{sequence}");
        sequence = sequence
            .checked_add(1)
            .ok_or(CuptiDecodeError::CaptureLengthOverflow)?;
    }

    Ok(CuptiCapture {
        dropped_records: read_u64(bytes, 32),
        unknown_records: read_u64(bytes, 40),
        events,
    })
}

fn decode_record(record: &[u8], index: usize, session_id: &str) -> Result<Event, CuptiDecodeError> {
    let kind = read_u32(record, 8);
    let (source, event_type) = match kind {
        1 => (EventSource::CuptiCallback, EventType::CudaApiEntry),
        2 => (EventSource::CuptiCallback, EventType::CudaApiExit),
        3 => (EventSource::CuptiActivity, EventType::GpuKernelStart),
        4 => (EventSource::CuptiActivity, EventType::GpuKernelEnd),
        _ => return Err(CuptiDecodeError::UnknownRecordKind { index, kind }),
    };
    let timestamp = read_u64(record, 0);
    let name_bytes = &record[72..200];
    let name_length = name_bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name_bytes.len());
    let name = str::from_utf8(&name_bytes[..name_length])
        .map_err(|_| CuptiDecodeError::InvalidName { index })?;
    let is_api = kind <= 2;
    let is_kernel_start = kind == 3;
    let is_kernel_end = kind == 4;
    let mut attributes = BTreeMap::new();
    if is_api {
        attributes.insert("cuda_api_name".to_owned(), Value::String(name.to_owned()));
    }

    Ok(Event {
        schema_version: SchemaVersion::current(),
        session_id: session_id.to_owned(),
        event_id: String::new(),
        sequence: 0,
        source,
        event_type,
        pid: read_u32(record, 12),
        tid: read_u32(record, 16),
        cpu: None,
        timestamp_raw: timestamp,
        timestamp_ns: timestamp,
        clock_domain: if is_api {
            ClockDomain::HostMonotonic
        } else {
            ClockDomain::Cupti
        },
        timestamp_error_ns: None,
        process_start_time: None,
        host: None,
        cuda: Some(CudaEvent {
            device_id: optional_unknown(read_u32(record, 20)),
            context_id: optional_unknown(read_u32(record, 24)),
            stream_id: optional_unknown(read_u32(record, 28)).map(u64::from),
            correlation_id: optional_nonzero(read_u32(record, 32)),
            runtime_correlation_id: optional_nonzero(read_u32(record, 68)),
            callback_domain: optional_nonzero(read_u32(record, 36)),
            callback_id: optional_nonzero(read_u32(record, 40)),
            kernel_name: (!is_api).then(|| name.to_owned()),
            kernel_name_mangled: None,
            start_ns: is_kernel_start.then_some(timestamp),
            end_ns: is_kernel_end.then_some(timestamp),
            grid: decode_dim(record, 44),
            block: decode_dim(record, 56),
            bytes: None,
            memcpy_kind: None,
        }),
        attributes,
    })
}

fn decode_dim(record: &[u8], offset: usize) -> Option<Dim3> {
    let dimension = Dim3 {
        x: read_u32(record, offset),
        y: read_u32(record, offset + 4),
        z: read_u32(record, offset + 8),
    };
    (dimension.x != 0 || dimension.y != 0 || dimension.z != 0).then_some(dimension)
}

const fn optional_unknown(value: u32) -> Option<u32> {
    if value == UNKNOWN_U32 {
        None
    } else {
        Some(value)
    }
}

const fn optional_nonzero(value: u32) -> Option<u32> {
    if value == 0 { None } else { Some(value) }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated u32 field"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated u64 field"),
    )
}

#[cfg(test)]
mod tests {
    use super::{CuptiDecodeError, HEADER_SIZE, OUTPUT_MAGIC, RECORD_SIZE, decode_capture};
    use xprobe_protocol::{ClockDomain, EventSource, EventType};

    fn capture(records: &[[u8; RECORD_SIZE]]) -> Vec<u8> {
        let mut bytes = vec![0_u8; HEADER_SIZE + records.len() * RECORD_SIZE];
        bytes[0..8].copy_from_slice(OUTPUT_MAGIC);
        bytes[8..12].copy_from_slice(&1_u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&super::HEADER_SIZE_U32.to_le_bytes());
        bytes[16..20].copy_from_slice(&super::RECORD_SIZE_U32.to_le_bytes());
        bytes[24..32].copy_from_slice(
            &u64::try_from(records.len())
                .expect("test record count must fit u64")
                .to_le_bytes(),
        );
        for (index, record) in records.iter().enumerate() {
            let offset = HEADER_SIZE + index * RECORD_SIZE;
            bytes[offset..offset + RECORD_SIZE].copy_from_slice(record);
        }
        bytes
    }

    fn record(kind: u32, timestamp: u64, correlation: u32, name: &str) -> [u8; RECORD_SIZE] {
        let mut record = [0_u8; RECORD_SIZE];
        record[0..8].copy_from_slice(&timestamp.to_le_bytes());
        record[8..12].copy_from_slice(&kind.to_le_bytes());
        record[12..16].copy_from_slice(&1234_u32.to_le_bytes());
        record[16..20].copy_from_slice(&1235_u32.to_le_bytes());
        record[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        record[24..28].copy_from_slice(&7_u32.to_le_bytes());
        record[28..32].copy_from_slice(&9_u32.to_le_bytes());
        record[32..36].copy_from_slice(&correlation.to_le_bytes());
        record[44..48].copy_from_slice(&2_u32.to_le_bytes());
        record[48..52].copy_from_slice(&3_u32.to_le_bytes());
        record[52..56].copy_from_slice(&4_u32.to_le_bytes());
        record[56..60].copy_from_slice(&32_u32.to_le_bytes());
        record[60..64].copy_from_slice(&1_u32.to_le_bytes());
        record[64..68].copy_from_slice(&1_u32.to_le_bytes());
        record[72..72 + name.len()].copy_from_slice(name.as_bytes());
        record
    }

    #[test]
    fn decodes_and_orders_callback_and_kernel_events() {
        let api = record(1, 200, 42, "cudaLaunchKernel");
        let kernel = record(3, 100, 42, "_Z12test_kernelv");
        let decoded =
            decode_capture(&capture(&[api, kernel]), "xp_test").expect("capture must decode");

        assert_eq!(decoded.events.len(), 2);
        assert_eq!(decoded.events[0].source, EventSource::CuptiActivity);
        assert_eq!(decoded.events[0].event_type, EventType::GpuKernelStart);
        assert_eq!(decoded.events[0].clock_domain, ClockDomain::Cupti);
        assert_eq!(decoded.events[0].sequence, 0);
        assert_eq!(decoded.events[1].source, EventSource::CuptiCallback);
        assert_eq!(decoded.events[1].event_type, EventType::CudaApiEntry);
        assert_eq!(decoded.events[1].clock_domain, ClockDomain::HostMonotonic);
        assert_eq!(
            decoded.events[1].attributes["cuda_api_name"],
            "cudaLaunchKernel"
        );
        assert_eq!(
            decoded.events[0]
                .cuda
                .as_ref()
                .expect("CUDA payload")
                .correlation_id,
            Some(42)
        );
    }

    #[test]
    fn rejects_unknown_record_kind() {
        let error = decode_capture(&capture(&[record(99, 100, 1, "bad")]), "xp_test")
            .expect_err("unknown kind must fail");
        assert_eq!(
            error,
            CuptiDecodeError::UnknownRecordKind { index: 0, kind: 99 }
        );
    }

    #[test]
    fn rejects_truncated_capture() {
        let mut bytes = capture(&[record(1, 100, 1, "cudaLaunchKernel")]);
        bytes.pop();
        assert!(matches!(
            decode_capture(&bytes, "xp_test"),
            Err(CuptiDecodeError::InvalidCaptureLength { .. })
        ));
    }
}
