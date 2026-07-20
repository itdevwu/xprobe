use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    io::{self, Read},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    str,
    time::Duration,
};

use serde_json::Value;
use xprobe_protocol::{
    ClockDomain, CudaEvent, Dim3, Event, EventSource, EventType, MemcpyKind, SchemaVersion,
};

const OUTPUT_MAGIC: &[u8; 8] = b"XPCUPTI\0";
const ABI_VERSION: u32 = 1;
const HEADER_SIZE: usize = 48;
const HEADER_SIZE_U32: u32 = 48;
const RECORD_SIZE: usize = 200;
const RECORD_SIZE_U32: u32 = 200;
const FEATURE_HOST_MONOTONIC_TIMESTAMPS: u32 = 1 << 0;
const FEATURE_TRANSFER_RECORDS: u32 = 1 << 1;
const SUPPORTED_FEATURES: u32 = FEATURE_HOST_MONOTONIC_TIMESTAMPS | FEATURE_TRANSFER_RECORDS;
const UNKNOWN_U32: u32 = u32::MAX;

#[derive(Debug, Clone, PartialEq)]
pub struct CuptiCapture {
    pub dropped_records: u64,
    pub unknown_records: u64,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CuptiDecodeError {
    HeaderTooShort {
        actual: usize,
    },
    InvalidMagic,
    UnsupportedAbi(u32),
    UnsupportedFeatureFlags(u32),
    InvalidHeaderSize {
        version: u32,
        actual: u32,
        expected: u32,
    },
    InvalidRecordSize(u32),
    CaptureLengthOverflow,
    InvalidCaptureLength {
        expected: usize,
        actual: usize,
    },
    UnknownRecordKind {
        index: usize,
        kind: u32,
    },
    InvalidName {
        index: usize,
    },
}

impl fmt::Display for CuptiDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTooShort { actual } => write!(
                formatter,
                "CUPTI capture header requires at least {HEADER_SIZE} bytes, found {actual}"
            ),
            Self::InvalidMagic => formatter.write_str("CUPTI capture magic is invalid"),
            Self::UnsupportedAbi(version) => {
                write!(formatter, "unsupported CUPTI capture ABI version {version}")
            }
            Self::UnsupportedFeatureFlags(flags) => {
                write!(
                    formatter,
                    "unsupported CUPTI capture feature flags {flags:#x}"
                )
            }
            Self::InvalidHeaderSize {
                version,
                actual,
                expected,
            } => {
                write!(
                    formatter,
                    "CUPTI capture ABI {version} header size is {actual}, expected {expected}"
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

#[derive(Debug)]
pub enum CuptiSnapshotError {
    Connect { path: PathBuf, source: io::Error },
    Configure(io::Error),
    Read(io::Error),
    Decode(CuptiDecodeError),
}

impl fmt::Display for CuptiSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect { path, source } => {
                write!(
                    formatter,
                    "failed to connect to {}: {source}",
                    path.display()
                )
            }
            Self::Configure(source) => {
                write!(
                    formatter,
                    "failed to configure CUPTI snapshot socket: {source}"
                )
            }
            Self::Read(source) => write!(formatter, "failed to read CUPTI snapshot: {source}"),
            Self::Decode(source) => write!(formatter, "failed to decode CUPTI snapshot: {source}"),
        }
    }
}

impl Error for CuptiSnapshotError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Connect { source, .. } | Self::Configure(source) | Self::Read(source) => {
                Some(source)
            }
            Self::Decode(source) => Some(source),
        }
    }
}

/// Request one immutable capture snapshot from a running CUPTI agent.
///
/// Connecting is the request. The agent flushes pending activity records and
/// sends one ABI capture before closing the socket.
///
/// # Errors
///
/// Returns [`CuptiSnapshotError`] when the socket cannot be connected or read,
/// or when the agent sends an invalid capture.
pub fn snapshot(
    socket_path: &Path,
    timeout: Duration,
    session_id: &str,
) -> Result<CuptiCapture, CuptiSnapshotError> {
    let mut stream =
        UnixStream::connect(socket_path).map_err(|source| CuptiSnapshotError::Connect {
            path: socket_path.to_owned(),
            source,
        })?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(CuptiSnapshotError::Configure)?;
    let mut bytes = Vec::new();
    read_snapshot(&mut stream, &mut bytes)?;
    decode_capture(&bytes, session_id).map_err(CuptiSnapshotError::Decode)
}

fn read_snapshot(reader: &mut impl Read, bytes: &mut Vec<u8>) -> Result<(), CuptiSnapshotError> {
    reader
        .read_to_end(bytes)
        .map_err(CuptiSnapshotError::Read)?;
    Ok(())
}

/// Decode an xprobe CUPTI binary capture into versioned protocol events.
///
/// The capture header advertises timestamp and record capabilities with
/// feature flags. GPU activity uses the host monotonic clock when the
/// corresponding feature is set; otherwise it remains in CUPTI's clock.
///
/// # Errors
///
/// Returns [`CuptiDecodeError`] when the capture header, size, record kind, or
/// bounded name does not match a supported ABI.
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
        return Err(CuptiDecodeError::InvalidHeaderSize {
            version: abi_version,
            actual: header_size,
            expected: HEADER_SIZE_U32,
        });
    }
    let record_size = read_u32(bytes, 16);
    if record_size != RECORD_SIZE_U32 {
        return Err(CuptiDecodeError::InvalidRecordSize(record_size));
    }
    let feature_flags = read_u32(bytes, 20);
    let unsupported_features = feature_flags & !SUPPORTED_FEATURES;
    if unsupported_features != 0 {
        return Err(CuptiDecodeError::UnsupportedFeatureFlags(
            unsupported_features,
        ));
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
        events.push(decode_record(record, index, session_id, feature_flags)?);
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

fn decode_record(
    record: &[u8],
    index: usize,
    session_id: &str,
    feature_flags: u32,
) -> Result<Event, CuptiDecodeError> {
    let kind = read_u32(record, 8);
    let (source, event_type) = match kind {
        1 => (EventSource::CuptiCallback, EventType::CudaApiEntry),
        2 => (EventSource::CuptiCallback, EventType::CudaApiExit),
        3 => (EventSource::CuptiActivity, EventType::GpuKernelStart),
        4 => (EventSource::CuptiActivity, EventType::GpuKernelEnd),
        5 if feature_flags & FEATURE_TRANSFER_RECORDS != 0 => {
            (EventSource::CuptiActivity, EventType::GpuMemcpyStart)
        }
        6 if feature_flags & FEATURE_TRANSFER_RECORDS != 0 => {
            (EventSource::CuptiActivity, EventType::GpuMemcpyEnd)
        }
        7 if feature_flags & FEATURE_TRANSFER_RECORDS != 0 => {
            (EventSource::CuptiActivity, EventType::GpuMemsetStart)
        }
        8 if feature_flags & FEATURE_TRANSFER_RECORDS != 0 => {
            (EventSource::CuptiActivity, EventType::GpuMemsetEnd)
        }
        _ => return Err(CuptiDecodeError::UnknownRecordKind { index, kind }),
    };
    let timestamp_raw = read_u64(record, 0);
    let name_bytes = &record[72..200];
    let name_length = name_bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name_bytes.len());
    let name = str::from_utf8(&name_bytes[..name_length])
        .map_err(|_| CuptiDecodeError::InvalidName { index })?;
    let is_api = matches!(kind, 1 | 2);
    let is_kernel = matches!(kind, 3 | 4);
    let is_memcpy = matches!(kind, 5 | 6);
    let is_transfer = matches!(kind, 5..=8);
    let is_start = matches!(kind, 3 | 5 | 7);
    let is_end = matches!(kind, 4 | 6 | 8);
    let (timestamp_ns, clock_domain, timestamp_error_ns) = if is_api {
        (timestamp_raw, ClockDomain::HostMonotonic, None)
    } else if feature_flags & FEATURE_HOST_MONOTONIC_TIMESTAMPS != 0 {
        (
            timestamp_raw,
            ClockDomain::CuptiNormalizedToHostMonotonic,
            None,
        )
    } else {
        (timestamp_raw, ClockDomain::Cupti, None)
    };
    let mut attributes = BTreeMap::new();
    if is_api {
        attributes.insert("cuda_api_name".to_owned(), Value::String(name.to_owned()));
    }
    if matches!(kind, 7 | 8) {
        attributes.insert("memset_value".to_owned(), Value::from(read_u32(record, 56)));
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
        timestamp_raw,
        timestamp_ns,
        clock_domain,
        timestamp_error_ns,
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
            kernel_name: is_kernel.then(|| name.to_owned()),
            kernel_name_mangled: None,
            start_ns: is_start.then_some(timestamp_ns),
            end_ns: is_end.then_some(timestamp_ns),
            grid: is_kernel.then(|| decode_dim(record, 44)).flatten(),
            block: is_kernel.then(|| decode_dim(record, 56)).flatten(),
            bytes: is_transfer.then(|| read_split_u64(record, 44)),
            memcpy_kind: is_memcpy.then(|| decode_memcpy_kind(read_u32(record, 52))),
        }),
        attributes,
    })
}

fn read_split_u64(record: &[u8], offset: usize) -> u64 {
    u64::from(read_u32(record, offset)) | (u64::from(read_u32(record, offset + 4)) << 32)
}

const fn decode_memcpy_kind(kind: u32) -> MemcpyKind {
    match kind {
        1 | 3 => MemcpyKind::HostToDevice,
        2 | 4 => MemcpyKind::DeviceToHost,
        5..=8 => MemcpyKind::DeviceToDevice,
        9 => MemcpyKind::HostToHost,
        10 => MemcpyKind::PeerToPeer,
        _ => MemcpyKind::Unknown,
    }
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
    use std::io::Cursor;

    use super::{
        CuptiDecodeError, HEADER_SIZE, OUTPUT_MAGIC, RECORD_SIZE, decode_capture, read_snapshot,
    };
    use xprobe_protocol::{ClockDomain, EventSource, EventType, MemcpyKind};

    fn capture(records: &[[u8; RECORD_SIZE]]) -> Vec<u8> {
        let mut bytes = vec![0_u8; HEADER_SIZE + records.len() * RECORD_SIZE];
        bytes[0..8].copy_from_slice(OUTPUT_MAGIC);
        bytes[8..12].copy_from_slice(&super::ABI_VERSION.to_le_bytes());
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

    fn normalized_capture(records: &[[u8; RECORD_SIZE]]) -> Vec<u8> {
        let mut bytes = capture(records);
        bytes[20..24].copy_from_slice(&super::FEATURE_HOST_MONOTONIC_TIMESTAMPS.to_le_bytes());
        bytes
    }

    fn transfer_capture(records: &[[u8; RECORD_SIZE]]) -> Vec<u8> {
        let mut bytes = normalized_capture(records);
        bytes[20..24].copy_from_slice(&super::SUPPORTED_FEATURES.to_le_bytes());
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

    fn transfer_record(
        kind: u32,
        timestamp: u64,
        correlation: u32,
        bytes: u64,
        payload_kind: u32,
    ) -> [u8; RECORD_SIZE] {
        let mut record = record(kind, timestamp, correlation, "");
        record[44..52].copy_from_slice(&bytes.to_le_bytes());
        if matches!(kind, 5 | 6) {
            record[52..56].copy_from_slice(&payload_kind.to_le_bytes());
        } else {
            record[56..60].copy_from_slice(&payload_kind.to_le_bytes());
        }
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
    fn rejects_transfer_records_without_feature_flag() {
        let memcpy = transfer_record(5, 100, 1, 4096, 1);
        let error = decode_capture(&normalized_capture(&[memcpy]), "xp_test")
            .expect_err("transfer records require their feature flag");
        assert_eq!(
            error,
            CuptiDecodeError::UnknownRecordKind { index: 0, kind: 5 }
        );
    }

    #[test]
    fn normalizes_flagged_gpu_timestamps_to_host_monotonic() {
        let api = record(1, 10_400, 42, "cudaLaunchKernel");
        let kernel = record(3, 10_525, 42, "test_kernel");
        let decoded = decode_capture(&normalized_capture(&[kernel, api]), "xp_test")
            .expect("normalized capture must decode");

        assert_eq!(decoded.events[0].timestamp_ns, 10_400);
        assert_eq!(decoded.events[0].clock_domain, ClockDomain::HostMonotonic);
        assert_eq!(decoded.events[1].timestamp_raw, 10_525);
        assert_eq!(decoded.events[1].timestamp_ns, 10_525);
        assert_eq!(
            decoded.events[1].clock_domain,
            ClockDomain::CuptiNormalizedToHostMonotonic
        );
        assert_eq!(decoded.events[1].timestamp_error_ns, None);
        assert_eq!(
            decoded.events[1]
                .cuda
                .as_ref()
                .expect("CUDA payload")
                .start_ns,
            Some(10_525)
        );
    }

    #[test]
    fn decodes_flagged_memcpy_and_memset_activity() {
        let bytes = (1_u64 << 32) + 99;
        let memcpy = transfer_record(5, 10_500, 43, bytes, 1);
        let memset = transfer_record(8, 10_700, 44, 4096, 0xab);
        let decoded = decode_capture(&transfer_capture(&[memcpy, memset]), "xp_test")
            .expect("transfer capture must decode");

        let memcpy_event = &decoded.events[0];
        assert_eq!(memcpy_event.event_type, EventType::GpuMemcpyStart);
        let memcpy_payload = memcpy_event.cuda.as_ref().expect("CUDA payload");
        assert_eq!(memcpy_payload.bytes, Some(bytes));
        assert_eq!(memcpy_payload.memcpy_kind, Some(MemcpyKind::HostToDevice));
        assert_eq!(memcpy_payload.start_ns, Some(10_500));
        assert_eq!(memcpy_payload.grid, None);

        let memset_event = &decoded.events[1];
        assert_eq!(memset_event.event_type, EventType::GpuMemsetEnd);
        let memset_payload = memset_event.cuda.as_ref().expect("CUDA payload");
        assert_eq!(memset_payload.bytes, Some(4096));
        assert_eq!(memset_payload.end_ns, Some(10_700));
        assert_eq!(memset_event.attributes["memset_value"], 0xab);
    }

    #[test]
    fn rejects_unknown_feature_flags() {
        let mut bytes = capture(&[]);
        bytes[20..24].copy_from_slice(&4_u32.to_le_bytes());
        assert_eq!(
            decode_capture(&bytes, "xp_test"),
            Err(CuptiDecodeError::UnsupportedFeatureFlags(4))
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

    #[test]
    fn reads_snapshot_until_eof() {
        let capture = normalized_capture(&[record(3, 100, 7, "test_kernel")]);
        let mut reader = Cursor::new(capture);
        let mut bytes = Vec::new();
        read_snapshot(&mut reader, &mut bytes).expect("snapshot must read");
        let decoded = decode_capture(&bytes, "xp_live").expect("snapshot must decode");

        assert_eq!(decoded.events.len(), 1);
        assert_eq!(decoded.events[0].session_id, "xp_live");
        assert_eq!(decoded.events[0].event_type, EventType::GpuKernelStart);
    }
}
