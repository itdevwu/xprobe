//! NVML device health sampled through `nvidia-smi`.

use std::{collections::BTreeMap, error::Error, fmt, io, process::Command};

use xprobe_protocol::{GpuDeviceHealth, PcieLink};

const FIELDS: &str = "index,uuid,utilization.gpu,utilization.memory,clocks_event_reasons.active,\
temperature.gpu,power.draw,pcie.link.gen.current,pcie.link.gen.max,pcie.link.width.current,\
pcie.link.width.max";
const LEGACY_FIELDS: &str = "index,uuid,utilization.gpu,utilization.memory,clocks_throttle_reasons.active,\
temperature.gpu,power.draw,pcie.link.gen.current,pcie.link.gen.max,pcie.link.width.current,\
pcie.link.width.max";

/// NVML clock event reason bits and their names.
const CLOCK_EVENT_REASONS: [(u64, &str); 9] = [
    (0x1, "gpu_idle"),
    (0x2, "applications_clocks_setting"),
    (0x4, "sw_power_cap"),
    (0x8, "hw_slowdown"),
    (0x10, "sync_boost"),
    (0x20, "sw_thermal_slowdown"),
    (0x40, "hw_thermal_slowdown"),
    (0x80, "hw_power_brake_slowdown"),
    (0x100, "display_clock_setting"),
];

/// One device row from one query.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceSample {
    pub index: u32,
    pub uuid: String,
    pub utilization_pct: Option<u32>,
    pub memory_utilization_pct: Option<u32>,
    pub clock_event_reasons: Option<u64>,
    pub temperature_c: Option<u32>,
    pub power_w: Option<f64>,
    pub pcie_generation: Option<(u32, u32)>,
    pub pcie_width: Option<(u32, u32)>,
}

#[derive(Debug)]
pub enum GpuHealthError {
    Command(io::Error),
    Failed { status: Option<i32>, stderr: String },
    InvalidOutput(String),
}

impl fmt::Display for GpuHealthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command(error) => write!(formatter, "failed to run nvidia-smi: {error}"),
            Self::Failed { status, stderr } => {
                write!(
                    formatter,
                    "nvidia-smi failed with status {status:?}: {stderr}"
                )
            }
            Self::InvalidOutput(line) => write!(formatter, "invalid nvidia-smi row: {line:?}"),
        }
    }
}

impl Error for GpuHealthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Command(error) => Some(error),
            _ => None,
        }
    }
}

/// Query every visible device once.
///
/// # Errors
///
/// Returns [`GpuHealthError`] when `nvidia-smi` is missing, fails with both
/// field spellings, or prints a malformed row.
pub fn query() -> Result<Vec<DeviceSample>, GpuHealthError> {
    match run(FIELDS) {
        Err(GpuHealthError::Failed { .. }) => run(LEGACY_FIELDS),
        result => result,
    }
}

fn run(fields: &str) -> Result<Vec<DeviceSample>, GpuHealthError> {
    let output = Command::new("nvidia-smi")
        .args([
            &format!("--query-gpu={fields}"),
            "--format=csv,noheader,nounits",
        ])
        .output()
        .map_err(GpuHealthError::Command)?;
    if !output.status.success() {
        return Err(GpuHealthError::Failed {
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| GpuHealthError::InvalidOutput(error.to_string()))?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_row)
        .collect()
}

fn parse_row(line: &str) -> Result<DeviceSample, GpuHealthError> {
    let invalid = || GpuHealthError::InvalidOutput(line.to_owned());
    let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
    if fields.len() != 11 {
        return Err(invalid());
    }
    let index = fields[0].parse().map_err(|_| invalid())?;
    if fields[1].is_empty() {
        return Err(invalid());
    }
    let pair = |left: Option<u32>, right: Option<u32>| left.zip(right);
    Ok(DeviceSample {
        index,
        uuid: fields[1].to_owned(),
        utilization_pct: optional(fields[2]).map_err(|()| invalid())?,
        memory_utilization_pct: optional(fields[3]).map_err(|()| invalid())?,
        clock_event_reasons: optional_hex(fields[4]).map_err(|()| invalid())?,
        temperature_c: optional(fields[5]).map_err(|()| invalid())?,
        power_w: optional(fields[6]).map_err(|()| invalid())?,
        pcie_generation: pair(
            optional(fields[7]).map_err(|()| invalid())?,
            optional(fields[8]).map_err(|()| invalid())?,
        ),
        pcie_width: pair(
            optional(fields[9]).map_err(|()| invalid())?,
            optional(fields[10]).map_err(|()| invalid())?,
        ),
    })
}

/// `[N/A]` and `[Not Supported]` read as absent; anything else must parse.
fn optional<T: std::str::FromStr>(field: &str) -> Result<Option<T>, ()> {
    if field.starts_with('[') {
        return Ok(None);
    }
    field.parse().map(Some).map_err(|_| ())
}

fn optional_hex(field: &str) -> Result<Option<u64>, ()> {
    if field.starts_with('[') {
        return Ok(None);
    }
    let digits = field.strip_prefix("0x").ok_or(())?;
    u64::from_str_radix(digits, 16).map(Some).map_err(|_| ())
}

/// Summarize repeated queries per device, ordered by index.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn summarize(rounds: &[Vec<DeviceSample>]) -> Vec<GpuDeviceHealth> {
    let mut devices = BTreeMap::<(u32, &str), Vec<&DeviceSample>>::new();
    for sample in rounds.iter().flatten() {
        devices
            .entry((sample.index, &sample.uuid))
            .or_default()
            .push(sample);
    }
    devices
        .into_iter()
        .map(|((index, uuid), samples)| {
            let mean = |values: Vec<u32>| {
                (!values.is_empty())
                    .then(|| f64::from(values.iter().sum::<u32>()) / values.len() as f64)
            };
            let utilization = samples
                .iter()
                .filter_map(|s| s.utilization_pct)
                .collect::<Vec<_>>();
            let memory = samples
                .iter()
                .filter_map(|s| s.memory_utilization_pct)
                .collect::<Vec<_>>();
            let reasons = samples
                .iter()
                .filter_map(|s| s.clock_event_reasons)
                .fold(0, |union, bits| union | bits);
            let generation = samples.iter().filter_map(|s| s.pcie_generation);
            let width = samples.iter().filter_map(|s| s.pcie_width);
            let pcie = generation
                .clone()
                .map(|(current, _)| current)
                .min()
                .zip(generation.map(|(_, max)| max).max())
                .zip(
                    width
                        .clone()
                        .map(|(current, _)| current)
                        .min()
                        .zip(width.map(|(_, max)| max).max()),
                )
                .map(
                    |((generation_min, generation_max), (width_min, width_max))| PcieLink {
                        generation_min,
                        generation_max,
                        width_min,
                        width_max,
                    },
                );
            GpuDeviceHealth {
                index,
                uuid: uuid.to_owned(),
                samples: samples.len() as u64,
                utilization_max_pct: utilization.iter().copied().max(),
                utilization_mean_pct: mean(utilization),
                memory_utilization_mean_pct: mean(memory),
                clock_event_reasons: CLOCK_EVENT_REASONS
                    .iter()
                    .filter(|(bit, _)| reasons & bit != 0)
                    .map(|(_, name)| (*name).to_owned())
                    .collect(),
                temperature_max_c: samples.iter().filter_map(|s| s.temperature_c).max(),
                power_max_w: samples
                    .iter()
                    .filter_map(|s| s.power_w)
                    .fold(None, |max: Option<f64>, value| {
                        Some(max.map_or(value, |max| max.max(value)))
                    }),
                pcie,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_row, summarize};

    const ROW: &str = "0, GPU-a, 37, 12, 0x0000000000000004, 71, 95.5, 3, 4, 8, 16";

    #[test]
    fn parses_rows_including_unavailable_fields() {
        let sample = parse_row(ROW).unwrap();
        assert_eq!(sample.utilization_pct, Some(37));
        assert_eq!(sample.clock_event_reasons, Some(0x4));
        assert_eq!(sample.pcie_width, Some((8, 16)));
        let partial =
            parse_row("1, GPU-b, 0, 0, [N/A], 40, [Not Supported], 4, 4, 16, 16").unwrap();
        assert_eq!(partial.clock_event_reasons, None);
        assert_eq!(partial.power_w, None);
        assert!(parse_row("0, GPU-a, high, 0, 0x0, 1, 1, 1, 1, 1, 1").is_err());
        assert!(parse_row("0, GPU-a, 1").is_err());
    }

    #[test]
    fn summarizes_rounds_per_device() {
        let rounds = vec![
            vec![parse_row(ROW).unwrap()],
            vec![
                parse_row("0, GPU-a, 63, 20, 0x0000000000000041, 74, 101.0, 4, 4, 16, 16").unwrap(),
            ],
        ];
        let health = summarize(&rounds);
        assert_eq!(health.len(), 1);
        let device = &health[0];
        assert_eq!(device.samples, 2);
        assert_eq!(device.utilization_mean_pct, Some(50.0));
        assert_eq!(device.utilization_max_pct, Some(63));
        assert_eq!(
            device.clock_event_reasons,
            ["gpu_idle", "sw_power_cap", "hw_thermal_slowdown"]
        );
        assert_eq!(device.temperature_max_c, Some(74));
        assert_eq!(device.power_max_w, Some(101.0));
        let pcie = device.pcie.as_ref().unwrap();
        assert_eq!(
            (pcie.generation_min, pcie.width_min, pcie.width_max),
            (3, 8, 16)
        );
    }
}
