use clap::Args;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "xprobe", version, about = "Runtime host-to-GPU latency probe")]
pub(crate) struct Cli {
    /// Print human-readable output even when stdout is not a terminal.
    #[arg(long, global = true)]
    pub(crate) human: bool,

    #[command(subcommand)]
    pub(crate) command: Command,
}

impl Cli {
    /// Choose the output form. JSON is the default whenever stdout is not a
    /// terminal, so agents and pipelines need no flags; `--human` keeps text.
    ///
    /// # Errors
    ///
    /// Returns a message when `--human` and `--json` are both set.
    pub(crate) fn resolve_output(&mut self, stdout_is_terminal: bool) -> Result<(), &'static str> {
        let human = self.human;
        let Some(json) = self.command.json_flag() else {
            return Ok(());
        };
        if human && *json {
            return Err("--human cannot be used with --json");
        }
        if !human && !stdout_is_terminal {
            *json = true;
        }
        Ok(())
    }
}

impl Command {
    fn json_flag(&mut self) -> Option<&mut bool> {
        match self {
            Self::Doctor(args) => Some(&mut args.json),
            Self::Discover(args) => Some(&mut args.json),
            Self::Inspect(args) => Some(&mut args.json),
            Self::Resolve(args) => Some(&mut args.json),
            Self::Validate(args) => Some(&mut args.output.json),
            Self::Measure(args) => Some(&mut args.output.json),
            Self::Trace(args) => Some(&mut args.json),
            Self::Export(args) => Some(&mut args.json),
            Self::Capture(args) | Self::Dev(args) => match &mut args.command {
                DevCommand::Uprobe(args) if args.output.jsonl => None,
                DevCommand::Uprobe(args) => Some(&mut args.output.json),
                DevCommand::Cupti(args) => Some(&mut args.json),
            },
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Inspect local tracing and GPU capabilities.
    Doctor(DoctorArgs),
    /// List NVML-confirmed CUDA context holders under a process-tree root.
    Discover(DiscoverArgs),
    /// Inspect a target process without attaching probes.
    #[command(hide = true)]
    Inspect(InspectArgs),
    /// Resolve a userspace event selector against a target process.
    #[command(hide = true)]
    Resolve(ResolveArgs),
    /// Validate two event selectors and their correlation policy.
    Validate(ValidateArgs),
    /// Measure latency between two events in files or a running process.
    Measure(Box<MeasureArgs>),
    /// Run a live measurement from a versioned specification.
    #[command(hide = true)]
    Trace(TraceArgs),
    /// Export completed captures to a stable trace format.
    #[command(hide = true)]
    Export(ExportArgs),
    /// Run bounded event collectors.
    #[command(hide = true)]
    Capture(DevArgs),
    /// Run low-level development probes.
    #[command(hide = true)]
    Dev(DevArgs),
}

#[derive(Debug, Args)]
pub(crate) struct DevArgs {
    #[command(subcommand)]
    pub(crate) command: DevCommand,
}

#[derive(Debug, Args)]
pub(crate) struct TraceArgs {
    /// Versioned `MeasurementSpec` JSON file.
    #[arg(long)]
    pub(crate) spec: PathBuf,

    /// Unix socket exposed by the target's xprobe CUPTI agent.
    #[arg(long, hide = true)]
    pub(crate) cupti_socket: Option<PathBuf>,

    /// Emit only the versioned JSON result on stdout (default when stdout is
    /// not a terminal).
    #[arg(long)]
    pub(crate) json: bool,

    /// Disable colored output.
    #[arg(long)]
    pub(crate) no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    pub(crate) non_interactive: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum ExportFormatArg {
    Jsonl,
    Chrome,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum EvidenceArg {
    Summary,
    Full,
}

impl EvidenceArg {
    pub(crate) const fn mode(self) -> xprobe_protocol::EvidenceMode {
        match self {
            Self::Summary => xprobe_protocol::EvidenceMode::Summary,
            Self::Full => xprobe_protocol::EvidenceMode::Full,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct ExportArgs {
    /// Completed CUPTI binary, host capture JSON, or Event JSONL; repeat to merge.
    #[arg(long, required = true)]
    pub(crate) input: Vec<PathBuf>,

    /// Artifact format.
    #[arg(long, value_enum)]
    pub(crate) format: ExportFormatArg,

    /// Destination artifact path.
    #[arg(long)]
    pub(crate) output: PathBuf,

    /// Emit only the versioned export result on stdout.
    #[arg(long)]
    pub(crate) json: bool,

    /// Disable colored output.
    #[arg(long)]
    pub(crate) no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    pub(crate) non_interactive: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum DevCommand {
    /// Capture entries to one userspace function.
    Uprobe(UprobeArgs),
    /// Decode an xprobe CUPTI capture as Event JSONL.
    Cupti(CuptiArgs),
}

#[derive(Debug, Clone, Copy, Args)]
pub(crate) struct DoctorArgs {
    /// Emit only the versioned JSON result on stdout (default when stdout is
    /// not a terminal).
    #[arg(long)]
    pub(crate) json: bool,

    /// Disable colored output.
    #[arg(long)]
    pub(crate) no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    pub(crate) non_interactive: bool,
}

#[derive(Debug, Clone, Copy, Args)]
pub(crate) struct DiscoverArgs {
    /// Target process ID.
    #[arg(long)]
    pub(crate) pid: u32,

    /// Maximum number of CUDA worker candidates to return.
    #[arg(long, default_value_t = 200)]
    pub(crate) limit: usize,

    /// Emit only the versioned JSON result on stdout (default when stdout is
    /// not a terminal).
    #[arg(long)]
    pub(crate) json: bool,

    /// Disable colored output.
    #[arg(long)]
    pub(crate) no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    pub(crate) non_interactive: bool,
}

#[derive(Debug, Clone, Copy, Args)]
pub(crate) struct InspectArgs {
    /// Target process ID.
    #[arg(long)]
    pub(crate) pid: u32,

    /// Emit only the versioned JSON result on stdout (default when stdout is
    /// not a terminal).
    #[arg(long)]
    pub(crate) json: bool,

    /// Disable colored output.
    #[arg(long)]
    pub(crate) no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    pub(crate) non_interactive: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ResolveArgs {
    /// Target process ID.
    #[arg(long)]
    pub(crate) pid: u32,

    /// Event selector for a mapped ELF symbol, C++ signature, or file offset.
    #[arg(long, alias = "event")]
    pub(crate) selector: String,

    /// Emit only the versioned JSON result on stdout (default when stdout is
    /// not a terminal).
    #[arg(long)]
    pub(crate) json: bool,

    /// Disable colored output.
    #[arg(long)]
    pub(crate) no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    pub(crate) non_interactive: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ValidateArgs {
    /// Target process ID.
    #[arg(long, required_unless_present = "spec")]
    pub(crate) pid: Option<u32>,

    /// Validate a versioned measurement graph spec; its target selects the
    /// process.
    #[arg(
        long,
        conflicts_with_all = ["pid", "from", "to", "match_policy", "cpu_sample", "syscall_aggregate"]
    )]
    pub(crate) spec: Option<PathBuf>,

    /// Start event selector.
    #[arg(long)]
    pub(crate) from: Option<String>,

    /// End event selector.
    #[arg(long)]
    pub(crate) to: Option<String>,

    /// Correlation policy.
    #[arg(long = "match")]
    pub(crate) match_policy: Option<String>,

    /// Validate bounded PID-scoped CPU sampling instead of an event pair.
    #[arg(long, conflicts_with_all = ["from", "to", "match_policy", "syscall_aggregate"])]
    pub(crate) cpu_sample: bool,

    /// Validate bounded PID-scoped syscall aggregation instead of an event pair.
    #[arg(long, conflicts_with_all = ["from", "to", "match_policy", "cpu_sample"])]
    pub(crate) syscall_aggregate: bool,

    #[command(flatten)]
    pub(crate) output: CommonOutputArgs,
}

#[derive(Debug, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "mutually exclusive clap mode flags with declared conflicts"
)]
pub(crate) struct MeasureArgs {
    /// Versioned measurement JSON for a live target.
    #[arg(long, conflicts_with_all = ["input", "pid", "from", "to", "match_policy", "cpu_sample", "syscall_aggregate", "samples", "duration_ms", "timeout_ms", "max_events", "max_samples", "frequency_hz", "stack_depth", "max_threads", "max_inflight", "aggregate", "max_groups", "name"])]
    pub(crate) spec: Option<PathBuf>,

    /// Completed CUPTI binary, host capture JSON, or Event JSONL; repeat to merge.
    #[arg(long)]
    pub(crate) input: Vec<PathBuf>,

    /// Collect from a running target process instead of completed capture files.
    #[arg(long)]
    pub(crate) pid: Option<u32>,

    /// Unix socket exposed by the target's xprobe CUPTI agent.
    #[arg(long, hide = true)]
    pub(crate) cupti_socket: Option<PathBuf>,

    /// CUPTI agent shared object used for automatic online injection.
    #[arg(long)]
    pub(crate) agent: Option<PathBuf>,

    /// Write the complete bounded event capture to this file. Live captures
    /// default to a private file under the temporary directory.
    #[arg(long)]
    pub(crate) events_out: Option<PathBuf>,

    /// Triage one bounded window: thread time, cgroup throttling, CPU samples,
    /// syscall totals, GPU health, and CUDA kernel activity, with ranked
    /// findings and the next exact measurement. Requires --pid and
    /// --duration-ms.
    #[arg(
        long,
        requires_all = ["pid", "duration_ms"],
        conflicts_with_all = [
            "spec", "input", "from", "to", "match_policy", "samples", "cpu_sample",
            "syscall_aggregate", "aggregate", "events_out", "format"
        ]
    )]
    pub(crate) triage: bool,

    /// Inline matched pairs: `summary` keeps rank exemplars and the artifact
    /// path; `full` also inlines every pair.
    #[arg(
        long,
        value_enum,
        default_value_t = EvidenceArg::Summary,
        conflicts_with_all = ["cpu_sample", "syscall_aggregate", "aggregate", "triage"]
    )]
    pub(crate) evidence: EvidenceArg,

    /// Evidence event format; defaults to jsonl when --events-out is set.
    #[arg(long, value_enum)]
    pub(crate) format: Option<ExportFormatArg>,

    /// Bound foreground collection and cleanup to this many milliseconds.
    #[arg(long, default_value_t = 30_000)]
    pub(crate) timeout_ms: u64,

    /// Start event selector.
    #[arg(long)]
    pub(crate) from: Option<String>,

    /// End event selector.
    #[arg(long)]
    pub(crate) to: Option<String>,

    /// Correlation policy.
    #[arg(long = "match")]
    pub(crate) match_policy: Option<String>,

    /// Collect a bounded PID-scoped CPU hotspot inventory.
    #[arg(long, conflicts_with_all = ["input", "from", "to", "match_policy", "samples", "aggregate", "events_out", "format", "cupti_socket", "agent"])]
    pub(crate) cpu_sample: bool,

    /// Target CPU sampling frequency in hertz.
    #[arg(
        long,
        requires = "cpu_sample",
        default_value_if("cpu_sample", "true", "99")
    )]
    pub(crate) frequency_hz: Option<u64>,

    /// Bound all observed CPU sample records.
    #[arg(
        long,
        requires = "cpu_sample",
        default_value_if("cpu_sample", "true", "10000")
    )]
    pub(crate) max_samples: Option<u64>,

    /// Bound user-space callchain depth.
    #[arg(
        long,
        requires = "cpu_sample",
        default_value_if("cpu_sample", "true", "64")
    )]
    pub(crate) stack_depth: Option<u32>,

    /// Bound target threads attached by CPU sampling.
    #[arg(
        long,
        requires = "cpu_sample",
        default_value_if("cpu_sample", "true", "1024")
    )]
    pub(crate) max_threads: Option<u32>,

    /// Aggregate all syscall lifecycles in bounded BPF maps.
    #[arg(long, conflicts_with_all = ["input", "from", "to", "match_policy", "samples", "cpu_sample", "aggregate", "events_out", "format", "cupti_socket", "agent"])]
    pub(crate) syscall_aggregate: bool,

    /// Bound concurrent syscall lifecycle starts retained in BPF.
    #[arg(
        long,
        requires = "syscall_aggregate",
        default_value_if("syscall_aggregate", "true", "1024")
    )]
    pub(crate) max_inflight: Option<u64>,

    /// Stop after this many matched samples.
    #[arg(long)]
    pub(crate) samples: Option<usize>,

    /// Restrict events to this many milliseconds from the first selected event.
    #[arg(long)]
    pub(crate) duration_ms: Option<u64>,

    /// Reject captures containing more events than this limit.
    #[arg(long, default_value_t = 100_000)]
    pub(crate) max_events: usize,

    /// Return bounded activity aggregates instead of exact event evidence.
    #[arg(long, conflicts_with_all = ["input", "samples", "events_out", "format"])]
    pub(crate) aggregate: bool,

    /// Bound distinct groups retained by aggregate or CPU inventory mode.
    #[arg(
        long,
        default_value_if("aggregate", "true", "4096"),
        default_value_if("cpu_sample", "true", "256"),
        default_value_if("syscall_aggregate", "true", "256")
    )]
    pub(crate) max_groups: Option<usize>,

    /// Optional measurement name.
    #[arg(long)]
    pub(crate) name: Option<String>,

    #[command(flatten)]
    pub(crate) output: CommonOutputArgs,
}

#[derive(Debug, Clone, Copy, Args)]
pub(crate) struct CommonOutputArgs {
    /// Emit only the versioned JSON result on stdout (default when stdout is
    /// not a terminal).
    #[arg(long)]
    pub(crate) json: bool,

    /// Disable colored output.
    #[arg(long)]
    pub(crate) no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    pub(crate) non_interactive: bool,
}

#[derive(Debug, Args)]
pub(crate) struct UprobeArgs {
    /// Target process ID.
    #[arg(long)]
    pub(crate) pid: u32,

    /// Executable or mapped shared library containing the symbol.
    #[arg(long)]
    pub(crate) binary: PathBuf,

    /// ELF function symbol to attach to.
    #[arg(long)]
    pub(crate) symbol: String,

    /// Attach at function return instead of function entry.
    #[arg(long = "return")]
    pub(crate) return_probe: bool,

    /// Probe identifier stored in each event.
    #[arg(long, default_value_t = 1)]
    pub(crate) probe_id: u32,

    /// Stop after this many events.
    #[arg(long, default_value_t = 1)]
    pub(crate) samples: usize,

    /// Stop waiting after this many milliseconds.
    #[arg(long, default_value_t = 5_000)]
    pub(crate) timeout_ms: u64,

    #[command(flatten)]
    pub(crate) output: EventOutputArgs,

    /// Disable colored output.
    #[arg(long)]
    pub(crate) no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    pub(crate) non_interactive: bool,
}

#[derive(Debug, Clone, Copy, Args)]
pub(crate) struct EventOutputArgs {
    /// Emit only the versioned JSON result on stdout (default when stdout is
    /// not a terminal).
    #[arg(long)]
    pub(crate) json: bool,

    /// Emit one versioned Event JSON object per line.
    #[arg(long, conflicts_with = "json")]
    pub(crate) jsonl: bool,
}

#[derive(Debug, Args)]
pub(crate) struct CuptiArgs {
    /// Raw binary capture written by the xprobe CUPTI agent.
    #[arg(long, required_unless_present = "socket", conflicts_with = "socket")]
    pub(crate) input: Option<PathBuf>,

    /// Unix socket exposed by a running xprobe CUPTI agent.
    #[arg(long, required_unless_present = "input", conflicts_with = "input")]
    pub(crate) socket: Option<PathBuf>,

    /// Stop waiting for an online snapshot after this many milliseconds.
    #[arg(long, default_value_t = 10_000)]
    pub(crate) timeout_ms: u64,

    /// Session identifier written into every Event.
    #[arg(long)]
    pub(crate) session_id: String,

    /// Emit one versioned Event JSON object per line.
    #[arg(long)]
    pub(crate) json: bool,

    /// Disable colored output.
    #[arg(long)]
    pub(crate) no_color: bool,

    /// Never wait for user input.
    #[arg(long)]
    pub(crate) non_interactive: bool,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command};

    fn json(arguments: &[&str], terminal: bool) -> Result<bool, &'static str> {
        let mut cli = Cli::try_parse_from(arguments).expect("arguments must parse");
        cli.resolve_output(terminal)?;
        Ok(match cli.command {
            Command::Doctor(args) => args.json,
            Command::Measure(args) => args.output.json,
            _ => unreachable!("test covers doctor and measure"),
        })
    }

    #[test]
    fn defaults_to_json_only_when_stdout_is_not_a_terminal() {
        assert_eq!(json(&["xprobe", "doctor"], false), Ok(true));
        assert_eq!(json(&["xprobe", "doctor"], true), Ok(false));
        assert_eq!(json(&["xprobe", "doctor", "--json"], true), Ok(true));
        assert_eq!(
            json(&["xprobe", "measure", "--input", "a.jsonl"], false),
            Ok(true)
        );
    }

    #[test]
    fn human_keeps_text_output_and_conflicts_with_json() {
        assert_eq!(json(&["xprobe", "doctor", "--human"], false), Ok(false));
        assert_eq!(json(&["xprobe", "--human", "doctor"], false), Ok(false));
        assert!(json(&["xprobe", "doctor", "--human", "--json"], true).is_err());
    }

    #[test]
    fn leaves_jsonl_event_streams_alone() {
        let mut cli = Cli::try_parse_from([
            "xprobe",
            "dev",
            "uprobe",
            "--pid",
            "1",
            "--binary",
            "/bin/true",
            "--symbol",
            "main",
            "--jsonl",
        ])
        .expect("uprobe arguments must parse");
        cli.resolve_output(false).expect("jsonl output is valid");
        let Command::Dev(args) = cli.command else {
            unreachable!("dev command parsed")
        };
        let super::DevCommand::Uprobe(args) = args.command else {
            unreachable!("uprobe parsed")
        };
        assert!(args.output.jsonl);
        assert!(!args.output.json);
    }
}
