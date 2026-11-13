use xprobe_protocol::CapabilityReport;
use xprobe_protocol::CheckResult;
use xprobe_protocol::DiscoveryResult;
use xprobe_protocol::HostCaptureResult;
use xprobe_protocol::MeasurementResult;
use xprobe_protocol::ProcessReport;
use xprobe_protocol::ResolvedProbe;
use xprobe_protocol::SchemaVersion;
use xprobe_protocol::ValidationResult;

pub(crate) fn print_human_report(report: &CapabilityReport) {
    println!(
        "xprobe doctor (schema {})",
        schema_version(report.schema_version)
    );
    println!();
    println!("Environment:");
    println!("  OS             {}", report.environment.operating_system);
    println!("  architecture   {}", report.environment.architecture);
    println!("  kernel         {}", report.environment.kernel_release);
    println!("  effective UID  {}", report.environment.effective_uid);
    println!(
        "  container      {}",
        report
            .environment
            .container
            .as_deref()
            .unwrap_or("none detected")
    );
    println!("  PID namespace  {}", report.environment.pid_namespace);
    println!();
    println!("Capabilities:");
    println!("  uprobe          {}", yes_no(report.capabilities.uprobe));
    println!(
        "  uretprobe       {}",
        yes_no(report.capabilities.uretprobe)
    );
    println!(
        "  tracepoint      {}",
        yes_no(report.capabilities.tracepoint)
    );
    println!(
        "  CUDA callback   {}",
        yes_no(report.capabilities.cuda_callback)
    );
    println!(
        "  CUDA activity   {}",
        yes_no(report.capabilities.cuda_activity)
    );
    println!(
        "  runtime inject  {}",
        yes_no(report.capabilities.runtime_injection)
    );
    println!();
    println!("Checks:");
    print_check("BTF", &report.checks.btf);
    print_check("eBPF permissions", &report.checks.ebpf_permissions);
    print_check("kernel lockdown", &report.checks.kernel_lockdown);
    print_check("perf paranoid", &report.checks.perf_event_paranoid);
    print_check("ptrace scope", &report.checks.ptrace_scope);
    print_check("NVIDIA driver", &report.checks.nvidia_driver);
    print_check("CUDA driver", &report.checks.cuda_driver);
    print_check("CUDA toolkit", &report.checks.cuda_toolkit);
    print_check("CUPTI", &report.checks.cupti);

    if !report.warnings.is_empty() {
        println!();
        println!("Warnings:");
        for warning in &report.warnings {
            println!("  {}: {}", warning.code, warning.message);
        }
    }
}

pub(crate) fn print_process_report(report: &ProcessReport) {
    println!("Process: PID {}", report.target.pid);
    println!("Executable: {}", report.executable);
    println!("Start time: {} ticks", report.target.process_start_time);
    println!("Namespace PIDs: {:?}", report.namespace_pids);
    println!("Mount namespace: {}", report.mount_namespace);
    println!(
        "Credentials: uid={} gid={}",
        report.credentials.effective_uid, report.credentials.effective_gid
    );
    println!();
    println!("CUDA:");
    println!("  libcuda          {}", yes_no(report.cuda.libcuda_loaded));
    println!(
        "  libcudart        {}",
        yes_no(report.cuda.libcudart_loaded)
    );
    println!(
        "  xprobe CUPTI    {}",
        yes_no(report.cuda.xprobe_cupti_loaded)
    );
    println!("  context          {:?}", report.cuda.context.status);
    println!();
    println!("Loaded shared libraries: {}", report.loaded_libraries.len());
}

pub(crate) fn print_discovery_result(result: &DiscoveryResult) {
    println!("Root: PID {}", result.root.pid);
    println!(
        "CUDA workers: {} of {}{}",
        result.candidates.len(),
        result.total_candidates,
        if result.truncated { " (truncated)" } else { "" }
    );
    for candidate in &result.candidates {
        println!(
            "  PID {} parent={} GPUs={} {}",
            candidate.target.pid,
            candidate.parent_pid,
            candidate.gpu_uuids.join(","),
            candidate.executable
        );
    }
    for warning in &result.warnings {
        eprintln!("{}: {}", warning.code, warning.message);
    }
}

pub(crate) fn print_host_capture(result: &HostCaptureResult) {
    println!(
        "Captured {} event(s), dropped {}, timed out: {}",
        result.captured, result.dropped, result.timed_out
    );
    for event in &result.events {
        println!(
            "  {}  pid={} tid={} cpu={} probe={}",
            event.timestamp_ns,
            event.pid,
            event.tid,
            event
                .cpu
                .map_or_else(|| "-".to_owned(), |cpu| cpu.to_string()),
            result.probe_id
        );
    }
}

pub(crate) fn print_resolved_probe(resolved: &ResolvedProbe) {
    println!("Target: PID {}", resolved.target.pid);
    println!("Binary: {}", resolved.binary_path);
    println!(
        "Build ID: {}",
        resolved.build_id.as_deref().unwrap_or("unavailable")
    );
    println!("Object: {:?}", resolved.object_kind);
    println!("Probe: {:?}", resolved.probe_kind);
    if let Some(symbol) = &resolved.symbol {
        println!("Symbol: {symbol}");
    }
    if let Some(symbol) = &resolved.symbol_demangled {
        println!("Demangled: {symbol}");
    }
    println!("File offset: {:#x}", resolved.file_offset);
    println!("Runtime address: {:#x}", resolved.runtime_address);
    println!(
        "Mapping: {:#x}-{:#x} (file offset {:#x})",
        resolved.mapping.start_address, resolved.mapping.end_address, resolved.mapping.file_offset
    );
}

pub(crate) fn print_validation_result(result: &ValidationResult) {
    println!(
        "Validation: {}",
        if result.valid { "valid" } else { "invalid" }
    );
    println!("Target: PID {}", result.target.pid);
    println!("Start: {}", result.start.selector);
    println!("End: {}", result.end.selector);
    println!("Match: {:?}", result.match_policy);
    println!(
        "Recommended match: {:?} ({:?})",
        result.policy_recommendation.policy, result.policy_recommendation.reason
    );
    println!(
        "Agent activation: {:?}",
        result.requirements.agent_activation
    );
    println!("Target mutation: {}", result.requirements.target_mutation);
    for issue in &result.issues {
        println!("Issue: {}: {}", issue.code, issue.message);
    }
    for warning in &result.warnings {
        println!("Warning: {}: {}", warning.code, warning.message);
    }
}

pub(crate) fn print_measurement_result(result: &MeasurementResult) {
    let latency = &result.measurement.latency_ns;
    println!(
        "Measurement: {}",
        result.measurement.name.as_deref().unwrap_or("unnamed")
    );
    println!("Matched samples: {}", result.measurement.samples.matched);
    println!("Evidence pairs: {}", result.evidence.len());
    println!("Correlation: {}", result.correlation.method);
    println!("Clock: {}", result.clock.alignment);
    println!("Latency (ns):");
    println!("  min   {}", latency.min);
    println!("  mean  {:.2}", latency.mean);
    println!("  p50   {}", latency.p50);
    println!("  p90   {}", latency.p90);
    println!("  p95   {}", latency.p95);
    println!("  p99   {}", latency.p99);
    println!("  max   {}", latency.max);
}

pub(crate) fn print_check(name: &str, result: &CheckResult) {
    println!(
        "  {name:<17} {:<11} {}",
        format!("{:?}", result.status).to_lowercase(),
        result.detail.as_deref().unwrap_or_default()
    );
}

pub(crate) const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

pub(crate) const fn schema_version(version: SchemaVersion) -> &'static str {
    match version {
        SchemaVersion::V2 => "2.0",
    }
}
