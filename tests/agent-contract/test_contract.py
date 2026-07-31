#!/usr/bin/env python3
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile


COMMON_FLAGS = ["--json", "--non-interactive", "--no-color"]
STABLE_COMMANDS = {
    "doctor",
    "discover",
    "validate",
    "measure",
}
SKILL_PATH = "skills/xprobe-measure-latency/SKILL.md"


def run_json(
    binary: pathlib.Path, arguments: list[str], schema_version: str = "2.0"
) -> dict:
    completed = subprocess.run(
        [binary, *arguments, *COMMON_FLAGS],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise AssertionError(
            f"{' '.join(arguments)} exited with {completed.returncode}"
        )
    assert completed.stderr == "", completed.stderr
    result = json.loads(completed.stdout)
    assert result["schema_version"] == schema_version
    assert result["ok"] is True
    return result


def check_skill(workspace: pathlib.Path) -> None:
    skill_path = workspace / SKILL_PATH
    skill_root = skill_path.parent.resolve()
    skill = skill_path.read_text()
    frontmatter = re.match(r"^---\n(.*?)\n---", skill, re.DOTALL)
    assert frontmatter is not None
    assert re.search(r"^name: xprobe-measure-latency$", frontmatter.group(1), re.MULTILINE)
    assert re.search(r"^description: .+", frontmatter.group(1), re.MULTILINE)
    normalized_skill = re.sub(r"\s+", " ", skill)

    for route in (
        "Existing artifact",
        "Known live boundary",
        "Unknown CPU or Python workload",
        "Unknown GPU or mixed workload",
        "Multiple processes",
        "Setup or repair",
    ):
        assert route in normalized_skill
    for adaptive_rule in (
        "Choose the shortest route",
        "skip installation, `doctor`, `discover`, and live attachment",
        "Do not run a broad inventory solely to satisfy a checklist",
        "Do not run CUDA discovery",
        "Start with bounded `--cpu-sample` evidence",
        "Add `--syscall-aggregate` only for a kernel-facing hypothesis",
        "inventories can run concurrently",
        "Existing artifacts do not require a local collector",
        "Run `doctor` when capability is unknown",
    ):
        assert adaptive_rule in normalized_skill
    for invariant in (
        "schema version `2.0`",
        "PID plus procfs start time",
        "Pass the selected exact endpoints through read-only `validate`",
        "Bound every capture",
        "leave the CUPTI shared object mapped",
        "temporal correlation is not exact causality",
    ):
        assert invariant in normalized_skill
    for quality_field in (
        "unmatched",
        "ambiguous",
        "loss/drops",
        "completeness",
        "symbol and stack coverage",
        "clock alignment",
        "method",
        "confidence",
        "evidence pair",
    ):
        assert quality_field in normalized_skill
    for investigation_step in (
        "CPU-only",
        "GPU or mixed",
        "Scope breadth and capture duration are independent",
        "python:gc_start",
        "native frames",
        "scripts/analyze_trace.py",
        "selector hints",
        "busy_union_ns",
        "overlap factor",
        "NCU or PC sampling",
    ):
        assert investigation_step in normalized_skill
    assert "leave the CUPTI shared object mapped" in normalized_skill

    for relative_link in re.findall(r"\]\(([^)]+)\)", skill):
        target = (skill_root / relative_link).resolve()
        assert target.is_relative_to(skill_root), relative_link
        assert target.is_file(), relative_link

    analyzer = skill_root / "scripts/analyze_trace.py"
    assert analyzer.is_file()
    assert os.access(analyzer, os.X_OK)
    assert not list(skill_root.rglob("__pycache__"))
    assert not list(skill_root.rglob("*.pyc"))
    examples = sorted((skill_root / "examples").glob("*.json"))
    assert len(examples) >= 5
    policies = set()
    modes = set()
    for example in examples:
        specification = json.loads(example.read_text())
        assert specification["schema_version"] == "2.0", example
        if "sample_event" in specification:
            modes.add("cpu_sample")
            assert specification["frequency_hz"] > 0, example
            assert specification["max_samples"] > 0, example
            assert specification["stack_depth"] > 0, example
            assert specification["max_threads"] > 0, example
            continue
        if "max_inflight" in specification and "start_selector" not in specification:
            modes.add("syscall_aggregate")
            assert specification["max_groups"] > 0, example
            assert specification["max_inflight"] > 0, example
            continue
        mode = specification.get("measurement_mode", "exact")
        modes.add(mode)
        if mode == "aggregate":
            assert specification["max_events"] is None, example
            assert specification["max_groups"] > 0, example
        else:
            assert specification["max_events"] > 0, example
        policies.add(specification["match_policy"])
    assert modes == {"exact", "aggregate", "cpu_sample", "syscall_aggregate"}
    assert {"exact", "first_after", "stack_nested", "stream_order"} <= policies

    openai_yaml = (skill_root / "agents/openai.yaml").read_text()
    assert 'display_name: "Xprobe Workload Profiling"' in openai_yaml
    assert (
        'short_description: "Route bounded CPU, Python, and GPU profiling"'
        in openai_yaml
    )
    assert "$xprobe-measure-latency" in openai_yaml

    investigation = (skill_root / "references/investigation.md").read_text()
    quality = (skill_root / "references/result-quality.md").read_text()
    multi_process = (skill_root / "references/multi-process.md").read_text()
    trace_analysis = (skill_root / "references/trace-analysis.md").read_text()
    setup = (skill_root / "references/setup.md").read_text()
    normalized_investigation = re.sub(r"\s+", " ", investigation)
    normalized_quality = re.sub(r"\s+", " ", quality)
    normalized_multi_process = re.sub(r"\s+", " ", multi_process)
    normalized_trace_analysis = re.sub(r"\s+", " ", trace_analysis)
    normalized_setup = re.sub(r"\s+", " ", setup)
    normalized_cli_contract = re.sub(
        r"\s+", " ", (skill_root / "references/cli-contract.md").read_text()
    )
    for required in (
        "Triton",
        "procfs start time",
        "EVENT_RATE_TOO_HIGH",
        "readelf -Ws",
        "NO_MATCHED_SAMPLES",
        "representative cycle",
        "concrete Runtime or Driver API name",
        "observed_samples",
        "python_status",
        "python:gc_start",
        "independent concurrent commands",
    ):
        assert required in normalized_investigation
    for required in (
        "minimum_records",
        "first selected event",
        "ARM completion",
        "Summed kernel",
        "Inventory modes are separate contracts",
        "max-groups",
        "lost samples",
        "stack truncation",
    ):
        assert required in normalized_quality
    for required in (
        "representative worker",
        "target.process_start_time",
        "target` exactly matches",
        "native concurrent tool calls",
        "Do not cancel sibling commands",
        "Never reuse an artifact path",
        "Do not concatenate artifacts",
        "overall experiment incomplete",
        "CPU sample inventory and GPU aggregate",
    ):
        assert required in normalized_multi_process
    for required in (
        "busy_union_ns",
        "summed_activity_ns",
        "launch_variants",
        "Cross-stream",
        "distinct capture windows",
    ):
        assert required in normalized_trace_analysis
    for required in (
        "python:gc_start|gc_end",
        "--cpu-sample",
        "--syscall-aggregate",
        "sampling uncertainty",
        "cannot be passed to `measure --input`",
    ):
        assert required in normalized_cli_contract
    for required in (
        "v0.5.0/install.sh",
        "xprobe `0.4.x`",
        "npx skills@1 add",
        "xprobe --version",
        "xprobe doctor",
        "host glibc",
        "CUDA/CUPTI majors other than 12 or 13 are not supported",
        "scripts/package-release.sh",
    ):
        assert required in normalized_setup

    engineering_rules = re.sub(
        r"\s+", " ", (workspace / "AGENTS.md").read_text()
    )
    for required in (
        "external reviews as evidence to investigate",
        "dedicated feature or fix branch",
        "Rebase pull requests",
        "GLIBC_2.34 ceiling",
        "downloading the public archive",
        "transient infrastructure failure",
        "Choose the shortest Skill route",
    ):
        assert required in engineering_rules

    entries = {
        "codex": workspace / "AGENTS.md",
        "claude": workspace / "CLAUDE.md",
        "cursor": workspace / ".cursor/rules/xprobe.mdc",
    }
    for client, path in entries.items():
        assert path.is_file(), client
        assert SKILL_PATH in path.read_text(), client


def check_schemas(workspace: pathlib.Path) -> None:
    schema_paths = sorted((workspace / "schemas").glob("*.schema.json"))
    assert schema_paths
    for path in schema_paths:
        schema = json.loads(path.read_text())
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False


def check_installation_docs(workspace: pathlib.Path) -> None:
    cargo = (workspace / "Cargo.toml").read_text()
    version_match = re.search(r'^version = "([^"]+)"$', cargo, re.MULTILINE)
    assert version_match is not None
    development_version = version_match.group(1)

    installer = (workspace / "install.sh").read_text()
    release_match = re.search(r"^version=\$\{XPROBE_VERSION:-([^}]+)\}$", installer, re.MULTILINE)
    assert release_match is not None
    release_version = release_match.group(1)
    assert tuple(map(int, development_version.split("."))) >= tuple(
        map(int, release_version.split("."))
    )
    assert f"default: {release_version}" in installer

    for relative_path in (
        "README.md",
        "docs/installation.md",
        "docs/agent-integration.md",
    ):
        document = (workspace / relative_path).read_text()
        assert "npx skills@1 add" in document, relative_path
        assert f"/v{release_version}/" in document, relative_path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_contract.py <xprobe-binary>")

    workspace = pathlib.Path(__file__).resolve().parents[2]
    binary = (workspace / sys.argv[1]).resolve()
    help_result = subprocess.run(
        [binary, "--help"], check=True, capture_output=True, text=True
    )
    commands = {
        line.split()[0]
        for line in help_result.stdout.splitlines()
        if line.startswith("  ") and line.strip() and not line.lstrip().startswith("-")
    }
    commands.discard("help")
    assert STABLE_COMMANDS == commands, {"commands": sorted(commands)}

    doctor = run_json(binary, ["doctor"])
    assert "capabilities" in doctor and "checks" in doctor
    with tempfile.TemporaryDirectory(prefix="xprobe-contract-") as directory:
        nvidia_smi = pathlib.Path(directory) / "nvidia-smi"
        nvidia_smi.write_text(f"#!/bin/sh\nprintf '%s\\n' '{os.getpid()}, GPU-test'\n")
        nvidia_smi.chmod(0o755)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{directory}:{old_path}"
        try:
            discovered = run_json(
                binary,
                ["discover", "--pid", str(os.getpid()), "--limit", "10"],
                schema_version="2.0",
            )
        finally:
            os.environ["PATH"] = old_path
    assert discovered["root"]["pid"] == os.getpid()
    assert discovered["candidates"][0]["target"]["pid"] == os.getpid()
    validated = run_json(
        binary,
        [
            "validate",
            "--pid",
            str(os.getpid()),
            "--from",
            "cuda:runtime_api:cudaLaunchKernel:entry",
            "--to",
            "cuda:kernel_start:name~xprobe_contract_kernel.*",
            "--match",
            "exact",
        ],
    )
    assert validated["requirements"]["needs_cupti"] is True
    assert validated["requirements"]["agent_activation"] == "injection_required"
    assert validated["requirements"]["target_mutation"] is True
    assert validated["valid"] is True
    assert validated["policy_recommendation"]["policy"] == "exact"
    assert (
        validated["policy_recommendation"]["reason"]
        == "deterministic_correlation_key"
    )
    assert "first_after" in validated["policy_recommendation"]["compatible_policies"]
    assert any(
        warning["code"] == "TARGET_PROCESS_WILL_BE_MODIFIED"
        for warning in validated["warnings"]
    )

    check_skill(workspace)
    check_schemas(workspace)
    check_installation_docs(workspace)
    print(
        json.dumps(
            {
                "schema_version": "2.0",
                "ok": True,
                "agents": ["claude", "codex", "cursor"],
                "commands": sorted(STABLE_COMMANDS),
                "schemas": len(list((workspace / "schemas").glob("*.schema.json"))),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
