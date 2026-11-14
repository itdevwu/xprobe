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
SKILL_WORD_BUDGET = 800
SKILL_TOTAL_WORD_BUDGET = 4000


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


def development_version(workspace: pathlib.Path) -> str:
    cargo = (workspace / "Cargo.toml").read_text()
    version_match = re.search(r'^version = "([^"]+)"$', cargo, re.MULTILINE)
    assert version_match is not None
    return version_match.group(1)


def release_version(workspace: pathlib.Path) -> str:
    installer = (workspace / "install.sh").read_text()
    release_match = re.search(r"^version=\$\{XPROBE_VERSION:-([^}]+)\}$", installer, re.MULTILINE)
    assert release_match is not None
    return release_match.group(1)


def check_skill(workspace: pathlib.Path, binary: pathlib.Path) -> None:
    skill_path = workspace / SKILL_PATH
    skill_root = skill_path.parent.resolve()
    skill = skill_path.read_text()
    frontmatter = re.match(r"^---\n(.*?)\n---", skill, re.DOTALL)
    assert frontmatter is not None
    assert re.search(r"^name: xprobe-measure-latency$", frontmatter.group(1), re.MULTILINE)
    assert re.search(r"^description: .+", frontmatter.group(1), re.MULTILINE)

    # The entry point stays short; details live in linked references.
    references = sorted((skill_root / "references").glob("*.md"))
    assert len(skill.split()) <= SKILL_WORD_BUDGET, len(skill.split())
    total = len(skill.split()) + sum(len(path.read_text().split()) for path in references)
    assert total <= SKILL_TOTAL_WORD_BUDGET, total

    # Every link resolves inside the Skill, and every reference is reachable.
    linked = set()
    for document in [skill_path, *references]:
        for relative_link in re.findall(r"\]\(([^)]+)\)", document.read_text()):
            target = (document.parent / relative_link).resolve()
            assert target.is_relative_to(skill_root), (document, relative_link)
            assert target.is_file(), (document, relative_link)
            linked.add(target)
    skill_links = {
        (skill_root / link).resolve() for link in re.findall(r"\]\(([^)]+)\)", skill)
    }
    assert {path.resolve() for path in references} <= skill_links, "orphaned reference"

    # The entry point covers the two-command flow and its safety invariants.
    normalized_skill = re.sub(r"\s+", " ", skill)
    for required in (
        "--triage",
        "measure --spec",
        "measure --input",
        "validate",
        "quality.verdict",
        "not_covered",
        "measurement graph",
        "Dig deeper",
        "PID plus procfs start time",
        "Bound every capture",
        "leave the CUPTI shared object mapped",
        "temporal correlation is not exact causality",
        "scripts/analyze_trace.py",
        "NCU or PC sampling",
    ):
        assert required in normalized_skill, required

    # Every documented xprobe command uses flags its subcommand accepts.
    help_flags = {}
    for document in [skill_path, *references]:
        for block in re.findall(r"```bash\n(.*?)```", document.read_text(), re.DOTALL):
            command = re.sub(r"\\\n\s*", " ", block)
            for line in command.splitlines():
                words = line.split()
                if len(words) < 2 or words[0] != "xprobe" or words[1].startswith("-"):
                    continue
                subcommand = words[1]
                if subcommand not in help_flags:
                    help_text = subprocess.run(
                        [binary, subcommand, "--help"],
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout
                    help_flags[subcommand] = set(re.findall(r"--[a-z][a-z0-9-]*", help_text))
                for flag in re.findall(r"(?<!\S)--[a-z][a-z0-9-]*", line):
                    assert flag in help_flags[subcommand], (document.name, subcommand, flag)
    assert {"measure", "validate"} <= set(help_flags), sorted(help_flags)

    analyzer = skill_root / "scripts/analyze_trace.py"
    assert analyzer.is_file()
    assert os.access(analyzer, os.X_OK)
    assert not list(skill_root.rglob("__pycache__"))
    assert not list(skill_root.rglob("*.pyc"))

    # Examples are valid templates for each spec shape.
    modes = set()
    policies = set()
    for example in sorted((skill_root / "examples").glob("*.json")):
        specification = json.loads(example.read_text())
        if "edges" in specification:
            assert specification["schema_version"] == "3.0", example
            modes.add("graph")
            names = set(specification["endpoints"])
            for edge in specification["edges"]:
                assert {edge["from"], edge["to"]} <= names, example
                policies.add(edge["match_policy"])
            continue
        assert specification["schema_version"] == "2.0", example
        if "sample_event" in specification:
            modes.add("cpu_sample")
            assert specification["frequency_hz"] > 0, example
            assert specification["max_samples"] > 0, example
            continue
        if "max_inflight" in specification and "start_selector" not in specification:
            modes.add("syscall_aggregate")
            assert specification["max_groups"] > 0, example
            continue
        mode = specification.get("measurement_mode", "exact")
        modes.add(mode)
        if mode == "aggregate":
            assert specification["max_events"] is None, example
            assert specification["max_groups"] > 0, example
        else:
            assert specification["max_events"] > 0, example
        policies.add(specification["match_policy"])
    assert modes == {"exact", "aggregate", "cpu_sample", "syscall_aggregate", "graph"}
    assert {"exact", "first_after", "stack_nested", "stream_order"} <= policies

    openai_yaml = (skill_root / "agents/openai.yaml").read_text()
    assert 'display_name: "Xprobe Workload Profiling"' in openai_yaml
    assert "$xprobe-measure-latency" in openai_yaml

    setup = re.sub(r"\s+", " ", (skill_root / "references/setup.md").read_text())
    major, minor, _ = development_version(workspace).split(".")
    release = release_version(workspace)
    for required in (
        f"xprobe `{major}.{minor}.x`",
        f"v{release}/install.sh",
        "npx skills@1 add",
        "xprobe --version",
        "xprobe doctor",
        "PID and mount namespaces",
        "namespace-local PID",
        "does not add capabilities",
        "CUDA/CUPTI majors other than 12 or 13 are not supported",
    ):
        assert required in setup, required


def check_schemas(workspace: pathlib.Path) -> None:
    schema_paths = sorted((workspace / "schemas").glob("*.schema.json"))
    assert schema_paths
    for path in schema_paths:
        schema = json.loads(path.read_text())
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False


def check_installation_docs(workspace: pathlib.Path) -> None:
    development = development_version(workspace)
    release = release_version(workspace)
    installer = (workspace / "install.sh").read_text()
    assert tuple(map(int, development.split("."))) >= tuple(map(int, release.split(".")))
    assert f"default: {release}" in installer

    for relative_path in (
        "README.md",
        "docs/installation.md",
        "docs/agent-integration.md",
    ):
        document = (workspace / relative_path).read_text()
        assert "npx skills@1 add" in document, relative_path
        assert f"/v{release}/" in document, relative_path


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

    check_skill(workspace, binary)
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
