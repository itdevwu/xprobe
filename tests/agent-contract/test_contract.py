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
    binary: pathlib.Path, arguments: list[str], schema_version: str = "1.0"
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

    ordered_steps = [
        "xprobe doctor",
        "xprobe discover",
        "xprobe validate",
        "xprobe measure",
        "Check `status`",
    ]
    positions = [skill.index(step) for step in ordered_steps]
    assert positions == sorted(positions)
    for quality_field in (
        "unmatched",
        "ambiguous",
        "dropped",
        "clock alignment",
        "correlation method",
        "confidence",
        "evidence",
    ):
        assert quality_field in skill
    assert "Expect a warning on automatic CUPTI injection" in skill
    assert "leave the CUPTI shared object mapped" in skill
    assert "Do not use unbounded" in skill

    for relative_link in re.findall(r"\]\(([^)]+)\)", skill):
        target = (skill_root / relative_link).resolve()
        assert target.is_relative_to(skill_root), relative_link
        assert target.is_file(), relative_link

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
                "schema_version": "1.0",
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
