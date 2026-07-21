#!/usr/bin/env python3
import json
import os
import pathlib
import re
import subprocess
import sys


COMMON_FLAGS = ["--json", "--non-interactive", "--no-color"]
STABLE_COMMANDS = {
    "doctor",
    "inspect",
    "resolve",
    "validate",
    "measure",
    "trace",
    "export",
    "capture",
}
SKILL_PATH = "skills/xprobe-measure-latency/SKILL.md"


def run_json(binary: pathlib.Path, arguments: list[str]) -> dict:
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
    assert result["schema_version"] == "1.0"
    assert result["ok"] is True
    return result


def check_skill(workspace: pathlib.Path) -> None:
    skill = (workspace / SKILL_PATH).read_text()
    frontmatter = re.match(r"^---\n(.*?)\n---", skill, re.DOTALL)
    assert frontmatter is not None
    assert re.search(r"^name: xprobe-measure-latency$", frontmatter.group(1), re.MULTILINE)
    assert re.search(r"^description: .+", frontmatter.group(1), re.MULTILINE)

    ordered_steps = [
        "xprobe doctor",
        "xprobe inspect",
        "xprobe resolve",
        "xprobe validate",
        "Run a bounded foreground `measure`",
        "Check `status`",
        "finish cleanup",
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
    ):
        assert quality_field in skill
    assert "Do not restart, inject into, signal, or modify" in skill
    assert "Do not use unbounded" in skill

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
    assert STABLE_COMMANDS <= commands, {"commands": sorted(commands)}

    doctor = run_json(binary, ["doctor"])
    assert "capabilities" in doctor and "checks" in doctor
    inspected = run_json(binary, ["inspect", "--pid", str(os.getpid())])
    assert inspected["target"]["pid"] == os.getpid()
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
    assert validated["requirements"]["target_mutation"] is False

    check_skill(workspace)
    check_schemas(workspace)
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
