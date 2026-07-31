#!/usr/bin/env python3
import json
import pathlib
import re


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("`", "")).lower()


def main() -> None:
    workspace = pathlib.Path(__file__).resolve().parents[2]
    skill_root = workspace / "skills/xprobe-measure-latency"
    sources = {
        "skill": normalize((skill_root / "SKILL.md").read_text()),
        "investigation": normalize(
            (skill_root / "references/investigation.md").read_text()
        ),
    }
    fixture = json.loads(
        (workspace / "tests/agent-contract/fixtures/workflow-routes.json").read_text()
    )
    covered = set()
    for scenario in fixture["scenarios"]:
        document = " ".join(sources[name] for name in scenario["sources"])
        for phrase in scenario["required"]:
            assert normalize(phrase) in document, (scenario["name"], phrase)
        covered.add(scenario["name"])
    assert covered == {
        "existing_artifact",
        "known_selector",
        "unknown_cpu",
        "python_semantics",
        "mixed_cpu_gpu",
        "unsupported_python_runtime",
    }
    print(json.dumps({"schema_version": "2.0", "ok": True, "routes": sorted(covered)}))


if __name__ == "__main__":
    main()
