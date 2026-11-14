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
        "setup": normalize((skill_root / "references/setup.md").read_text()),
        "selectors": normalize((skill_root / "references/selectors.md").read_text()),
        "interpreting": normalize((skill_root / "references/interpreting.md").read_text()),
        "deep_dive": normalize((skill_root / "references/deep-dive.md").read_text()),
        "multi_process": normalize(
            (skill_root / "references/multi-process.md").read_text()
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
        "unknown_workload",
        "known_selector",
        "several_boundaries",
        "dig_deeper",
        "python_semantics",
        "multi_process",
        "container_namespace",
    }
    print(json.dumps({"schema_version": "2.0", "ok": True, "routes": sorted(covered)}))


if __name__ == "__main__":
    main()
