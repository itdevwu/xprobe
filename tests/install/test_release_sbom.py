#!/usr/bin/env python3
import json
import pathlib
import subprocess
import tempfile


def main() -> None:
    workspace = pathlib.Path(__file__).resolve().parents[2]
    checker = workspace / "scripts/check-release-sbom.py"
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "xprobe-release",
        "documentNamespace": "https://example.invalid/xprobe/test",
        "creationInfo": {"created": "2026-08-16T00:00:00Z", "creators": ["Tool: test"]},
        "packages": [
            {
                "name": "xprobe-cli",
                "SPDXID": "SPDXRef-Package-xprobe-cli",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
            }
        ],
    }
    with tempfile.TemporaryDirectory(prefix="xprobe-sbom-") as directory:
        path = pathlib.Path(directory) / "release.spdx.json"
        path.write_text(json.dumps(document))
        subprocess.run([checker, path], check=True, capture_output=True, text=True)


if __name__ == "__main__":
    main()
