#!/usr/bin/env python3
import json
import pathlib
import sys


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-release-sbom.py <sbom.spdx.json>")

    path = pathlib.Path(sys.argv[1])
    document = json.loads(path.read_text())
    if not str(document.get("spdxVersion", "")).startswith("SPDX-2."):
        raise SystemExit(f"{path} is not an SPDX 2.x document")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise SystemExit(f"{path} has no SPDX document identifier")
    if document.get("dataLicense") != "CC0-1.0":
        raise SystemExit(f"{path} has an unexpected SPDX data license")
    if not document.get("documentNamespace"):
        raise SystemExit(f"{path} has no document namespace")
    if not document.get("creationInfo", {}).get("created"):
        raise SystemExit(f"{path} has no creation timestamp")

    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        raise SystemExit(f"{path} contains no software packages")
    for package in packages:
        if not package.get("name") or not str(package.get("SPDXID", "")).startswith(
            "SPDXRef-"
        ):
            raise SystemExit(f"{path} contains an invalid package entry")

    print(f"Verified SPDX SBOM with {len(packages)} packages")


if __name__ == "__main__":
    main()
