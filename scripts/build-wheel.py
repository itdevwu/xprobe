#!/usr/bin/env python3
"""Build the PyPI wheel from a verified release staging directory.

The wheel installs the CLI into the environment's `bin/` and the CUPTI Agents
into `lib/xprobe/cudaNN/`, preserving the `bin/../lib/xprobe` layout the CLI
searches. It contains no Python code and supports glibc 2.34 or newer on
x86_64, matching the release archive.

    scripts/build-wheel.py dist/xprobe-X.Y.Z-linux-x86_64 dist
"""

import base64
import csv
import hashlib
import io
import pathlib
import re
import sys
import zipfile

NAME = "xprobe"
TAG = "py3-none-manylinux_2_34_x86_64"
# Fixed timestamp so the same inputs produce the same wheel.
EPOCH = (2026, 1, 1, 0, 0, 0)
KEYWORDS = (
    "profiler,profiling,performance,latency,gpu,cuda,cupti,ebpf,perf,"
    "pytorch,python,linux,ai-agent,claude-code,codex,cursor"
)
CLASSIFIERS = (
    "Development Status :: 4 - Beta",
    "Environment :: Console",
    "Environment :: GPU :: NVIDIA CUDA :: 12",
    "Environment :: GPU :: NVIDIA CUDA :: 13",
    "Intended Audience :: Developers",
    "Intended Audience :: Science/Research",
    "License :: OSI Approved :: Apache Software License",
    "Operating System :: POSIX :: Linux",
    "Programming Language :: Rust",
    "Topic :: Software Development :: Debuggers",
    "Topic :: System :: Monitoring",
)

# (path inside the staging directory, install scheme path, mode)
PAYLOAD = (
    ("bin/xprobe", "scripts/xprobe", 0o755),
    ("lib/xprobe/cuda12/libxprobe-cupti.so", "data/lib/xprobe/cuda12/libxprobe-cupti.so", 0o755),
    ("lib/xprobe/cuda13/libxprobe-cupti.so", "data/lib/xprobe/cuda13/libxprobe-cupti.so", 0o755),
)
SHARED_TREES = ("schemas", "skills")


def record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"sha256={digest.decode()}"


def metadata(version: str, readme: str) -> str:
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {NAME}",
        f"Version: {version}",
        "Summary: Find out why your CPU, Python, or CUDA process is slow in two "
        "commands: a bounded Linux profiler for AI coding agents.",
        "Home-page: https://github.com/itdevwu/xprobe",
        "Author: itdevwu",
        "License: Apache-2.0",
        f"Keywords: {KEYWORDS}",
        "Requires-Python: >=3.8",
        "Project-URL: Source, https://github.com/itdevwu/xprobe",
        "Project-URL: Documentation, https://github.com/itdevwu/xprobe/tree/master/docs",
        "Project-URL: Issues, https://github.com/itdevwu/xprobe/issues",
        "Project-URL: Changelog, https://github.com/itdevwu/xprobe/releases",
        *(f"Classifier: {classifier}" for classifier in CLASSIFIERS),
        "Description-Content-Type: text/markdown",
        "",
        absolute_links(readme),
    ]
    return "\n".join(lines)


def absolute_links(readme: str) -> str:
    """PyPI renders README links relative to nothing; point them at GitHub."""
    base = "https://github.com/itdevwu/xprobe/blob/master/"
    raw = "https://raw.githubusercontent.com/itdevwu/xprobe/master/"

    def link(match: re.Match[str]) -> str:
        target = match.group(2)
        if re.match(r"^[a-z]+:|^#", target):
            return match.group(0)
        return f"{match.group(1)}{base}{target}{match.group(3)}"

    readme = re.sub(r"(\]\()([^)\s]+)(\))", link, readme)
    return re.sub(
        r'((?:src|srcset)=")(?!https?:)([^"]+)(")',
        lambda match: f"{match.group(1)}{raw}{match.group(2)}{match.group(3)}",
        readme,
    )


def build(stage: pathlib.Path, output: pathlib.Path) -> pathlib.Path:
    match = re.fullmatch(r"xprobe-(\d+\.\d+\.\d+)(?:-dev\.(\d+))?-linux-x86_64", stage.name)
    if match is None:
        raise SystemExit(f"unexpected staging directory name: {stage.name}")
    # Cargo's X.Y.Z-dev.N is PEP 440's X.Y.Z.devN.
    version = match.group(1) + (f".dev{match.group(2)}" if match.group(2) else "")
    data_dir = f"{NAME}-{version}.data"
    dist_info = f"{NAME}-{version}.dist-info"

    entries: list[tuple[str, bytes, int]] = []
    for source, target, mode in PAYLOAD:
        path = stage / source
        if not path.is_file():
            raise SystemExit(f"missing release file: {path}")
        entries.append((f"{data_dir}/{target}", path.read_bytes(), mode))
    for tree in SHARED_TREES:
        for path in sorted((stage / tree).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                relative = path.relative_to(stage).as_posix()
                mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                entries.append((f"{data_dir}/data/share/xprobe/{relative}", path.read_bytes(), mode))
    entries.append((f"{dist_info}/METADATA", metadata(version, (stage / "README.md").read_text()).encode(), 0o644))
    entries.append((
        f"{dist_info}/WHEEL",
        f"Wheel-Version: 1.0\nGenerator: xprobe build-wheel.py\nRoot-Is-Purelib: false\nTag: {TAG}\n".encode(),
        0o644,
    ))
    entries.append((f"{dist_info}/LICENSE", (stage / "LICENSE").read_bytes(), 0o644))

    record = io.StringIO()
    writer = csv.writer(record, lineterminator="\n")
    for name, data, _ in entries:
        writer.writerow([name, record_hash(data), len(data)])
    writer.writerow([f"{dist_info}/RECORD", "", ""])
    entries.append((f"{dist_info}/RECORD", record.getvalue().encode(), 0o644))

    output.mkdir(parents=True, exist_ok=True)
    wheel = output / f"{NAME}-{version}-{TAG}.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=EPOCH)
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return wheel


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: build-wheel.py <release-staging-directory> <output-directory>")
    print(build(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])))


if __name__ == "__main__":
    main()
