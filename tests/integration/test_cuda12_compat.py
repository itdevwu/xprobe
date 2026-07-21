#!/usr/bin/env python3
import pathlib
import subprocess
import sys
import tempfile


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: test_cuda12_compat.py <build-image> <runtime-image> <xprobe-binary>"
        )

    workspace = pathlib.Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="xprobe-cuda12-agent-") as output_dir:
        agent = pathlib.Path(output_dir) / "libxprobe-cupti.so"
        build = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--volume",
                f"{workspace}:/workspace:ro",
                "--volume",
                f"{output_dir}:/output",
                sys.argv[1],
                "bash",
                "-lc",
                "gcc -std=c11 -Wall -Wextra -Wpedantic -Werror -O2 "
                "-fPIC -shared -D_GNU_SOURCE -DXPROBE_HAS_CUPTI=1 "
                "-I/workspace/cupti/include -isystem /usr/local/cuda/include "
                "/workspace/cupti/src/cupti_agent.c -L/usr/local/cuda/lib64 "
                "-lcupti -lpthread -o /output/libxprobe-cupti.so",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if build.returncode != 0:
            sys.stdout.write(build.stdout)
            sys.stderr.write(build.stderr)
            raise SystemExit(build.returncode)

        tested = subprocess.run(
            [
                sys.executable,
                workspace / "tests/integration/test_cupti.py",
                sys.argv[2],
                sys.argv[3],
                agent,
            ],
            check=False,
            text=True,
        )
        raise SystemExit(tested.returncode)


if __name__ == "__main__":
    main()
