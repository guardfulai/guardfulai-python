"""Explicit online setup for the locked offline package-consumer checks."""

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    # Frozen sync downloads wheels by URL; it need not cache index metadata.
    # Resolve the exact exported lock once during setup, never during checks.
    with tempfile.TemporaryDirectory(prefix="guardfulai-cache-") as raw:
        requirements = Path(raw) / "requirements.txt"
        subprocess.run(
            [
                "uv",
                "export",
                "--frozen",
                "--no-emit-project",
                "--no-hashes",
                "--no-header",
                "--no-annotate",
                "--output-file",
                str(requirements),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "uv",
                "pip",
                "compile",
                "--python",
                sys.executable,
                str(requirements),
                "--output-file",
                str(Path(raw) / "resolved.txt"),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
    print("Locked package-consumer dependency metadata cached")


if __name__ == "__main__":
    main()
