"""Build, audit and independently install reproducible distributions."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
VERSION = PROJECT["version"]
EPOCH = "1580601600"
TOP_FILES = {
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "AGENTS.md",
    "pyproject.toml",
    "uv.lock",
    "Makefile",
    ".gitignore",
    ".gitattributes",
}
SOURCE_DIRS = {"src", "tests", "scripts", "examples", "docs"}
FORBIDDEN = {".env", ".local", ".venv", ".git", "__pycache__", "node_modules"}
SECRET = re.compile(
    rb"(?:ag_[a-f0-9]{32}_[A-Za-z0-9_-]{43}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    rb"|gh[pousr]_[A-Za-z0-9]{30,}|pypi-[A-Za-z0-9_-]{40,})"
)
PRIVATE = re.compile(rb"(?:/(?:Users|home)/[^/\s]+/|(?:\.\./)+docs/)")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_files() -> set[str]:
    files = set(TOP_FILES)
    for directory in SOURCE_DIRS:
        for path in (ROOT / directory).rglob("*"):
            relative = path.relative_to(ROOT)
            if "__pycache__" in relative.parts or path.suffix == ".pyc":
                continue
            if path.is_symlink():
                raise ValueError(f"source symlink: {relative}")
            if path.is_file():
                if path.suffix not in {".py", ".json", ".md", ".typed"} and path.name != "py.typed":
                    raise ValueError(f"unexpected source file: {relative}")
                files.add(relative.as_posix())
    return files


def inspect_content(name: str, data: bytes) -> None:
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or not path.parts
        or FORBIDDEN.intersection(path.parts)
    ):
        raise ValueError(f"unsafe path: {name}")
    if path.suffix in {".onnx", ".gguf", ".safetensors", ".sqlite3", ".pem", ".key", ".pyc"}:
        raise ValueError(f"forbidden payload: {name}")
    if SECRET.search(data) or PRIVATE.search(data):
        raise ValueError(f"sensitive or private content: {name}")


def audit_source() -> list[str]:
    files = source_files()
    # Audit all tracked/untracked publishable files, including workflows.
    if (ROOT / ".git").exists():
        output = subprocess.check_output(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT
        )
        files |= {name.decode() for name in output.split(b"\0") if name}
    for name in sorted(files):
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"non-regular source: {name}")
        inspect_content(name, path.read_bytes())
    # Inspect every reachable committed blob, not only HEAD.
    if (ROOT / ".git").exists() and subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT, capture_output=True
    ).returncode == 0:
        rows = (
            subprocess.check_output(["git", "rev-list", "--objects", "--all"], cwd=ROOT)
            .decode()
            .splitlines()
        )
        for row in rows:
            oid, _, name = row.partition(" ")
            kind = subprocess.check_output(["git", "cat-file", "-t", oid], cwd=ROOT).strip()
            if kind == b"blob":
                inspect_content(
                    name, subprocess.check_output(["git", "cat-file", "blob", oid], cwd=ROOT)
                )
    return sorted(files)


def metadata(data: bytes) -> None:
    parsed = BytesParser().parsebytes(data)
    if parsed["Name"] != "guardfulai" or parsed["Version"] != VERSION:
        raise ValueError("distribution identity mismatch")
    from packaging.requirements import Requirement

    if {str(Requirement(v)) for v in parsed.get_all("Requires-Dist", [])} != {
        str(Requirement(v)) for v in PROJECT["dependencies"]
    }:
        raise ValueError("runtime dependency mismatch")
    if (
        parsed["Requires-Python"] != PROJECT["requires-python"]
        or parsed["License-Expression"] != "MIT"
    ):
        raise ValueError("Python or license metadata mismatch")


def inspect_wheel(path: Path) -> list[str]:
    prefix = f"guardfulai-{VERSION}.dist-info/"
    expected = {p.removeprefix("src/") for p in source_files() if p.startswith("src/")}
    expected |= {prefix + p for p in ["METADATA", "WHEEL", "RECORD", "licenses/LICENSE"]}
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or set(names) != expected:
            raise ValueError(f"wheel file allowlist mismatch: {set(names) ^ expected}")
        payloads = {}
        for info in archive.infolist():
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("wheel symlink")
            payloads[info.filename] = archive.read(info)
            inspect_content(info.filename, payloads[info.filename])
    metadata(payloads[prefix + "METADATA"])
    rows = list(csv.reader(io.StringIO(payloads[prefix + "RECORD"].decode())))
    if len(rows) != len(expected) or {r[0] for r in rows} != expected:
        raise ValueError("RECORD inventory mismatch")
    for name, sha, size in rows:
        if name == prefix + "RECORD":
            if sha or size:
                raise ValueError("RECORD self hash")
        else:
            data = payloads[name]
            actual = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            if sha != f"sha256={actual}" or size != str(len(data)):
                raise ValueError("RECORD digest mismatch")
    return sorted(names)


def inspect_sdist(path: Path) -> list[str]:
    expected = source_files() | {"PKG-INFO"}
    names = set()
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            inspect_content(member.name, b"")
            if not member.isfile():
                raise ValueError("sdist contains non-regular member")
            prefix, separator, name = member.name.partition("/")
            if prefix != f"guardfulai-{VERSION}" or not separator or name in names:
                raise ValueError("invalid sdist identity or duplicate member")
            data = archive.extractfile(member).read()
            inspect_content(name, data)
            if name == "PKG-INFO":
                metadata(data)
            names.add(name)
    if names != expected:
        raise ValueError(f"sdist file allowlist mismatch: {names ^ expected}")
    return sorted(names)


def run(args: list[str], *, cwd: Path = ROOT, offline: bool = True) -> None:
    environment = os.environ.copy()
    environment.update(
        PYTHONHASHSEED="0",
        SOURCE_DATE_EPOCH=EPOCH,
        UV_PYTHON_DOWNLOADS="never",
        PYTHONNOUSERSITE="1",
    )
    environment.pop("PYTHONPATH", None)
    if offline:
        environment["UV_OFFLINE"] = "1"
        environment["PIP_NO_INDEX"] = "1"
    subprocess.run(args, cwd=cwd, env=environment, check=True)


def python_at(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def install(artifact: Path, destination: Path) -> None:
    run(["uv", "venv", "--python", sys.executable, str(destination)])
    run(
        ["uv", "pip", "install", "--python", str(python_at(destination)), "--strict", str(artifact)]
    )
    run(
        [
            str(python_at(destination)),
            "-I",
            "-c",
            "from importlib.metadata import version; from importlib.resources import files; "
            "from guardfulai import GuardfulAI, AsyncGuardfulAI, RetryPolicy; "
            f"assert version('guardfulai') == '{VERSION}'; "
            "assert files('guardfulai').joinpath('py.typed').is_file(); "
            "assert GuardfulAI and AsyncGuardfulAI and RetryPolicy",
        ],
        cwd=destination,
    )


def build(destination: Path) -> tuple[Path, Path]:
    run(
        [
            "uv",
            "build",
            "--offline",
            "--no-create-gitignore",
            "--out-dir",
            str(destination),
            str(ROOT),
        ]
    )
    wheels, sources = list(destination.glob("*.whl")), list(destination.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        raise ValueError("expected one wheel and one sdist")
    return wheels[0], sources[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--audit-only", action="store_true")
    args = parser.parse_args()
    audit_source()
    if args.audit_only:
        print("Public source and reachable history audit passed")
        return
    with tempfile.TemporaryDirectory(prefix="guardfulai-package-") as raw:
        scratch = Path(raw)
        first, second = build(scratch / "first"), build(scratch / "second")
        artifacts = []
        for i, (a, b) in enumerate(zip(first, second, strict=True)):
            if a.read_bytes() != b.read_bytes():
                raise ValueError("non-reproducible build")
            names = inspect_wheel(a) if i == 0 else inspect_sdist(a)
            install(a, scratch / f"consumer-{i}")
            # Run the portable suite against the installed distribution, outside source.
            run(
                [
                    "uv",
                    "pip",
                    "install",
                    "--python",
                    str(python_at(scratch / f"consumer-{i}")),
                    "pytest",
                ]
            )
            import shutil

            shutil.copytree(
                ROOT / "tests", scratch / f"tests-{i}", ignore=shutil.ignore_patterns("__pycache__")
            )
            # Packaging/release tooling tests belong to the source tree, not runtime consumers.
            for tooling in (scratch / f"tests-{i}").glob("test_tooling*.py"):
                tooling.unlink()
            run(
                [
                    str(python_at(scratch / f"consumer-{i}")),
                    "-I",
                    "-m",
                    "pytest",
                    "-q",
                    str(scratch / f"tests-{i}"),
                ],
                cwd=scratch,
            )
            args.output.mkdir(parents=True, exist_ok=True)
            target = args.output / a.name
            if target.exists() and digest(target) != digest(a):
                raise ValueError(f"refusing to replace accepted artifact: {target.name}")
            shutil.copyfile(a, target)
            artifacts.append(
                {"filename": a.name, "sha256": digest(a), "bytes": a.stat().st_size, "files": names}
            )
        receipt = {
            "schema_version": 1,
            "package": "guardfulai",
            "version": VERSION,
            "source_date_epoch": int(EPOCH),
            "reproducible": True,
            "source_tree_sha256": hashlib.sha256(
                b"".join(
                    n.encode() + b"\0" + bytes.fromhex(digest(ROOT / n))
                    for n in sorted(source_files())
                )
            ).hexdigest(),
            "artifacts": artifacts,
            "published": False,
        }
        (args.output / "provenance.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        )
        print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
