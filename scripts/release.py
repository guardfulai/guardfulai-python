"""Explicit authorized release dispatch and independent registry verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from package_acceptance import (
    ROOT,
    VERSION,
    digest,
    inspect_sdist,
    inspect_wheel,
    install,
    python_at,
    run,
)

REPOSITORY = "guardfulai/guardfulai-python"


def command(*args: str) -> str:
    return subprocess.check_output(list(args), cwd=ROOT, text=True).strip()


def accepted(version: str) -> dict:
    if version != VERSION or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("explicit version must match project metadata and be a stable release")
    value = json.loads((ROOT / "dist/provenance.json").read_text())
    if value["version"] != version or value["package"] != "guardfulai":
        raise ValueError("acceptance identity mismatch")
    expected = {f"guardfulai-{version}-py3-none-any.whl", f"guardfulai-{version}.tar.gz"}
    if {a["filename"] for a in value["artifacts"]} != expected:
        raise ValueError("acceptance must contain exactly the expected wheel and sdist")
    for artifact in value["artifacts"]:
        if digest(ROOT / "dist" / artifact["filename"]) != artifact["sha256"]:
            raise ValueError("artifact digest differs from acceptance")
    return value


def prepare_dispatch(version: str) -> list[str]:
    if command("git", "status", "--porcelain"):
        raise ValueError("release requires a clean public checkout")
    if command("git", "branch", "--show-current") != "main":
        raise ValueError("release must start on main")
    origins = command("git", "remote", "get-url", "--push", "--all", "origin").splitlines()
    allowed = {
        f"https://github.com/{REPOSITORY}.git",
        f"https://github.com/{REPOSITORY}",
        f"git@github.com:{REPOSITORY}.git",
    }
    if len(origins) != 1 or origins[0] not in allowed:
        raise ValueError("origin must identify the intended public repository")
    value = accepted(version)
    commit = command("git", "rev-parse", "HEAD")
    args = [
        "gh",
        "workflow",
        "run",
        "publish.yml",
        "--repo",
        REPOSITORY,
        "--ref",
        f"v{version}",
        "-f",
        f"commit={commit}",
        "-f",
        f"version={version}",
    ]
    for artifact in value["artifacts"]:
        kind = "wheel" if artifact["filename"].endswith(".whl") else "sdist"
        args += ["-f", f"{kind}_sha256={artifact['sha256']}"]
    return args


def check_remote_history() -> bool:
    """Accept an empty initial remote or a main branch we can fast-forward."""
    refs = command("git", "ls-remote", "origin")
    if not refs:
        return False
    if not any(row.endswith("\trefs/heads/main") for row in refs.splitlines()):
        raise ValueError("nonempty remote has no main branch; inspect repository ownership")
    command("git", "fetch", "origin", "main", "--tags")
    command("git", "merge-base", "--is-ancestor", "origin/main", "HEAD")
    return True


def publish(version: str) -> None:
    # All validation completes before any remote mutation.
    command(sys.executable, "-m", "ruff", "check", ".")
    command(sys.executable, "-m", "ruff", "format", "--check", ".")
    command(sys.executable, "-m", "mypy")
    command(sys.executable, "-m", "pytest", "-q")
    command(sys.executable, "scripts/package_acceptance.py")
    args = prepare_dispatch(version)
    remote_initialized = check_remote_history()
    tag = f"v{version}"
    existing = subprocess.run(
        ["git", "rev-parse", "--verify", f"{tag}^{{commit}}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if existing.returncode == 0 and existing.stdout.strip() != command("git", "rev-parse", "HEAD"):
        raise ValueError("existing release tag points elsewhere; never replace it")
    # Fail closed if the version already exists. Partial uploads need explicit recovery.
    from urllib.error import HTTPError

    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/guardfulai/{version}/json", timeout=30):
            raise ValueError("version exists on PyPI; use --verify, not a second publication")
    except HTTPError as error:
        if error.code != 404:
            raise
    if remote_initialized:
        runs = json.loads(
            command(
                "gh",
                "run",
                "list",
                "--repo",
                REPOSITORY,
                "--workflow",
                "publish.yml",
                "--branch",
                tag,
                "--json",
                "status",
                "--limit",
                "20",
            )
        )
        if any(run["status"] != "completed" for run in runs):
            raise ValueError("release workflow is already active; resume it")
    command("git", "push", "origin", "main")
    import time

    # GitHub can take a moment to register the push-triggered CI run.
    for _attempt in range(12):
        checks = json.loads(
            command(
                "gh",
                "run",
                "list",
                "--repo",
                REPOSITORY,
                "--workflow",
                "ci.yml",
                "--commit",
                command("git", "rev-parse", "HEAD"),
                "--branch",
                "main",
                "--event",
                "push",
                "--json",
                "databaseId",
                "--limit",
                "1",
            )
        )
        if checks:
            break
        time.sleep(5)
    else:
        raise ValueError("CI run not found; inspect GitHub Actions before retrying release")
    command(
        "gh", "run", "watch", str(checks[0]["databaseId"]), "--repo", REPOSITORY, "--exit-status"
    )
    if existing.returncode != 0:
        command("git", "tag", "-a", tag, "-m", f"Guardful AI Python {version}")
    command("git", "push", "origin", tag)
    command(*args)
    print(f"Dispatched https://github.com/{REPOSITORY}/actions/workflows/publish.yml")
    print("Approve the accepted pypi deployment; then run this command with --verify.")


def verify(version: str) -> None:
    value = accepted(version)
    with urllib.request.urlopen(
        f"https://pypi.org/pypi/guardfulai/{version}/json", timeout=30
    ) as response:
        published = json.load(response)
    files = {item["filename"]: item for item in published["urls"]}
    if set(files) != {item["filename"] for item in value["artifacts"]}:
        raise ValueError("registry artifact inventory differs")
    from urllib.parse import urlsplit

    with tempfile.TemporaryDirectory(prefix="guardfulai-registry-") as raw:
        scratch = Path(raw)
        for index, artifact in enumerate(value["artifacts"]):
            item = files[artifact["filename"]]
            url = urlsplit(item["url"])
            if url.scheme != "https" or url.hostname != "files.pythonhosted.org":
                raise ValueError("unexpected registry download host")
            if item.get("yanked") or item["digests"]["sha256"] != artifact["sha256"]:
                raise ValueError("registry digest mismatch or yanked artifact")
            with urllib.request.urlopen(item["url"], timeout=60) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != artifact["sha256"]:
                raise ValueError("download digest mismatch")
            path = scratch / artifact["filename"]
            path.write_bytes(data)
            (inspect_wheel if path.suffix == ".whl" else inspect_sdist)(path)
            # Verify the signed provenance using PyPI's official verification CLI.
            command(
                sys.executable,
                "-m",
                "pypi_attestations",
                "verify",
                "pypi",
                "--repository",
                f"https://github.com/{REPOSITORY}",
                str(path),
            )
            environment = scratch / f"consumer-{index}"
            install(path, environment)
            run(["uv", "pip", "install", "--python", str(python_at(environment)), "pytest"])
            tests = scratch / f"tests-{index}"
            shutil.copytree(ROOT / "tests", tests, ignore=shutil.ignore_patterns("__pycache__"))
            for tooling in tests.glob("test_tooling*.py"):
                tooling.unlink()
            run([str(python_at(environment)), "-I", "-m", "pytest", "-q", str(tests)], cwd=scratch)
    print(f"Verified PyPI guardfulai=={version}: hashes, attestations, wheel/sdist installation")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--publish", action="store_true")
    action.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    (publish if args.publish else verify)(args.version)


if __name__ == "__main__":
    main()
