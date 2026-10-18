"""Explicit authorized release dispatch and independent registry verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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
COMMAND_ENV: dict[str, str] | None = None


def command(*args: str) -> str:
    if args[0] == "gh" and COMMAND_ENV is None:
        raise ValueError("Select and verify the GitHub release account first")
    return subprocess.check_output(list(args), cwd=ROOT, text=True, env=COMMAND_ENV).strip()


def origin_host() -> str:
    origins = command("git", "remote", "get-url", "--push", "--all", "origin").splitlines()
    if len(origins) != 1:
        raise ValueError("origin must have exactly one push URL")
    match = re.fullmatch(
        r"git@([A-Za-z0-9][A-Za-z0-9.-]*):" + re.escape(REPOSITORY) + r"(?:\.git)?", origins[0]
    )
    if not match:
        raise ValueError("origin must use SSH for the intended public repository")
    fetch = command("git", "remote", "get-url", "--all", "origin").splitlines()
    if fetch != origins:
        raise ValueError("origin fetch and push identities must match")
    host = match[1]
    config = dict(
        line.split(None, 1)
        for line in command("ssh", "-G", "git@" + host).splitlines()
        if " " in line
    )
    if config.get("hostname") != "github.com" or config.get("user") != "git":
        raise ValueError("origin SSH alias must resolve to git@github.com")
    return host


def configure_identity(username: str) -> None:
    global COMMAND_ENV
    COMMAND_ENV = None
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", username):
        raise ValueError("Supply the explicit GitHub username with --github-user")
    environment = os.environ.copy()
    for key in (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GH_HOST",
    ):
        environment.pop(key, None)
    if (
        any(environment.get(key) for key in ("GIT_SSH", "GIT_SSH_COMMAND"))
        or subprocess.run(
            ["git", "config", "--get", "core.sshCommand"], cwd=ROOT, capture_output=True
        ).returncode
        == 0
    ):
        raise ValueError("Use the configured SSH alias without Git SSH command overrides")
    host = origin_host()
    credential = subprocess.run(
        ["gh", "auth", "token", "--hostname", "github.com", "--user", username],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    if credential.returncode or not credential.stdout.strip():
        raise ValueError("GitHub CLI has no credential for the requested account")
    environment["GH_TOKEN"] = credential.stdout.strip()
    environment["GH_HOST"] = "github.com"
    identity = subprocess.run(
        ["gh", "api", "user", "--jq", ".login"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    if identity.returncode or identity.stdout.strip() != username:
        raise ValueError("GitHub CLI identity does not match the requested account")
    probe = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-T", "git@" + host],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    greeting = (
        f"Hi {username}! You've successfully authenticated, "
        "but GitHub does not provide shell access."
    )
    if probe.returncode != 1 or greeting not in (probe.stdout + probe.stderr).splitlines():
        raise ValueError("SSH identity does not match the requested GitHub account")
    for role in ("GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"):
        if command("git", "var", role).split(" <", 1)[0] != username:
            raise ValueError("Git author and committer names must match the release account")
    COMMAND_ENV = environment


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
    origin_host()
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


def publish(version: str, username: str) -> None:
    configure_identity(username)
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
    parser.add_argument("--github-user", default=os.environ.get("GUARDFULAI_GITHUB_USER", ""))
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--publish", action="store_true")
    action.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.publish:
        publish(args.version, args.github_user)
    else:
        verify(args.version)


if __name__ == "__main__":
    main()
