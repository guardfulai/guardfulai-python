"""Fail closed on release identity, ancestry and accepted artifact digests."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tomllib
from pathlib import Path


def validate(values, *, artifacts=False):
    version, commit = values["RELEASE_VERSION"], values["RELEASE_COMMIT"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("invalid release identity")
    if values["GITHUB_REF"] != f"refs/tags/v{version}":
        raise ValueError("release ref mismatch")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if (
        actual != commit
        or tomllib.loads(Path("pyproject.toml").read_text())["project"]["version"] != version
    ):
        raise ValueError("release commit or metadata mismatch")
    subprocess.run(["git", "merge-base", "--is-ancestor", commit, "origin/main"], check=True)
    if values.get("GITHUB_ACTIONS") == "true":
        runs = json.loads(
            subprocess.check_output(
                [
                    "gh",
                    "run",
                    "list",
                    "--repo",
                    "guardfulai/guardfulai-python",
                    "--workflow",
                    "ci.yml",
                    "--commit",
                    commit,
                    "--branch",
                    "main",
                    "--event",
                    "push",
                    "--json",
                    "status,conclusion",
                    "--limit",
                    "20",
                ],
                text=True,
            )
        )
        if not any(r["status"] == "completed" and r["conclusion"] == "success" for r in runs):
            raise ValueError("Full CI matrix must pass on the accepted main commit first")
    for kind, filename in [
        ("WHEEL", f"guardfulai-{version}-py3-none-any.whl"),
        ("SDIST", f"guardfulai-{version}.tar.gz"),
    ]:
        expected = values[f"{kind}_SHA256"]
        if not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise ValueError("invalid accepted digest")
        if (
            artifacts
            and hashlib.sha256((Path("dist") / filename).read_bytes()).hexdigest() != expected
        ):
            raise ValueError("CI artifact differs from locally accepted bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", action="store_true")
    validate(os.environ, artifacts=parser.parse_args().artifacts)
