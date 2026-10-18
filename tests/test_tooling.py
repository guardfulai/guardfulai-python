import hashlib
import json
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import release  # noqa: E402
from package_acceptance import inspect_content, inspect_sdist, inspect_wheel  # noqa: E402
from release import accepted, prepare_dispatch  # noqa: E402


@pytest.mark.parametrize(
    "path", ["/absolute", "../escape", "src/../../escape", "a\\b", ".env", ".local/data"]
)
def test_archive_paths_rejected(path):
    with pytest.raises(ValueError):
        inspect_content(path, b"")


def test_private_key_rejected():
    with pytest.raises(ValueError):
        inspect_content("example.txt", b"-----BEGIN " + b"PRIVATE KEY-----")


def test_archive_duplicate_and_link_rejected(tmp_path):
    wheel = tmp_path / "bad.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("extra.py", "bad")
    with pytest.raises(ValueError):
        inspect_wheel(wheel)
    sdist = tmp_path / "bad.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        member = tarfile.TarInfo(f"guardfulai-{release.VERSION}/link")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
        archive.addfile(member)
    with pytest.raises(ValueError):
        inspect_sdist(sdist)


def test_fixture_manifest_covers_exact_cases():
    root = ROOT / "tests/fixtures"
    manifest = json.loads((root / "contracts.json").read_text())
    for name, entry in manifest["files"].items():
        data = (root / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]
        assert [case["name"] for case in json.loads(data)] == entry["cases"]
        assert len(entry["cases"]) == len(set(entry["cases"]))


def test_release_refuses_dirty_tree_before_any_remote_action(monkeypatch):
    commands = []

    def command(*args):
        commands.append(args)
        return " M README.md"

    monkeypatch.setattr(release, "command", command)
    with pytest.raises(ValueError, match="clean"):
        prepare_dispatch(release.VERSION)
    assert commands == [("git", "status", "--porcelain")]


def test_release_refuses_wrong_origin(monkeypatch):
    def command(*args):
        return {
            ("git", "status", "--porcelain"): "",
            ("git", "branch", "--show-current"): "main",
            (
                "git",
                "remote",
                "get-url",
                "--push",
                "--all",
                "origin",
            ): "https://example.test/wrong.git",
        }[args]

    monkeypatch.setattr(release, "command", command)
    with pytest.raises(ValueError, match="origin"):
        prepare_dispatch(release.VERSION)


def test_release_requires_exact_artifacts(tmp_path, monkeypatch):
    version = release.VERSION
    monkeypatch.setattr(release, "ROOT", tmp_path)
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist/provenance.json").write_text(
        json.dumps({"version": version, "package": "guardfulai", "artifacts": []})
    )
    with pytest.raises(ValueError, match="exactly"):
        accepted(version)


@pytest.mark.parametrize("version", ["0.1.0", "1.2.4", "1.2.3rc1", "1.2.3; touch forbidden"])
def test_release_rejects_wrong_version_before_reading_artifacts(tmp_path, monkeypatch, version):
    monkeypatch.setattr(release, "ROOT", tmp_path)
    monkeypatch.setattr(release, "VERSION", "1.2.3")
    with pytest.raises(ValueError, match="version"):
        accepted(version)


def test_release_guard_checks_ref_commit_and_digests(tmp_path, monkeypatch):
    import validate_release

    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.1.0"\n')
    monkeypatch.setattr(validate_release.subprocess, "check_output", lambda *a, **kw: "a" * 40)
    monkeypatch.setattr(validate_release.subprocess, "run", lambda *a, **kw: None)
    values = dict(
        RELEASE_VERSION="0.1.0",
        RELEASE_COMMIT="a" * 40,
        GITHUB_REF="refs/tags/v0.1.0",
        WHEEL_SHA256="b" * 64,
        SDIST_SHA256="c" * 64,
    )
    validate_release.validate(values)
    for changed in (
        {"GITHUB_REF": "refs/heads/main"},
        {"RELEASE_COMMIT": "d" * 40},
        {"WHEEL_SHA256": "bad"},
        {"RELEASE_VERSION": "0.2.0"},
    ):
        with pytest.raises(ValueError):
            validate_release.validate(values | changed)
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist/guardfulai-0.1.0-py3-none-any.whl").write_bytes(b"different")
    with pytest.raises(ValueError, match="differs"):
        validate_release.validate(values, artifacts=True)


def test_declined_example_never_checks(monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location("sync_example", ROOT / "examples/check.py")
    example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(example)
    for key, value in {
        "API_KEY": "synthetic-key",
        "BASE_URL": "https://service.example.test",
        "POLICY_ID": "synthetic-policy",
        "POLICY_VERSION": "1",
        "EVENT_ID": "event:1",
    }.items():
        monkeypatch.setenv("GUARDFULAI_" + key, value)

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def estimate(self, *args, **kwargs):
            from types import SimpleNamespace

            return SimpleNamespace(credits=1)

        def check(self, *args, **kwargs):
            raise AssertionError("Declined estimate must not send consuming check")

    monkeypatch.setattr(example, "GuardfulAI", Client)
    monkeypatch.setattr("builtins.input", lambda prompt: "no")
    example.main()


def test_release_remote_bootstrap_and_divergence(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setattr(release, "ROOT", tmp_path)
    remote = tmp_path / "remote.git"
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    subprocess.run(["git", "init", "-b", "main", str(checkout)], check=True, capture_output=True)
    monkeypatch.setattr(release, "ROOT", checkout)
    release.command("git", "config", "user.name", "Test Maintainer")
    release.command("git", "config", "user.email", "maintainer@example.test")
    release.command("git", "remote", "add", "origin", str(remote))
    release.command("git", "commit", "--allow-empty", "-m", "Initial source")
    assert release.check_remote_history() is False
    release.command("git", "push", "origin", "main")
    assert release.check_remote_history() is True
    initial = release.command("git", "rev-parse", "HEAD")
    release.command("git", "commit", "--allow-empty", "-m", "Remote change")
    release.command("git", "push", "origin", "main")
    release.command("git", "checkout", "--detach", initial)
    with pytest.raises(subprocess.CalledProcessError):
        release.check_remote_history()


def test_release_rejects_nonempty_remote_without_main(monkeypatch):
    monkeypatch.setattr(release, "command", lambda *args: "a" * 40 + "\trefs/heads/other")
    with pytest.raises(ValueError, match="nonempty remote"):
        release.check_remote_history()


@pytest.mark.parametrize("wrong", ["cli", "ssh", None])
def test_explicit_release_identity_never_falls_back(monkeypatch, wrong):
    from types import SimpleNamespace

    monkeypatch.setenv("GH_TOKEN", "ambient-account-token")
    monkeypatch.delenv("GIT_SSH", raising=False)
    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    monkeypatch.setattr(release, "COMMAND_ENV", None)
    monkeypatch.setattr(release, "origin_host", lambda: "release-host")
    monkeypatch.setattr(
        release, "command", lambda *args: "maintainer <maintainer@example.test> 1 +0000"
    )
    seen = []

    def run(args, **kwargs):
        seen.append(args)
        if args[:2] == ["git", "config"]:
            return SimpleNamespace(returncode=1)
        if args[:3] == ["gh", "auth", "token"]:
            assert args[-1] == "maintainer"
            assert "GH_TOKEN" not in kwargs["env"]
            return SimpleNamespace(returncode=0, stdout="selected-account-token\n")
        if args[:3] == ["gh", "api", "user"]:
            assert kwargs["env"]["GH_TOKEN"] == "selected-account-token"
            return SimpleNamespace(returncode=0, stdout="other" if wrong == "cli" else "maintainer")
        assert args[0] == "ssh" and args[-1] == "git@release-host"
        login = "other" if wrong == "ssh" else "maintainer"
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr=(
                f"Hi {login}! You've successfully authenticated, "
                "but GitHub does not provide shell access.\n"
            ),
        )

    monkeypatch.setattr(release.subprocess, "run", run)
    if wrong:
        with pytest.raises(ValueError, match="identity"):
            release.configure_identity("maintainer")
        assert release.COMMAND_ENV is None
        if wrong == "cli":
            assert not any(args[0] == "ssh" for args in seen)
    else:
        release.configure_identity("maintainer")
        assert release.COMMAND_ENV["GH_TOKEN"] == "selected-account-token"


@pytest.mark.parametrize("hostname,accepted", [("github.com", True), ("example.test", False)])
def test_origin_alias_preserves_only_intended_destination(monkeypatch, hostname, accepted):
    def command(*args):
        if args[0] == "ssh":
            assert args == ("ssh", "-G", "git@release-host")
            return f"hostname {hostname}\nuser git\n"
        return "git@release-host:guardfulai/guardfulai-python.git"

    monkeypatch.setattr(release, "command", command)
    if accepted:
        assert release.origin_host() == "release-host"
    else:
        with pytest.raises(ValueError, match="resolve"):
            release.origin_host()


def test_socketpair_works_but_direct_connections_stay_blocked():
    import socket

    a, b = socket.socketpair()
    with a, b:
        a.sendall(b"test")
        assert b.recv(4) == b"test"
    for method in ("connect", "connect_ex"):
        with socket.socket() as sock, pytest.raises(AssertionError, match="mocked"):
            getattr(sock, method)(("127.0.0.1", 1))
