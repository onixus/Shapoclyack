"""Installation safety and lifecycle checks without a Docker daemon."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

spec = importlib.util.spec_from_file_location(
    "server_installer", Path(__file__).resolve().parents[1] / "scripts/install-server.py"
)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def test_prepare_production_and_preserve_secrets(tmp_path):
    args = argparse.Namespace(image=installer.DEFAULT_IMAGE, url="https://scan.example.com", port=8080)
    installer.prepare(tmp_path, args)
    path = tmp_path / "compose.json"
    before = path.read_bytes()
    config = json.loads(before)
    api = config["services"]["api"]
    assert api["environment"]["OCTO_ENV"] == "prod"
    assert api["ports"] == ["127.0.0.1:8080:8080"]
    assert "@sha256:" in api["image"]
    assert all("build" not in service for service in config["services"].values())
    assert "ports" not in config["services"]["postgres"]
    assert path.stat().st_mode & 0o777 == 0o600
    credentials = json.loads((tmp_path / "access.json").read_text())
    assert len(credentials["password"]) >= 24
    assert json.loads(api["environment"]["OCTO_API_USERS"])[0]["password"] == credentials["password"]
    with pytest.raises(ValueError, match="empty"):
        installer.prepare(tmp_path, args)
    assert path.read_bytes() == before


@pytest.mark.parametrize("value", ["http://scan.example.com", "https://user:pass@x", "https://x/a",
                                   "https://x?bad=1", "https://x:$PORT", "https://x:99999"])
def test_reject_invalid_public_url(value):
    with pytest.raises(argparse.ArgumentTypeError):
        installer.origin(value)


def test_migration_failure_never_starts_api(tmp_path, monkeypatch):
    calls = []

    def compose(directory, *args, **kwargs):
        calls.append(args)
        if args[0] == "run":
            raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(installer, "compose", compose)
    monkeypatch.setattr(installer, "backup", lambda directory: calls.append(("backup",)))
    with pytest.raises(subprocess.CalledProcessError):
        installer.start(tmp_path, 120)
    assert calls[0] == ("pull",)
    assert calls[2:4] == [("stop", "api"), ("backup",)]
    assert not any(args[0] == "up" and args[-1] == "api" for args in calls)


def test_pull_failure_does_not_stop_running_installation(tmp_path, monkeypatch):
    calls = []

    def compose(directory, *args, **kwargs):
        calls.append(args)
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(installer, "compose", compose)
    with pytest.raises(subprocess.CalledProcessError):
        installer.start(tmp_path, 120)
    assert calls == [("pull",)]


def test_failed_backup_removed(tmp_path, monkeypatch):
    def compose(*args, **kwargs):
        kwargs["stdout"].write(b"partial dump")
        raise subprocess.CalledProcessError(1, ["pg_dump"])

    monkeypatch.setattr(installer, "compose", compose)
    with pytest.raises(subprocess.CalledProcessError):
        installer.backup(tmp_path)
    assert not list((tmp_path / "backups").iterdir())


def test_success_requires_readiness_and_never_builds(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(installer, "compose", lambda directory, *args: calls.append(args))
    monkeypatch.setattr(installer, "backup", lambda directory: calls.append(("backup",)))
    installer.start(tmp_path, 120)
    assert calls[-1] == ("up", "-d", "--no-build", "--wait", "--wait-timeout", "120", "api")
    assert calls[-2] == ("run", "--rm", "--no-deps", "--pull", "never", "api",
                         "python", "-m", "api.db.migrate")
    assert all("build" not in args for args in calls)
