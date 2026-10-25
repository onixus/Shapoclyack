"""Disposable operational drill rejects unsafe inputs before Docker access."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/operator-acceptance-drill.py"


@pytest.fixture
def drill_module():
    spec = importlib.util.spec_from_file_location("operator_acceptance_drill", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("reference", ["latest", "postgres:16", "--privileged", "$(id)",
    "sha256:" + "a" * 63, "image@sha256:" + "a" * 64])
def test_mutable_or_shell_image_input_is_rejected_before_docker(drill_module, reference):
    with pytest.raises(argparse.ArgumentTypeError):
        drill_module.checked_image(reference)


@pytest.mark.parametrize("symlink", [False, True])
def test_report_cannot_overwrite_existing_file_or_symlink(tmp_path, symlink):
    target = tmp_path / "important.json"
    target.write_text("preserve")
    report = tmp_path / "report.json"
    if symlink:
        report.symlink_to(target)
    else:
        report.write_text("preserve")
    result = subprocess.run([sys.executable, "-B", str(SCRIPT),
        "--app-image", "sha256:" + "a" * 64,
        "--postgres-image", "sha256:" + "b" * 64,
        "--report", str(report)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "Report must be a new regular file" in result.stderr
    assert target.read_text() == report.read_text() == "preserve"


def test_source_snapshot_refuses_symlink_before_mounting_host_files(drill_module, tmp_path, monkeypatch):
    source = tmp_path / "checkout"
    (source / "api").mkdir(parents=True)
    private = tmp_path / "private"
    private.write_text("private fixture")
    (source / "api" / "unsafe.py").symlink_to(private)
    monkeypatch.setattr(drill_module, "ROOT", source)
    drill = object.__new__(drill_module.Drill)
    drill.source_root = tmp_path / "snapshot"
    drill.run = lambda args: b"api/unsafe.py\0"
    with pytest.raises(RuntimeError, match="Refusing symlink"):
        drill.setup()
    assert not drill.source_root.exists()


def test_docker_cleanup_failure_is_reported_without_global_cleanup(drill_module):
    drill = object.__new__(drill_module.Drill)
    drill.containers = ["task-only-container"]
    drill.network_created = False
    drill.report = {"status": "passed"}
    calls = []

    def failed(*args, **kwargs):
        calls.append(args)
        raise subprocess.TimeoutExpired("docker", 20)

    drill.docker = failed
    drill.cleanup()
    assert calls == [("rm", "--force", "--volumes", "task-only-container")]
    assert drill.report["status"] == "failed"
    assert drill.report["cleanup"] is False
    assert drill.report["cleanup_pending_resources"] == ["task-only-container"]


def test_command_error_redacts_task_credentials(drill_module, monkeypatch):
    drill = object.__new__(drill_module.Drill)
    drill.password = "private-drill-password"
    monkeypatch.setattr(drill_module.subprocess, "run", lambda *a, **k:
        subprocess.CompletedProcess(a, 1, stdout=b"", stderr=b"connect private-drill-password rejected"))
    with pytest.raises(RuntimeError) as raised:
        drill.run(["docker", "exec", "task-only-container"])
    assert "private-drill-password" not in str(raised.value)
    assert "[redacted]" in str(raised.value)


@pytest.mark.parametrize("enabled", [False, True])
def test_generated_feature_disable_configuration_passes_real_settings_validation(drill_module, tmp_path, monkeypatch, enabled):
    from api.settings import load_settings

    drill = object.__new__(drill_module.Drill)
    drill.directory = tmp_path
    drill.password = "private-database-password"
    drill.login_password = "private-console-password"
    drill.jwt_secret = "a" * 64
    drill.master_key = "b" * 64
    drill.provider_url = "http://127.0.0.1:8080/v1"
    path = drill.environment("drill.env", enabled=enabled)
    for line in path.read_text().splitlines():
        name, value = line.split("=", 1)
        monkeypatch.setenv(name, value)
    settings = load_settings()
    assert settings.operator_enabled is enabled
    assert settings.operator_worker_enabled is enabled
    assert settings.output_dir.is_absolute() and settings.state_dir.is_absolute()
    assert path.stat().st_mode & 0o777 == 0o600
