"""Configuration CLI, redaction and documentation ownership contract (#344)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from api.settings import InsecureConfigurationError, Settings
from api import settings_cli

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_settings_environment_matches_the_documented_owner_index():
    owned = settings_cli.settings_environment_names()
    indexed = settings_cli.documentation_index_names()
    mentioned = settings_cli.documentation_mentions()

    assert owned == indexed
    assert owned <= mentioned
    assert "OCTO_WEB_DIST" in mentioned


def test_effective_configuration_redacts_credentials_and_url_userinfo():
    settings = Settings()
    settings.jwt_secret = "current-jwt-secret"
    settings.jwt_secret_previous = ["previous-jwt-secret"]
    settings.agent_token = "legacy-agent-token"
    settings.metrics_token = "metrics-bearer-token"
    settings.postgres_url = "postgresql+psycopg://octo:database-password@db/shapoclyack"
    settings.users = [
        {"username": "admin", "password": "bootstrap-password", "role": "admin"}
    ]

    rendered = settings_cli.redacted_settings(settings)
    serialized = json.dumps(rendered, sort_keys=True)

    for secret in (
        "current-jwt-secret",
        "previous-jwt-secret",
        "legacy-agent-token",
        "metrics-bearer-token",
        "database-password",
        "bootstrap-password",
    ):
        assert secret not in serialized
    assert rendered["jwt_secret"] == settings_cli.REDACTED
    assert rendered["jwt_secret_previous"] == [settings_cli.REDACTED]
    assert rendered["users"][0]["username"] == "admin"
    assert rendered["users"][0]["password"] == settings_cli.REDACTED
    assert rendered["postgres_url"] == (
        "postgresql+psycopg://<redacted>@db/shapoclyack"
    )


def test_cli_success_prints_only_a_redacted_effective_configuration(capsys):
    settings = Settings()
    settings.jwt_secret = "cli-jwt-secret"
    settings.metrics_token = "cli-metrics-token"

    result = settings_cli.main(
        ["--check"],
        load_settings_fn=lambda: settings,
        insecure_error_type=InsecureConfigurationError,
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert captured.out.startswith("configuration: OK\n")
    assert "cli-jwt-secret" not in captured.out
    assert "cli-metrics-token" not in captured.out
    assert settings_cli.REDACTED in captured.out


def test_cli_does_not_echo_an_invalid_raw_value(capsys):
    def _invalid() -> Settings:
        raise ValueError("invalid literal for int(): 'do-not-print-me'")

    result = settings_cli.main(
        ["--check"],
        load_settings_fn=_invalid,
        insecure_error_type=InsecureConfigurationError,
    )

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert "configuration: INVALID" in captured.err
    assert "do-not-print-me" not in captured.err
    assert "value redacted" in captured.err


def test_python_m_api_settings_check_uses_the_real_loader_without_leaking(tmp_path):
    env = os.environ.copy()
    env.update(
        {
            "OCTO_ENV": "dev",
            "OCTO_JWT_SECRET": "subprocess-jwt-secret",
            "OCTO_METRICS_TOKEN": "subprocess-metrics-secret",
            "OCTO_POSTGRES_URL": (
                "postgresql+psycopg://octo:subprocess-db-secret@db/shapoclyack"
            ),
            "OCTO_OUTPUT_DIR": str(tmp_path / "output"),
            "OCTO_STATE_DIR": str(tmp_path / "state"),
        }
    )

    completed = subprocess.run(
        [sys.executable, "-m", "api.settings", "--check"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "configuration: OK" in output
    assert "subprocess-jwt-secret" not in output
    assert "subprocess-metrics-secret" not in output
    assert "subprocess-db-secret" not in output
    assert settings_cli.REDACTED in output
