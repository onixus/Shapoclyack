"""Configuration CLI, redaction and documentation ownership contract (#344)."""

from __future__ import annotations

import dataclasses
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from sqlalchemy.engine import make_url

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
    assert "invalid literal for int(): <redacted>" in captured.err


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


# Settings fields whose names look like credentials but hold a lifetime, a
# switch or a counter. Only non-string fields may be listed: a string field
# with a secret-looking name is presumed to be a credential.
_NON_SECRET_SETTINGS_FIELDS = frozenset(
    {
        "access_token_expire_minutes",
        "provisioning_key_ttl_days",
        "service_tokens_enabled",
        "service_token_default_ttl_days",
        "service_token_max_ttl_days",
        "service_token_last_used_interval_seconds",
        "webhook_allow_private_targets",
    }
)
_SECRET_LOOKING_NAME_RE = re.compile(r"secret|passw|token|key|private|credential", re.IGNORECASE)


def test_every_secret_looking_settings_field_is_redacted():
    # Walks the dataclass instead of a hand-written list: the S3 secret leaked
    # because its field name matched neither the exact names nor the suffixes,
    # and a list in the test would have repeated the same omission.
    fields = {field.name: field for field in dataclasses.fields(Settings)}
    assert _NON_SECRET_SETTINGS_FIELDS <= set(fields)

    settings = Settings()
    sentinels: dict[str, str] = {}
    for name, field in fields.items():
        if not _SECRET_LOOKING_NAME_RE.search(name):
            continue
        if name in _NON_SECRET_SETTINGS_FIELDS:
            assert field.type in ("int", "bool", int, bool), name
            continue
        sentinel = f"sentinel-{name.replace('_', '-')}"
        sentinels[name] = sentinel
        value = getattr(settings, name)
        setattr(settings, name, [sentinel] if isinstance(value, list) else sentinel)

    assert "artifact_s3_secret_access_key" in sentinels
    rendered = settings_cli.redacted_settings(settings)
    serialized = json.dumps(rendered, sort_keys=True)
    leaked = sorted(name for name, sentinel in sentinels.items() if sentinel in serialized)
    assert leaked == []
    for name in sentinels:
        assert rendered[name] in (settings_cli.REDACTED, [settings_cli.REDACTED]), name


def _real_loader_env(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("OCTO_ENV", "dev")
    monkeypatch.setenv("OCTO_OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setenv("OCTO_STATE_DIR", str(tmp_path / "state"))


def test_cli_does_not_print_the_s3_secret_access_key(tmp_path, monkeypatch, capsys):
    _real_loader_env(monkeypatch, tmp_path)
    monkeypatch.setenv("OCTO_ARTIFACT_S3_ACCESS_KEY_ID", "AKIAEXAMPLEKEYID")
    monkeypatch.setenv("OCTO_ARTIFACT_S3_SECRET_ACCESS_KEY", "wJalrXUtnFEMI-s3-secret-access-key")

    result = settings_cli.main(["--check"])

    captured = capsys.readouterr()
    assert result == 0, captured.err
    assert "wJalrXUtnFEMI-s3-secret-access-key" not in captured.out + captured.err
    rendered = json.loads(captured.out.split("\n", 1)[1])
    assert rendered["artifact_s3_secret_access_key"] == settings_cli.REDACTED


def test_insecure_error_text_scrubs_the_s3_secret_access_key(monkeypatch, capsys):
    monkeypatch.setenv("OCTO_ARTIFACT_S3_SECRET_ACCESS_KEY", "s3-secret-in-refusal")

    def _refuse() -> Settings:
        raise InsecureConfigurationError("refusing: key s3-secret-in-refusal is weak")

    result = settings_cli.main(
        ["--check"],
        load_settings_fn=_refuse,
        insecure_error_type=InsecureConfigurationError,
    )

    captured = capsys.readouterr()
    assert result == 1
    assert "s3-secret-in-refusal" not in captured.err
    assert "refusing: key <redacted> is weak" in captured.err


# SQLAlchemy's URL grammar takes everything between the first ':' after the
# username and the '@' as the password, so '/', ':', '#' and '?' are all legal
# unencoded password characters there.
_AWKWARD_PASSWORD = "ab/cd:ef#gh?ij"
_AWKWARD_URL = f"postgresql+psycopg://octo:{_AWKWARD_PASSWORD}@db/shapoclyack"
_AWKWARD_FRAGMENTS = ("ab/cd", "cd:ef", "ef#gh", "gh?ij")


def test_url_password_with_reserved_characters_is_redacted_whole():
    assert make_url(_AWKWARD_URL).password == _AWKWARD_PASSWORD
    settings = Settings()
    settings.postgres_url = _AWKWARD_URL

    rendered = settings_cli.redacted_settings(settings)

    assert rendered["postgres_url"] == "postgresql+psycopg://<redacted>@db/shapoclyack"
    serialized = json.dumps(rendered)
    for fragment in _AWKWARD_FRAGMENTS:
        assert fragment not in serialized


def test_error_text_redacts_url_password_with_reserved_characters(capsys):
    def _refuse() -> Settings:
        raise InsecureConfigurationError(f"refusing to use {_AWKWARD_URL} in prod")

    result = settings_cli.main(
        ["--check"],
        load_settings_fn=_refuse,
        insecure_error_type=InsecureConfigurationError,
    )

    captured = capsys.readouterr()
    assert result == 1
    for fragment in _AWKWARD_FRAGMENTS:
        assert fragment not in captured.err
    assert "postgresql+psycopg://<redacted>@db/shapoclyack in prod" in captured.err


def test_conversion_error_names_the_variable_without_its_value(tmp_path, monkeypatch, capsys):
    _real_loader_env(monkeypatch, tmp_path)
    monkeypatch.setenv("OCTO_DB_POOL_SIZE", "not-a-pool-size")

    result = settings_cli.main(["--check"])

    captured = capsys.readouterr()
    assert result == 1
    assert "configuration: INVALID" in captured.err
    assert "OCTO_DB_POOL_SIZE" in captured.err
    assert "not-a-pool-size" not in captured.err


def test_conversion_error_does_not_leak_a_secret_pasted_into_the_wrong_variable(
    tmp_path, monkeypatch, capsys
):
    # An operator pasting the SMTP password into a numeric variable is exactly
    # the case where the rejected value is a credential under a harmless name.
    _real_loader_env(monkeypatch, tmp_path)
    monkeypatch.setenv("OCTO_REPORT_SMTP_PORT", "smtp-password-pasted-here")

    result = settings_cli.main(["--check"])

    captured = capsys.readouterr()
    assert result == 1
    assert "OCTO_REPORT_SMTP_PORT" in captured.err
    assert "smtp-password-pasted-here" not in captured.err


def test_loader_validation_message_reaches_the_operator(tmp_path, monkeypatch, capsys):
    _real_loader_env(monkeypatch, tmp_path)
    monkeypatch.setenv("OCTO_API_USERS", "{}")

    result = settings_cli.main(["--check"])

    captured = capsys.readouterr()
    assert result == 1
    assert "OCTO_API_USERS must be a non-empty JSON list" in captured.err


def test_malformed_users_json_does_not_leak_a_bootstrap_password(tmp_path, monkeypatch, capsys):
    _real_loader_env(monkeypatch, tmp_path)
    monkeypatch.setenv("OCTO_API_USERS", '[{"username": "admin", "password": "users-json-secret"')

    result = settings_cli.main(["--check"])

    captured = capsys.readouterr()
    assert result == 1
    assert "configuration: INVALID" in captured.err
    assert "users-json-secret" not in captured.err


def test_generic_error_scrubs_sensitive_environment_values(monkeypatch, capsys):
    monkeypatch.setenv("OCTO_REPORT_SMTP_PASSWORD", "smtp-secret-in-error")

    def _invalid() -> Settings:
        raise ValueError("cannot log in with smtp-secret-in-error")

    result = settings_cli.main(
        ["--check"],
        load_settings_fn=_invalid,
        insecure_error_type=InsecureConfigurationError,
    )

    captured = capsys.readouterr()
    assert result == 1
    assert "smtp-secret-in-error" not in captured.err
    assert "cannot log in with <redacted>" in captured.err
