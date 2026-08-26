"""Fail-closed startup configuration (#155, #174).

The property under test is that "forgot to configure" and "configured" are
distinguishable. Every case therefore drives ``load_settings()`` through the
real environment rather than constructing ``Settings`` directly — the whole
point is what the process does with what the deployment actually hands it.
"""

from __future__ import annotations

import json

import pytest

from api.settings import (
    DEFAULT_JWT_SECRET,
    ENV_DEV,
    ENV_PROD,
    InsecureConfigurationError,
    load_settings,
)


CONFIGURED_USERS = json.dumps([{"username": "ops", "password": "$2b$12$x", "role": "admin"}])

CONFIGURED_POSTGRES = "postgresql+psycopg://scan:secret@postgres:5432/shapoclyack"

# The variables that decide the outcome. Cleared per test so a value inherited
# from the developer's shell cannot make a refusal test pass by accident (or a
# success test fail for a reason it never asserts).
_DECIDING_VARS = (
    "OCTO_ENV",
    "OCTO_JWT_SECRET",
    "API_SECRET_KEY",
    "OCTO_API_USERS",
    "OCTO_API_CORS",
    "OCTO_POSTGRES_URL",
    "OCTO_HSTS_ENABLED",
)


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in _DECIDING_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def _configure_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fully configured production environment — the baseline that must start."""
    monkeypatch.setenv("OCTO_ENV", ENV_PROD)
    monkeypatch.setenv("OCTO_JWT_SECRET", "a-real-and-sufficiently-long-secret")
    monkeypatch.setenv("OCTO_API_USERS", CONFIGURED_USERS)
    monkeypatch.setenv("OCTO_API_CORS", "https://console.example.com")
    monkeypatch.setenv("OCTO_POSTGRES_URL", CONFIGURED_POSTGRES)


def test_prod_is_the_default_environment(clean_env: pytest.MonkeyPatch) -> None:
    """An unset OCTO_ENV must not be the permissive one."""
    with pytest.raises(InsecureConfigurationError):
        load_settings()


def test_prod_refuses_every_default_and_names_them_all(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("OCTO_ENV", ENV_PROD)

    with pytest.raises(InsecureConfigurationError) as excinfo:
        load_settings()

    message = str(excinfo.value)
    # All at once: an operator fixing them one restart at a time would
    # otherwise learn about the next only after redeploying.
    assert "OCTO_JWT_SECRET" in message
    assert "OCTO_API_CORS" in message
    assert "OCTO_POSTGRES_URL" in message


def test_console_accounts_are_not_checked_here(clean_env: pytest.MonkeyPatch) -> None:
    """Since #156 accounts live in Postgres, so an unset OCTO_API_USERS is normal.

    Only the database can tell an install with a real admin from one with none;
    that check is users_service.bootstrap(), which runs once the store is up.
    """
    _configure_prod(clean_env)
    clean_env.delenv("OCTO_API_USERS", raising=False)

    settings = load_settings()

    assert settings.env == ENV_PROD


def test_refusal_never_echoes_configured_values(clean_env: pytest.MonkeyPatch) -> None:
    """The message reaches logs and terminals, so it names variables, not values."""
    clean_env.setenv("OCTO_ENV", ENV_PROD)
    clean_env.setenv("OCTO_JWT_SECRET", DEFAULT_JWT_SECRET)
    clean_env.setenv("OCTO_API_USERS", CONFIGURED_USERS)

    with pytest.raises(InsecureConfigurationError) as excinfo:
        load_settings()

    message = str(excinfo.value)
    assert DEFAULT_JWT_SECRET not in message
    assert "$2b$12$x" not in message


def test_prod_refuses_the_default_jwt_secret_when_set_explicitly(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """Copying the published default into the Secret is not configuration."""
    _configure_prod(clean_env)
    clean_env.setenv("OCTO_JWT_SECRET", DEFAULT_JWT_SECRET)

    with pytest.raises(InsecureConfigurationError, match="OCTO_JWT_SECRET"):
        load_settings()


def test_prod_refuses_empty_jwt_secret(clean_env: pytest.MonkeyPatch) -> None:
    _configure_prod(clean_env)
    clean_env.setenv("OCTO_JWT_SECRET", "")
    clean_env.setenv("API_SECRET_KEY", "")

    with pytest.raises(InsecureConfigurationError, match="OCTO_JWT_SECRET"):
        load_settings()


def test_prod_accepts_the_secret_from_api_secret_key(clean_env: pytest.MonkeyPatch) -> None:
    """API_SECRET_KEY is the other accepted spelling and must satisfy the check."""
    _configure_prod(clean_env)
    clean_env.delenv("OCTO_JWT_SECRET", raising=False)
    clean_env.setenv("API_SECRET_KEY", "a-real-and-sufficiently-long-secret")

    assert load_settings().jwt_secret == "a-real-and-sufficiently-long-secret"


def test_prod_refuses_wildcard_cors(clean_env: pytest.MonkeyPatch) -> None:
    _configure_prod(clean_env)
    clean_env.setenv("OCTO_API_CORS", "*")

    with pytest.raises(InsecureConfigurationError, match="OCTO_API_CORS"):
        load_settings()


def test_prod_refuses_wildcard_listed_beside_real_origins(clean_env: pytest.MonkeyPatch) -> None:
    """["*", "https://x"] is exactly as open as ["*"] while looking deliberate."""
    _configure_prod(clean_env)
    clean_env.setenv("OCTO_API_CORS", "https://console.example.com,*")

    with pytest.raises(InsecureConfigurationError, match="OCTO_API_CORS"):
        load_settings()


def test_prod_refuses_the_sqlite_fallback(clean_env: pytest.MonkeyPatch) -> None:
    """#174 — an unset OCTO_POSTGRES_URL must not quietly become a local file.

    The pre-existing guard in tenants_service.load_tenants() never fires here:
    load_settings() has already substituted a URL that resolves, so the empty
    value it checks for cannot reach it.
    """
    _configure_prod(clean_env)
    clean_env.delenv("OCTO_POSTGRES_URL", raising=False)

    with pytest.raises(InsecureConfigurationError, match="OCTO_POSTGRES_URL"):
        load_settings()


def test_prod_refuses_an_explicit_sqlite_url(clean_env: pytest.MonkeyPatch) -> None:
    """Not only "forgot to set it" but also "set it to the wrong thing"."""
    _configure_prod(clean_env)
    clean_env.setenv("OCTO_POSTGRES_URL", "sqlite:///scanner/state/shapoclyack.db")

    with pytest.raises(InsecureConfigurationError, match="OCTO_POSTGRES_URL"):
        load_settings()


def test_sqlite_refusal_explains_the_multi_replica_consequence(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """Naming the variable is not enough — the operator has to know why."""
    _configure_prod(clean_env)
    clean_env.delenv("OCTO_POSTGRES_URL", raising=False)

    with pytest.raises(InsecureConfigurationError) as excinfo:
        load_settings()

    message = str(excinfo.value)
    assert "replica" in message
    assert "SKIP LOCKED" in message


def test_sqlite_refusal_distinguishes_unset_from_misconfigured(
    clean_env: pytest.MonkeyPatch,
) -> None:
    _configure_prod(clean_env)
    clean_env.delenv("OCTO_POSTGRES_URL", raising=False)
    with pytest.raises(InsecureConfigurationError) as unset:
        load_settings()

    clean_env.setenv("OCTO_POSTGRES_URL", "sqlite:///tmp/whatever.db")
    with pytest.raises(InsecureConfigurationError) as wrong:
        load_settings()

    assert "unset" in str(unset.value)
    assert "unset" not in str(wrong.value)


def test_fully_configured_prod_starts(clean_env: pytest.MonkeyPatch) -> None:
    _configure_prod(clean_env)

    settings = load_settings()

    assert settings.env == ENV_PROD
    assert settings.cors_origins == ["https://console.example.com"]
    assert settings.users[0]["username"] == "ops"
    assert settings.postgres_url == CONFIGURED_POSTGRES


def test_dev_allows_every_default(clean_env: pytest.MonkeyPatch) -> None:
    """The escape hatch has to actually work, or it is not an escape hatch."""
    clean_env.setenv("OCTO_ENV", ENV_DEV)

    settings = load_settings()

    assert settings.env == ENV_DEV
    assert settings.jwt_secret == DEFAULT_JWT_SECRET
    assert settings.cors_origins == ["*"]
    # The SQLite fallback is deliberate here: dev and the test suite must not
    # need a database to start (#174 refuses it only under OCTO_ENV=prod).
    assert settings.postgres_url.startswith("sqlite")


def test_unrecognised_env_is_refused(clean_env: pytest.MonkeyPatch) -> None:
    """A typo must be named, not guessed in either direction."""
    clean_env.setenv("OCTO_ENV", "staging")

    with pytest.raises(InsecureConfigurationError, match="OCTO_ENV"):
        load_settings()


def test_env_value_is_case_insensitive(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("OCTO_ENV", "DEV")

    assert load_settings().env == ENV_DEV


def test_legacy_agent_token_warns_but_starts(
    clean_env: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A working install must not be broken over a design preference."""
    _configure_prod(clean_env)
    clean_env.setenv("OCTO_AGENT_TOKEN", "legacy-shared-token")

    with caplog.at_level("WARNING", logger="api.settings"):
        settings = load_settings()

    assert settings.agent_token == "legacy-shared-token"
    assert "OCTO_AGENT_TOKEN" in caplog.text
    assert "legacy-shared-token" not in caplog.text


def test_hsts_defaults_to_the_environment(clean_env: pytest.MonkeyPatch) -> None:
    """#224: HSTS had no environment variable at all, so the header could not be
    turned on. The default follows OCTO_ENV rather than being a flag an operator
    has to remember, and stays overridable in both directions."""
    _configure_prod(clean_env)
    assert load_settings().hsts_enabled is True

    clean_env.setenv("OCTO_HSTS_ENABLED", "false")
    assert load_settings().hsts_enabled is False

    clean_env.setenv("OCTO_ENV", ENV_DEV)
    clean_env.delenv("OCTO_HSTS_ENABLED", raising=False)
    assert load_settings().hsts_enabled is False

    clean_env.setenv("OCTO_HSTS_ENABLED", "true")
    assert load_settings().hsts_enabled is True
