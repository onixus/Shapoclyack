"""Configuration validation CLI and documentation parity helpers (#344).

``api.settings`` remains the runtime loader. This module keeps the command-line
surface, redaction and source/documentation inspection out of an already large
settings file while still letting operators run ``python -m api.settings
--check`` against exactly the loader the API uses at startup.
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import json
import os
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SETTINGS_SOURCE = REPO_ROOT / "api" / "settings.py"
CONFIGURATION_DOC = REPO_ROOT / "docs" / "configuration.md"

ENVIRONMENT_NAME_RE = re.compile(r"OCTO_[A-Z0-9_]+")
ENV_INDEX_START = "<!-- BEGIN API SETTINGS ENV INDEX -->"
ENV_INDEX_END = "<!-- END API SETTINGS ENV INDEX -->"
REDACTED = "<redacted>"

_SECRET_EXACT_NAMES = frozenset(
    {
        "access_key",
        "agent_jwt_secret",
        "api_key",
        "password",
        "private_key",
        "secret",
        "secret_key",
        "session_token",
        "token",
        "agent_jwt_secret_previous",
        "agent_token",
        "artifact_s3_access_key",
        "artifact_s3_access_key_id",
        "artifact_s3_secret_key",
        "artifact_s3_session_token",
        "jwt_secret",
        "jwt_secret_previous",
        "metrics_token",
        "oidc_client_secret",
        "report_smtp_password",
    }
)
_SECRET_SUFFIXES = (
    "_api_key",
    "_client_secret",
    "_password",
    "_private_key",
    "_secret",
    "_secret_key",
    "_session_token",
    "_token",
)
_URL_USERINFO_RE = re.compile(r"([a-z][a-z0-9+.-]*://)[^\s/@]+@", re.IGNORECASE)


def settings_environment_names(path: Path = SETTINGS_SOURCE) -> set[str]:
    """Return literal ``OCTO_*`` variables owned by ``api.settings``.

    AST constants are used instead of a source regex so comments and prose do
    not quietly become supported configuration. A variable constructed at
    runtime would be invisible here by design: configuration names are an API
    and should be searchable literals.
    """

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and ENVIRONMENT_NAME_RE.fullmatch(node.value)
    }


def documentation_index_names(path: Path = CONFIGURATION_DOC) -> set[str]:
    """Return the machine-readable settings-owner index from the docs."""

    body = _documentation_index_body(path.read_text(encoding="utf-8"))
    return set(ENVIRONMENT_NAME_RE.findall(body))


def documentation_mentions(path: Path = CONFIGURATION_DOC) -> set[str]:
    """Return human-facing variable mentions outside the generated index."""

    text = path.read_text(encoding="utf-8")
    start = text.find(ENV_INDEX_START)
    end = text.find(ENV_INDEX_END)
    if start < 0 or end < 0 or end < start:
        raise ValueError("configuration documentation has no valid API settings index")
    human_text = text[:start] + text[end + len(ENV_INDEX_END) :]
    return set(ENVIRONMENT_NAME_RE.findall(human_text))


def render_environment_index(names: set[str]) -> str:
    """Render the collapsed ownership manifest embedded in configuration.md."""

    listed = "\n".join(sorted(names))
    return (
        "<details>\n"
        "<summary>Machine-readable variables owned by <code>api/settings.py</code></summary>\n\n"
        "This index is checked against the loader and against the human-facing\n"
        "documentation below. It is not a second source of defaults.\n\n"
        f"{ENV_INDEX_START}\n"
        "```text\n"
        f"{listed}\n"
        "```\n"
        f"{ENV_INDEX_END}\n\n"
        "</details>"
    )


def documentation_parity(
    *, settings_path: Path = SETTINGS_SOURCE, documentation_path: Path = CONFIGURATION_DOC
) -> tuple[set[str], set[str], set[str]]:
    """Return ``(missing_from_index, stale_in_index, undocumented)``."""

    owned = settings_environment_names(settings_path)
    indexed = documentation_index_names(documentation_path)
    mentioned = documentation_mentions(documentation_path)
    return owned - indexed, indexed - owned, owned - mentioned


def redacted_settings(settings: Any) -> dict[str, Any]:
    """Serialize a Settings instance without credentials or URL userinfo."""

    if not dataclasses.is_dataclass(settings):
        raise TypeError("redacted_settings expects a dataclass instance")
    return {
        field.name: _redact_value(field.name, getattr(settings, field.name))
        for field in dataclasses.fields(settings)
    }


def _documentation_index_body(text: str) -> str:
    start = text.find(ENV_INDEX_START)
    end = text.find(ENV_INDEX_END)
    if start < 0 or end < 0 or end < start:
        raise ValueError("configuration documentation has no valid API settings index")
    return text[start + len(ENV_INDEX_START) : end]


def _is_sensitive_name(name: str) -> bool:
    normalized = name.strip().lower()
    if normalized in _SECRET_EXACT_NAMES:
        return True
    return normalized.endswith(_SECRET_SUFFIXES)


def _redact_value(name: str, value: Any) -> Any:
    if _is_sensitive_name(name):
        if value in (None, ""):
            return value
        if isinstance(value, (list, tuple)):
            return [REDACTED for _ in value]
        return REDACTED
    if dataclasses.is_dataclass(value):
        return {
            field.name: _redact_value(field.name, getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, Mapping):
        return {str(key): _redact_value(str(key), item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_redact_value(name, item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str):
        return _redact_url(value)
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    return value


def _redact_url(value: str) -> str:
    """Remove URL userinfo and sensitive query values without parsing the host."""

    redacted = _URL_USERINFO_RE.sub(rf"\1{REDACTED}@", value)
    if "?" not in redacted:
        return redacted
    base, query = redacted.split("?", 1)
    chunks: list[str] = []
    for chunk in query.split("&"):
        key, separator, raw_value = chunk.partition("=")
        if separator and _is_sensitive_name(key):
            chunks.append(f"{key}={REDACTED}")
        else:
            chunks.append(chunk if separator else key)
    return f"{base}?{'&'.join(chunks)}"


def _redact_exception_text(text: str) -> str:
    """Scrub configured secrets before a validation error reaches a terminal."""

    result = _URL_USERINFO_RE.sub(rf"\1{REDACTED}@", text)
    for name, value in os.environ.items():
        if value and (_is_sensitive_name(name) or name == "API_SECRET_KEY"):
            result = result.replace(value, REDACTED)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m api.settings",
        description="Validate API configuration without starting the service.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="load and validate the current environment, then exit",
    )
    parser.add_argument(
        "--no-effective-config",
        action="store_true",
        help="print only the verdict, not the redacted effective configuration",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    load_settings_fn: Callable[[], Any] | None = None,
    insecure_error_type: type[Exception] | None = None,
) -> int:
    """Validate current configuration and print a redacted effective view."""

    parser = _parser()
    args = parser.parse_args(argv)
    if not args.check:
        parser.error("--check is required")

    if load_settings_fn is None or insecure_error_type is None:
        from api import settings as settings_module

        load_settings_fn = load_settings_fn or settings_module.load_settings
        insecure_error_type = insecure_error_type or settings_module.InsecureConfigurationError

    try:
        settings = load_settings_fn()
    except insecure_error_type as exc:
        print("configuration: INVALID", file=sys.stderr)
        print(_redact_exception_text(str(exc)), file=sys.stderr)
        return 1
    except (OSError, TypeError, ValueError) as exc:
        # Python's conversion errors quote the rejected value. That value came
        # from the environment and may itself be sensitive, so report the class
        # rather than obediently copying it into CI logs.
        print("configuration: INVALID", file=sys.stderr)
        print(
            f"{type(exc).__name__}: invalid configuration value (value redacted)",
            file=sys.stderr,
        )
        return 1

    print("configuration: OK")
    if not args.no_effective_config:
        print(json.dumps(redacted_settings(settings), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - direct helper invocation
    raise SystemExit(main())
