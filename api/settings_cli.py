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
import traceback
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

# Credentials are recognised by the words in a name rather than by a list of
# field names: the first cut of #344 listed ``artifact_s3_secret_key`` while the
# field is ``artifact_s3_secret_access_key``, and ``--check`` printed the S3
# secret. A name is sensitive when any word carries one of these markers
# ("sslpassword" as much as "report_smtp_password") ...
_SECRET_MARKERS = ("secret", "passw", "passphrase", "credential")
# ... or when its last word names a credential. Only the last word counts, so
# lifetimes and switches such as ``service_token_max_ttl_days`` stay visible.
_SECRET_FINAL_WORDS = frozenset({"key", "keys", "token", "tokens"})
# Names neither rule catches. The S3 access key ID is not a secret in AWS terms,
# but on MinIO and Ceph it is the account half of a static credential pair, and
# the endpoint and bucket printed next to it already say which store is meant.
_SECRET_EXACT_NAMES = frozenset({"artifact_s3_access_key_id"})
_NAME_WORD_SPLIT_RE = re.compile(r"[^a-z0-9]+")

_URL_SCHEME_RE = re.compile(r"[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_URL_IN_TEXT_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^\s'\"<>]*", re.IGNORECASE)
# Python's own conversion errors end by quoting the rejected literal.
_CONVERSION_ERROR_RE = re.compile(
    r"^(invalid literal for [\w.]+\(\)[^:]*: |could not convert string to \w+: ).*$",
    re.DOTALL,
)


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
    if normalized in _SECRET_EXACT_NAMES or normalized.removeprefix("octo_") in _SECRET_EXACT_NAMES:
        return True
    if any(marker in normalized for marker in _SECRET_MARKERS):
        return True
    words = [word for word in _NAME_WORD_SPLIT_RE.split(normalized) if word]
    return bool(words) and words[-1] in _SECRET_FINAL_WORDS


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
    """Redact a setting value that is, or contains, URLs.

    A value that starts with a scheme is treated as one URL to its end, so a
    password with whitespace in it cannot cut the userinfo short. Anywhere
    else URLs are found as whitespace-delimited runs.
    """

    if _URL_SCHEME_RE.match(value):
        return _redact_single_url(value)
    return _redact_urls_in_text(value)


def _redact_urls_in_text(text: str) -> str:
    return _URL_IN_TEXT_RE.sub(lambda match: _redact_single_url(match.group(0)), text)


def _redact_single_url(url: str) -> str:
    """Remove userinfo and sensitive query values without parsing the host."""

    scheme = _URL_SCHEME_RE.match(url)
    if scheme is None:
        return url
    rest = url[scheme.end() :]
    # RFC 3986 ends the authority at the first '/', '?' or '#', but SQLAlchemy
    # reads everything after the username's ':' up to '@' as the password, so
    # 'postgresql://octo:ab/cd@db/x' has the password 'ab/cd'. The last '@' is
    # the only boundary both grammars agree cannot sit inside the userinfo; an
    # '@' in a path or query over-redacts the host, which is the safe way to be
    # wrong.
    at = rest.rfind("@")
    if at >= 0:
        rest = f"{REDACTED}{rest[at:]}"
    if "?" not in rest:
        return f"{scheme.group(0)}{rest}"
    base, query = rest.split("?", 1)
    chunks: list[str] = []
    for chunk in query.split("&"):
        key, separator, _raw_value = chunk.partition("=")
        if separator and _is_sensitive_name(key):
            chunks.append(f"{key}={REDACTED}")
        else:
            chunks.append(chunk if separator else key)
    return f"{scheme.group(0)}{base}?{'&'.join(chunks)}"


def _redact_exception_text(text: str, *, failing_names: Sequence[str] = ()) -> str:
    """Scrub configured secrets before a validation error reaches a terminal.

    ``failing_names`` are variables whose own value the error may quote; their
    values are scrubbed whatever their names say, because a credential pasted
    into the wrong variable is exactly the value that fails to parse.
    """

    result = text
    # Longest first, so a secret that contains another is not half-replaced.
    for name, value in sorted(os.environ.items(), key=lambda item: -len(item[1])):
        if not value:
            continue
        if _is_sensitive_name(name) or name in failing_names:
            result = result.replace(value, REDACTED)
            continue
        # A whole URL value is scrubbed as one piece before the text-level pass
        # below, which would stop at whitespace inside a password.
        redacted = _redact_url(value)
        if redacted != value:
            result = result.replace(value, redacted)
    return _redact_urls_in_text(result)


def _failing_environment_names(exc: BaseException, path: Path = SETTINGS_SOURCE) -> list[str]:
    """Return the ``OCTO_*`` literals inside the ``api.settings`` expression that raised.

    Numeric settings are read inline, as ``int(os.environ.get("OCTO_X", "5"))``,
    so ``int()``'s error names the value and not the variable. The traceback's
    column span of the failing call does contain the variable's name, and it
    is read back from the same AST ``settings_environment_names`` walks. An
    error raised anywhere else, or on a Python without column positions,
    yields no names and the message alone has to do.
    """

    resolved = path.resolve()
    frames = [
        frame
        for frame in traceback.extract_tb(exc.__traceback__)
        if Path(frame.filename).resolve() == resolved
    ]
    if not frames:
        return []
    frame = frames[-1]
    start_col = getattr(frame, "colno", None)
    end_line = getattr(frame, "end_lineno", None)
    end_col = getattr(frame, "end_colno", None)
    if frame.lineno is None or start_col is None or end_line is None or end_col is None:
        return []
    start = (frame.lineno, start_col)
    end = (end_line, end_col)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return sorted(
        {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and ENVIRONMENT_NAME_RE.fullmatch(node.value)
            and start <= (node.lineno, node.col_offset)
            and (node.end_lineno, node.end_col_offset) <= end
        }
    )


def _describe_invalid_value(exc: BaseException) -> str:
    """Render a loader error with the failing variable named and no raw value."""

    names = _failing_environment_names(exc)
    message = str(exc)
    conversion = _CONVERSION_ERROR_RE.match(message)
    if conversion is not None:
        # Whichever variable it came from, the literal after the colon is the
        # raw environment value; nothing after it is worth the risk. With it
        # gone, scrubbing the failing value again would only mangle the prose
        # around it when the value is short.
        message = _redact_exception_text(f"{conversion.group(1)}{REDACTED}")
    else:
        message = _redact_exception_text(message, failing_names=names)
    label = type(exc).__name__
    if names:
        label = f"{label} in {', '.join(names)}"
    return f"{label}: {message}" if message else label


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
        # Python's conversion errors quote the rejected value, which came from
        # the environment and may itself be sensitive. The operator gets the
        # variable's name and the loader's own message instead, both scrubbed.
        print("configuration: INVALID", file=sys.stderr)
        print(_describe_invalid_value(exc), file=sys.stderr)
        return 1

    print("configuration: OK")
    if not args.no_effective_config:
        print(json.dumps(redacted_settings(settings), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - direct helper invocation
    raise SystemExit(main())
