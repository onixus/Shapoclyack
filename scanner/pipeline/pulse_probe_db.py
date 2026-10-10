"""Validation of the service-probe database handed to Pulse with ``--probe-db``.

Pulse (GenDec ``src/scanner/probe_db.rs``) replaces its embedded set with the
file wholesale, and on *any* read, parse or regex error only prints
``probe-db <path>: ... -- using the embedded set`` to stderr and carries on. A
bad edit of our database would therefore silently turn into "the stock rules
ran", so the adapter validates the file itself and refuses to pass a file
Pulse would reject.

Pulse compiles patterns with the Rust ``regex`` crate; Python's ``re`` is a
superset in the ways that matter here (look-around, back-references), so
compiling in ``re`` is necessary but not sufficient: those constructs are
rejected explicitly.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Text Pulse prints on stderr when it dropped ``--probe-db`` for its embedded set.
FALLBACK_MARKER = "using the embedded set"

_HEX = re.compile(r"(?:[0-9a-fA-F]{2})*")
# Group openers the Rust ``regex`` crate has no support for.
_RUST_UNSUPPORTED_GROUPS = ("(?=", "(?!", "(?<=", "(?<!", "(?>", "(?P=")


class ProbeDbError(ValueError):
    """The probe database is unusable; the message says why."""


@dataclass(frozen=True)
class ProbeDbInfo:
    path: str
    version: str
    sha256: str
    probes: int
    matches: int


def rust_incompatibility(pattern: str) -> str | None:
    """Name the first construct in ``pattern`` that Rust's ``regex`` rejects."""
    i, n, in_class = 0, len(pattern), False
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n:
            nxt = pattern[i + 1]
            if nxt.isdigit() and nxt != "0" or nxt == "k":
                return f"back-reference \\{nxt}"
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
            # ``[]abc]`` / ``[^]abc]``: a leading ']' is literal.
            if pattern.startswith("^]", i + 1):
                i += 2
            elif pattern.startswith("]", i + 1):
                i += 1
        elif c == "(":
            for opener in _RUST_UNSUPPORTED_GROUPS:
                if pattern.startswith(opener, i):
                    return f"unsupported group {opener}"
        i += 1
    return None


def validate_probe_db_text(text: str) -> tuple[str, int, int]:
    """Check ``text`` the way Pulse will load it; return (version, probes, matches)."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProbeDbError(f"not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("probes"), list):
        raise ProbeDbError("top level must be an object with a 'probes' list")
    version = doc.get("version", "")
    if not isinstance(version, str):
        raise ProbeDbError("'version' must be a string")
    total = 0
    for probe in doc["probes"]:
        if not isinstance(probe, dict) or not isinstance(probe.get("name"), str):
            raise ProbeDbError("every probe needs a string 'name'")
        name = probe["name"]
        ports = probe.get("ports", [])
        if not isinstance(ports, list) or not all(
            isinstance(p, int) and not isinstance(p, bool) and 0 <= p <= 65535 for p in ports
        ):
            raise ProbeDbError(f"probe {name}: 'ports' must be a list of 0-65535 integers")
        rarity = probe.get("rarity", 5)
        if not isinstance(rarity, int) or isinstance(rarity, bool) or not 0 <= rarity <= 255:
            raise ProbeDbError(f"probe {name}: 'rarity' must be an integer 0-255")
        for key in ("payload", "payload_hex"):
            if not isinstance(probe.get(key, ""), str):
                raise ProbeDbError(f"probe {name}: '{key}' must be a string")
        hex_payload = probe.get("payload_hex", "")
        if not _HEX.fullmatch(hex_payload):
            raise ProbeDbError(f"probe {name}: invalid payload_hex")
        matches = probe.get("matches", [])
        if not isinstance(matches, list):
            raise ProbeDbError(f"probe {name}: 'matches' must be a list")
        for rule in matches:
            if not isinstance(rule, dict) or not isinstance(rule.get("pattern"), str):
                raise ProbeDbError(f"probe {name}: every match needs a string 'pattern'")
            for key in ("service", "product", "version"):
                if not isinstance(rule.get(key, ""), str):
                    raise ProbeDbError(f"probe {name}: match '{key}' must be a string")
            if not isinstance(rule.get("soft", False), bool):
                raise ProbeDbError(f"probe {name}: match 'soft' must be a boolean")
            pattern = rule["pattern"]
            bad = rust_incompatibility(pattern)
            if bad:
                raise ProbeDbError(f"probe {name}: pattern {pattern!r} uses {bad}, which Pulse's regex engine rejects")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ProbeDbError(f"probe {name}: bad pattern {pattern!r}: {exc}") from exc
            total += 1
    return version, len(doc["probes"]), total


def load_probe_db(path: Path) -> ProbeDbInfo:
    """Validate the file at ``path``; raise :class:`ProbeDbError` when Pulse would not take it."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ProbeDbError(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProbeDbError(f"not UTF-8: {exc}") from exc
    version, probes, matches = validate_probe_db_text(text)
    return ProbeDbInfo(str(path), version, hashlib.sha256(raw).hexdigest(), probes, matches)


def fallback_lines(stderr: str) -> list[str]:
    """Pulse's own ``probe-db ... using the embedded set`` lines found in ``stderr``."""
    return [
        line.strip()
        for line in (stderr or "").splitlines()
        if "probe-db" in line and FALLBACK_MARKER in line
    ]


def describe(info: ProbeDbInfo | None, reason: str | None) -> dict[str, Any]:
    """Run-metadata view: what ``--probe-db`` was, or why it was left off."""
    if info is None:
        return {"probe_db": None, "probe_db_version": None, "probe_db_sha256": None, "probe_db_skipped": reason}
    return {
        "probe_db": info.path,
        "probe_db_version": info.version,
        "probe_db_sha256": info.sha256,
        "probe_db_skipped": None,
    }
