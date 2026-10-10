"""Read the cipher-suite enumeration of a Pulse ``tls[]`` row.

EXPECTED SHAPE -- GenDec#34 (onixus/GenDec#34, opt-in suite enumeration). Pulse
v1.3.0 does not emit it yet; this is the form Shapoclyack proposes and parses,
and nothing here is evidence that an engine produces it::

    "enumeration": {
      "complete": true,
      "versions": [
        {"version": "TLSv1.2", "accepted": true, "server_preference": true,
         "ciphers": [{"code": "0xC02F", "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                      "kex_group": "x25519", "kex_bits": 253}]},
        {"version": "SSLv3", "accepted": false}
      ]
    }

The reader is lenient, because the producer is not ours: a version label may be
``TLSv1_2`` / ``TLSv1.2`` / ``TLS 1.2`` / ``0x0303`` / ``771`` / ``SSLv2``; a
suite may be a bare string or an object; ``code`` may be an int or a hex string;
a suite with a code and no name is named from the IANA registry. Anything it
cannot read is skipped, never raised. ``complete`` must be exactly ``true`` to
count as a finished enumeration; a suite missing from the list is never read
as "not accepted".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from .tls_grading import grade_cipher_suite, normalize_suite_name, worst_grade

_IANA_TABLE = Path(__file__).parent / "pulse_data" / "tls_cipher_suites.tsv"

# wire value (ProtocolVersion) -> label; 0x0200 is how SSLv2 is sometimes written
_WIRE_VERSIONS = {0x0200: "SSLv2", 0x0002: "SSLv2", 0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1",
                  0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}
_VERSION_RE = re.compile(r"^(ssl|tls)v?(\d)(?:[._]?(\d))?$")
_HEX_RE = re.compile(r"^(?:0x)?([0-9a-f]{1,4})$")
_HEX_PAIR_RE = re.compile(r"^0x([0-9a-f]{2})[, ]+0x([0-9a-f]{2})$")
_SUITE_NAME_RE = re.compile(r"^(?:TLS|SSL)_[A-Za-z0-9_]+$")


@lru_cache(maxsize=1)
def iana_cipher_names() -> dict[int, str]:
    """Code point -> IANA name; empty if the table is unreadable (names then stay unknown)."""
    names: dict[int, str] = {}
    try:
        text = _IANA_TABLE.read_text(encoding="utf-8")
    except OSError:
        return names
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        code, _, name = line.partition("\t")
        try:
            names[int(code, 16)] = name.strip()
        except ValueError:
            continue
    return names


def normalize_version(raw: Any) -> str | None:
    """Canonical ``SSLv2``/``SSLv3``/``TLSv1.0``..``TLSv1.3`` for any spelling, else ``None``."""
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, int):
        return _WIRE_VERSIONS.get(raw)
    if not isinstance(raw, str):
        return None
    low = re.sub(r"[\s-]", "", raw.lower())
    if low.startswith("0x"):
        try:
            return _WIRE_VERSIONS.get(int(low, 16))
        except ValueError:
            return None
    m = _VERSION_RE.match(low)
    if not m:
        return None
    family, major, minor = m.group(1), int(m.group(2)), m.group(3)
    if family == "ssl":
        return {2: "SSLv2", 3: "SSLv3"}.get(major) if minor in (None, "0") else None
    if major != 1:
        return None
    minor_i = 0 if minor is None else int(minor)
    return f"TLSv1.{minor_i}" if minor_i <= 3 else None


def _parse_code(raw: Any) -> int | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if 0 <= raw <= 0xFFFF else None
    if not isinstance(raw, str):
        return None
    s = raw.strip().lower()
    pair = _HEX_PAIR_RE.match(s)
    if pair:
        return int(pair.group(1) + pair.group(2), 16)
    m = _HEX_RE.match(s)
    return int(m.group(1), 16) if m else None


def _int_or_none(raw: Any) -> int | None:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    return int(raw) if raw > 0 else None


def parse_suite(raw: Any) -> dict[str, Any] | None:
    """``{name, grade, code?}`` for one suite entry; ``None`` when nothing usable is there."""
    code: int | None = None
    name = ""
    kex_group: str | None = None
    kex_bits: int | None = None
    if isinstance(raw, str):
        text = raw.strip()
        if _SUITE_NAME_RE.match(text):
            name = text
        else:
            code = _parse_code(text)
    elif isinstance(raw, dict):
        code = _parse_code(raw.get("code"))
        if isinstance(raw.get("name"), str):
            name = raw["name"].strip()
        if isinstance(raw.get("kex_group"), str):
            kex_group = raw["kex_group"]
        kex_bits = _int_or_none(raw.get("kex_bits"))
    else:
        return None
    if not name and code is not None:
        name = iana_cipher_names().get(code, "")
    if not name or not _SUITE_NAME_RE.match(name):
        return None
    name = normalize_suite_name(name)
    return {"name": name, "grade": grade_cipher_suite(name, kex_bits=kex_bits, kex_group=kex_group)}


@dataclass
class Enumeration:
    complete: bool
    versions: list[dict[str, Any]] = field(default_factory=list)


def parse_enumeration(row: dict[str, Any]) -> Enumeration | None:
    """``cipher_versions``-shaped list from ``row["enumeration"]``; ``None`` when absent or unusable.

    Only versions the engine reports as accepted (``accepted: true``, or a
    non-empty suite list with no ``accepted`` key) are returned. ``accepted:
    false`` and a version with neither flag nor suites yield nothing.
    """
    block = row.get("enumeration")
    if not isinstance(block, dict) or not isinstance(block.get("versions"), list):
        return None
    versions: dict[str, dict[str, Any]] = {}
    for entry in block["versions"]:
        if not isinstance(entry, dict):
            continue
        label = normalize_version(entry.get("version"))
        if label is None:
            continue
        suites_raw = entry.get("ciphers")
        suites = [s for s in map(parse_suite, suites_raw) if s] if isinstance(suites_raw, list) else []
        accepted = entry.get("accepted")
        if accepted is False or not (accepted is True or suites):
            continue
        slot = versions.setdefault(label, {"version": label, "ciphers": [], "least_strength": None})
        seen = {c["name"] for c in slot["ciphers"]}
        slot["ciphers"].extend(s for s in suites if s["name"] not in seen)
        if isinstance(entry.get("server_preference"), bool):
            slot["server_preference"] = entry["server_preference"]
    for slot in versions.values():
        slot["least_strength"] = worst_grade([c["grade"] for c in slot["ciphers"]])
    if not versions:
        return None
    return Enumeration(complete=block.get("complete") is True, versions=list(versions.values()))
