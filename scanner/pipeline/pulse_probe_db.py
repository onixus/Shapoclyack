"""Validation of the service-probe database handed to Pulse with ``--probe-db``.

Pulse (GenDec ``src/scanner/probe_db.rs``) replaces its embedded set with the
file wholesale, and on *any* read, parse or regex error only prints
``probe-db <path>: ... -- using the embedded set`` to stderr and carries on. A
bad edit of our database would therefore silently turn into "the stock rules
ran", so the adapter validates the file itself and refuses to pass a file
Pulse would reject.

Pulse compiles patterns with the Rust ``regex`` crate (1.x, default size
limit), Python checks with ``re``, and the two dialects differ in both
directions. The rule is therefore **"patterns must be in the common subset"**,
not "everything Rust accepts": a pattern is passed only if Python compiles it
and it uses nothing outside the subset below. Constructs that are Python-only
(look-around, back-references, ``\\Z``, ``(?#...)``, ``(?(1)..)``, possessive
quantifiers, flags other than ``i``/``m``/``s``) or Rust-only (``\\pL``,
``\\x{41}``, ``(?U)``, mid-pattern flags, nested or ``&&``/``--``/``~~`` classes,
``\\z`` which Python 3.14 accepts and 3.12 does not) are rejected, so the result
does not depend on the interpreter. A pattern whose estimated compiled size
exceeds :data:`MAX_PATTERN_COST` is rejected too: Rust refuses programs over
its size limit (``\\w{300}``), which Python happily compiles. The subset and the
cost budget were checked against a real ``regex`` 1.13.1 compile of every
pattern in the shipped database and a battery of edge cases
(``tests/test_pulse_probe_db.py``).
"""

from __future__ import annotations

import hashlib
import json
import re
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Text Pulse prints on stderr when it dropped ``--probe-db`` for its embedded set.
FALLBACK_MARKER = "using the embedded set"

#: Rust's ``char::is_whitespace``, which ``decode_hex`` strips before reading digits.
_RUST_SPACE = "\t\n\x0b\x0c\r \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000"
_STRIP_SPACE = re.compile(f"[{_RUST_SPACE}]")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2})*")

#: Estimated compiled size a single pattern may reach, in "instructions" where a
#: literal is 1 and a Unicode class (``\w``, ``\d``, ``\s``, a negated class) is
#: 10. Measured against regex 1.13.1: ``\w{200}`` (2000) compiles, ``\w{300}``
#: (3000) and ``(\w{1,50}){1,5}`` (2500) do not. The budget is half of what was
#: seen to compile, and the largest shipped pattern is far below it.
MAX_PATTERN_COST = 1000
_HEAVY = 10

_SIMPLE_ESCAPES = frozenset("dDsSwWnrtfvabB")
_CLASS_ESCAPES = frozenset("dDsSwWnrtfv")
_FLAGS = "ims"
_SCOPED_FLAGS = re.compile(rf"[{_FLAGS}]*(?:-[{_FLAGS}]+)?:")
_NAMED_GROUP = re.compile(r"P<[A-Za-z_][A-Za-z0-9_]*>")
_COUNT = re.compile(r"\{(\d+)(?:(,)(\d*))?\}")


class ProbeDbError(ValueError):
    """The probe database is unusable; the message says why."""


@dataclass(frozen=True)
class ProbeDbInfo:
    path: str
    version: str
    sha256: str
    probes: int
    matches: int


def analyze(pattern: str) -> tuple[str | None, int]:
    r"""Scan ``pattern`` once: (first construct outside the common subset, estimated size).

    The size counts a literal as 1, a Unicode class (``\w``, ``\d``, ``\s``, a
    negated class) as :data:`_HEAVY`, multiplies by counted repetitions
    (``{n,m}`` costs ``m`` copies, ``+`` two) and nests through groups, so
    ``(\w{1,50}){1,5}`` is 2500, which is what blows Rust's size limit.
    """
    n = len(pattern)
    i = 0
    leading = True  # bare flag groups such as (?i) may only open the pattern
    # One frame per open group: [cost of finished alternatives, cost of this one, last atom]
    stack: list[list[int]] = [[0, 0, 0]]
    while i < n:
        c = pattern[i]
        frame = stack[-1]
        atom: int | None = None
        if c == "\\":
            bad, nxt = _escape(pattern, i, in_class=False)
            if bad:
                return bad, 0
            atom = _HEAVY if pattern[i + 1] in "dDsSwW" else 1
            i = nxt
        elif c == "[":
            bad, nxt = _char_class(pattern, i)
            if bad:
                return bad, 0
            body = pattern[i:nxt]
            atom = _HEAVY if body.startswith("[^") or re.search(r"\\[dDsSwW]", body) else 1
            i = nxt
        elif c == "(":
            leading_flags = re.match(rf"\(\?[{_FLAGS}]+\)", pattern[i:])
            if leading_flags and leading:
                i += leading_flags.end()
                continue
            if pattern.startswith("(?", i):
                rest = pattern[i + 2 :]
                named = _NAMED_GROUP.match(rest)
                scoped = _SCOPED_FLAGS.match(rest)
                if rest.startswith(":"):
                    i += 3
                elif named:
                    i += 2 + named.end()
                elif scoped:
                    i += 2 + scoped.end()
                else:
                    return f"group construct {pattern[i : i + 4]!r}", 0
            else:
                i += 1
            stack.append([0, 0, 0])
            leading = False
            continue
        elif c == ")":
            if len(stack) == 1:
                return None, 0  # unbalanced: re.compile reports it
            done = stack.pop()
            frame = stack[-1]
            atom = done[0] + done[1]
            i += 1
        elif c == "|":
            frame[0] += frame[1]
            frame[1] = frame[2] = 0
            i += 1
            leading = False
            continue
        elif c in "*+?{":
            if c == "{":
                m = _COUNT.match(pattern, i)
                if not m:
                    return "'{' that is not a counted repetition", 0
                low, comma, high = int(m.group(1)), m.group(2), m.group(3)
                factor = max(int(high), 1) if high else (low + 1 if comma else max(low, 1))
                i = m.end()
            else:
                factor = 2 if c == "+" else 1
                i += 1
            if pattern.startswith("+", i):
                return "possessive quantifier", 0
            if pattern.startswith("?", i):
                i += 1  # lazy: the same in both
            frame[1] += frame[2] * (factor - 1)
            frame[2] *= factor
            leading = False
            continue
        else:
            atom = 1
            i += 1
        leading = False
        frame[1] += atom
        frame[2] = atom
    return None, stack[0][0] + stack[0][1]


def subset_violation(pattern: str) -> str | None:
    """Name the first construct in ``pattern`` outside the Python/Rust common subset."""
    return analyze(pattern)[0]


def pattern_cost(pattern: str) -> int:
    """Estimated compiled size of ``pattern`` (see :func:`analyze`)."""
    return analyze(pattern)[1]


def _escape(pattern: str, i: int, *, in_class: bool) -> tuple[str | None, int]:
    """Check the escape at ``pattern[i]`` (a backslash); return (violation, next index)."""
    if i + 1 >= len(pattern):
        return "trailing backslash", i + 1
    ch = pattern[i + 1]
    if ch == "x":
        if re.fullmatch(r"[0-9a-fA-F]{2}", pattern[i + 2 : i + 4]):
            return None, i + 4
        return "\\x that is not followed by two hex digits", i + 2
    if ch in (_CLASS_ESCAPES if in_class else _SIMPLE_ESCAPES | {"A"}):
        return None, i + 2
    if ch.isascii() and not ch.isalnum():
        return None, i + 2  # an escaped punctuation mark or space: a literal in both
    if ch.isdigit():
        return f"back-reference or octal escape \\{ch}", i + 2
    return f"escape \\{ch}", i + 2


def _char_class(pattern: str, i: int) -> tuple[str | None, int]:
    """Check the bracketed class starting at ``pattern[i]``; return (violation, next index)."""
    n = len(pattern)
    j = i + 1
    if pattern.startswith("^", j):
        j += 1
    if pattern.startswith("]", j):
        j += 1  # a leading ']' is a literal in both
    while j < n:
        c = pattern[j]
        if c == "\\":
            bad, j = _escape(pattern, j, in_class=True)
            if bad:
                return bad, j
            continue
        if c == "]":
            return None, j + 1
        if c == "[":
            return "nested or POSIX class inside [...]", j
        if pattern[j : j + 2] in ("&&", "--", "~~", "||"):
            return f"class set operator {pattern[j : j + 2]!r}", j
        j += 1
    return None, j  # unterminated: re.compile reports it


def validate_probe_db_text(text: str) -> tuple[str, int, int]:
    """Check ``text`` the way Pulse will load it; return (version, probes, matches)."""
    def reject_constant(name: str) -> Any:
        raise ProbeDbError(f"not valid JSON: {name} is not a JSON number")

    try:
        doc = json.loads(text, parse_constant=reject_constant)
        # serde_json refuses a lone surrogate escape (\ud800); Python keeps it
        # in the str and only fails when the string is encoded.
        json.dumps(doc, ensure_ascii=False).encode("utf-8")
    except json.JSONDecodeError as exc:
        raise ProbeDbError(f"not valid JSON: {exc}") from exc
    except UnicodeEncodeError as exc:
        raise ProbeDbError("not valid JSON: a string holds a lone surrogate") from exc
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
        if not _HEX.fullmatch(_STRIP_SPACE.sub("", hex_payload)):
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
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", FutureWarning)  # "possible set difference": rejected below
                    re.compile(pattern)
            except re.error as exc:
                raise ProbeDbError(f"probe {name}: bad pattern {pattern!r}: {exc}") from exc
            bad, cost = analyze(pattern)
            if bad:
                raise ProbeDbError(
                    f"probe {name}: pattern {pattern!r} uses {bad}, outside the subset Python and "
                    "Pulse's regex engine both accept"
                )
            if cost > MAX_PATTERN_COST:
                raise ProbeDbError(
                    f"probe {name}: pattern {pattern!r} is too large (estimated {cost} > {MAX_PATTERN_COST}); "
                    "Pulse's regex engine would refuse to compile it"
                )
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
