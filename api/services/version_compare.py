"""Distribution package version comparison (dpkg and rpm EVR).

The whole point of matching endpoint software against *vendor* advisories
rather than upstream CVE ranges (ROADMAP Track E, docs/software-cve-matching.md)
is that a distribution's fixed version is expressed in the distribution's own
version grammar. ``1.1.1f-1ubuntu2.16`` is not a semantic version and it is not
comparable with anything but dpkg's rules: it is upstream ``1.1.1f`` — which
every naive matcher will call vulnerable forever — carrying a backported fix in
its revision. Getting the comparison wrong in either direction is worse than
not answering at all, so both algorithms here are transcriptions of the
canonical C implementations rather than approximations:

* :func:`compare_dpkg_version` follows ``verrevcmp``/``dpkg_version_compare``
  from dpkg's ``lib/dpkg/version.c``;
* :func:`compare_rpm_version` follows ``rpmvercmp`` from rpm's
  ``lib/rpmvercmp.c``, including the ``~`` (pre-release) and ``^``
  (post-release) separators.

No third-party dependency: ``python-apt``/``rpm`` are C extensions that are not
installable in the API image, and the algorithms are forty lines each. They are
tested against a large table of known-tricky pairs in
``tests/test_version_compare.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Package version grammars this module understands.
DEB = "deb"
RPM = "rpm"
FLAVORS = (DEB, RPM)


class VersionParseError(ValueError):
    """A version string is not a well-formed EVR for its flavor.

    Raised rather than guessed at: an unparsable version means the endpoint's
    package cannot be compared with an advisory's fixed version, which the
    matcher must report as ``unknown``, never as ``fixed``.
    """


@dataclass(frozen=True)
class Evr:
    """A parsed epoch:version-release triple.

    ``epoch`` defaults to 0 exactly as both package managers do, so
    ``1.2.3-1`` and ``0:1.2.3-1`` are the same version.
    """

    epoch: int
    version: str
    release: str
    flavor: str

    def __str__(self) -> str:
        head = f"{self.epoch}:{self.version}" if self.epoch else self.version
        return f"{head}-{self.release}" if self.release else head


def _split_epoch(raw: str) -> tuple[int, str]:
    """``1:2.3`` → ``(1, "2.3")``. A colon whose prefix is not a number is part
    of the version, which is legal in rpm and what dpkg reports as an error."""
    head, sep, tail = raw.partition(":")
    if not sep:
        return 0, raw
    if head.isdigit():
        return int(head), tail
    return 0, raw


def parse_evr(raw: str, *, flavor: str = DEB) -> Evr:
    """Parse ``[epoch:]version[-release]``.

    The release is split on the **last** hyphen: a dpkg upstream version may
    itself contain hyphens (``1.2-beta-3-1`` is upstream ``1.2-beta-3``,
    revision ``1``), and taking the first hyphen would silently compare the
    wrong halves.
    """
    if flavor not in FLAVORS:
        raise VersionParseError(f"unknown version flavor: {flavor!r}")
    text = (raw or "").strip()
    if not text:
        raise VersionParseError("empty version string")
    epoch, rest = _split_epoch(text)
    if not rest:
        raise VersionParseError(f"version {raw!r} has an epoch but no version")
    version, sep, release = rest.rpartition("-")
    if not sep:
        version, release = rest, ""
    if not version:
        raise VersionParseError(f"version {raw!r} has an empty upstream part")
    return Evr(epoch=epoch, version=version, release=release, flavor=flavor)


# --------------------------------------------------------------------------
# dpkg
# --------------------------------------------------------------------------


def _is_alnum(char: str) -> bool:
    # Deliberately ASCII-only, like rpm's ``risalnum``: Python's ``str.isalnum``
    # is true for e.g. "²" and for non-Latin letters, which would make two
    # versions compare differently here than they do on the box the package
    # came from.
    return ("0" <= char <= "9") or ("a" <= char <= "z") or ("A" <= char <= "Z")


def _is_digit(char: str) -> bool:
    return "0" <= char <= "9"


def _is_alpha(char: str) -> bool:
    return ("a" <= char <= "z") or ("A" <= char <= "Z")


def _dpkg_order(char: str) -> int:
    """dpkg's ``order()``: ``~`` sorts before everything including the empty
    string, digits are handled by the caller, letters sort before every other
    non-digit character."""
    if _is_digit(char):
        return 0
    if _is_alpha(char):
        return ord(char)
    if char == "~":
        return -1
    if char:
        return ord(char) + 256
    return 0


def _dpkg_verrevcmp(left: str, right: str) -> int:
    """dpkg's ``verrevcmp``, applied to one component (upstream or revision)."""
    a, b = left or "", right or ""
    i = j = 0
    len_a, len_b = len(a), len(b)
    while i < len_a or j < len_b:
        first_diff = 0
        while (i < len_a and not _is_digit(a[i])) or (j < len_b and not _is_digit(b[j])):
            ac = _dpkg_order(a[i]) if i < len_a else 0
            bc = _dpkg_order(b[j]) if j < len_b else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len_a and a[i] == "0":
            i += 1
        while j < len_b and b[j] == "0":
            j += 1
        while i < len_a and j < len_b and _is_digit(a[i]) and _is_digit(b[j]):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len_a and _is_digit(a[i]):
            return 1
        if j < len_b and _is_digit(b[j]):
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def compare_dpkg_version(left: str, right: str) -> int:
    """Compare two Debian/Ubuntu versions. ``-1``/``0``/``1`` like ``cmp``."""
    a = parse_evr(left, flavor=DEB)
    b = parse_evr(right, flavor=DEB)
    if a.epoch != b.epoch:
        return -1 if a.epoch < b.epoch else 1
    result = _dpkg_verrevcmp(a.version, b.version)
    if result:
        return result
    return _dpkg_verrevcmp(a.release, b.release)


# --------------------------------------------------------------------------
# rpm
# --------------------------------------------------------------------------


def rpmvercmp(left: str, right: str) -> int:  # noqa: C901 - transcription of rpmvercmp.c
    """rpm's ``rpmvercmp``, applied to one component.

    Structure follows the C original statement for statement so it can be
    diffed against it; ``~`` sorts before everything (so ``1.0~rc1`` < ``1.0``)
    and ``^`` sorts after a bare base version (so ``1.0`` < ``1.0^20240101git``).
    """
    a, b = left or "", right or ""
    if a == b:
        return 0
    i = j = 0
    len_a, len_b = len(a), len(b)

    while i < len_a or j < len_b:
        while i < len_a and not _is_alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len_b and not _is_alnum(b[j]) and b[j] not in "~^":
            j += 1

        a_char = a[i] if i < len_a else ""
        b_char = b[j] if j < len_b else ""

        # ``~`` sorts before everything else, including the end of the string.
        if a_char == "~" or b_char == "~":
            if a_char != "~":
                return 1
            if b_char != "~":
                return -1
            i += 1
            j += 1
            continue

        # ``^`` is the mirror image: like ``~``, except that a string that has
        # *ended* is the lower one (a base version precedes its snapshots).
        if a_char == "^" or b_char == "^":
            if not a_char:
                return -1
            if not b_char:
                return 1
            if a_char != "^":
                return 1
            if b_char != "^":
                return -1
            i += 1
            j += 1
            continue

        if not (a_char and b_char):
            break

        start_a, start_b = i, j
        if _is_digit(a[i]):
            while i < len_a and _is_digit(a[i]):
                i += 1
            while j < len_b and _is_digit(b[j]):
                j += 1
            isnum = True
        else:
            while i < len_a and _is_alpha(a[i]):
                i += 1
            while j < len_b and _is_alpha(b[j]):
                j += 1
            isnum = False

        seg_a = a[start_a:i]
        seg_b = b[start_b:j]

        # One side had a numeric segment where the other had an alphabetic one:
        # numbers are always newer than letters.
        if not seg_b:
            return 1 if isnum else -1

        if isnum:
            seg_a = seg_a.lstrip("0")
            seg_b = seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1

        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1

    if i >= len_a and j >= len_b:
        return 0
    return -1 if i >= len_a else 1


def compare_rpm_version(left: str, right: str) -> int:
    """Compare two rpm EVRs. ``-1``/``0``/``1`` like ``cmp``."""
    a = parse_evr(left, flavor=RPM)
    b = parse_evr(right, flavor=RPM)
    if a.epoch != b.epoch:
        return -1 if a.epoch < b.epoch else 1
    result = rpmvercmp(a.version, b.version)
    if result:
        return result
    return rpmvercmp(a.release, b.release)


def compare(left: str, right: str, *, flavor: str) -> int:
    """Compare two versions in ``flavor``'s grammar (``deb`` or ``rpm``)."""
    if flavor == DEB:
        return compare_dpkg_version(left, right)
    if flavor == RPM:
        return compare_rpm_version(left, right)
    raise VersionParseError(f"unknown version flavor: {flavor!r}")


def is_fixed(installed: str, fixed: str, *, flavor: str) -> bool:
    """True when ``installed`` already carries the advisory's fix.

    ``>=`` rather than ``>``: the fixed version itself is the fixed version.
    """
    return compare(installed, fixed, flavor=flavor) >= 0
