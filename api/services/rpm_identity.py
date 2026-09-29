"""Conservative RPM identity rules shared by inventory and advisory import.

Release bindings are explicit. A RHEL minor release is not silently redirected
onto the newest minor/EUS product, nor is a derivative treated as Red Hat.
"""
from __future__ import annotations

import re

from api.services import version_compare

RPM_DISTROS = ("rhel", "sles", "amazonlinux")
RPM_ARCHES = frozenset({
    "x86_64", "aarch64", "i386", "i486", "i586", "i686", "ppc64", "ppc64le",
    "s390", "s390x", "armv6hl", "armv7hl", "riscv64", "noarch",
})
_ARCH_ALIASES = {"amd64": "x86_64", "arm64": "aarch64"}
_EVR = re.compile(r"(?:[0-9]{1,10}:)?[A-Za-z0-9][A-Za-z0-9.+_~^]*-[A-Za-z0-9][A-Za-z0-9.+_~^]*\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._-]{0,254}\Z")


def architecture(value: str | None) -> str | None:
    arch = (value or "").strip().lower()
    arch = _ARCH_ALIASES.get(arch, arch)
    return arch if arch in RPM_ARCHES else None


def valid_name(value: str) -> bool:
    return bool(_NAME.fullmatch(value))


def valid_evr(value: str) -> bool:
    """Require the full binary RPM EVR, not an upstream or NEVRA string."""
    return (
        len(value) <= 256 and bool(_EVR.fullmatch(value))
        and value.rsplit(".", 1)[-1] not in RPM_ARCHES | {"src", "nosrc"}
    )


def canonical_evr(value: str) -> str:
    if not isinstance(value, str) or not valid_evr(value):
        raise ValueError("expected a complete RPM [epoch:]version-release")
    return str(version_compare.parse_evr(value, flavor=version_compare.RPM))


def release_id(distro: str, value: str, name: str = "") -> str | None:
    """Keep RHEL minor and SLES service pack; ALAS uses the OS major series."""
    value = value.strip().lower()
    if distro == "amazonlinux":
        found = re.match(r"^(2|2023)(?:[.\s(]|$)", value)
        return found[1] if found else None
    if distro == "rhel":
        found = re.match(r"^(7|8|9|10)(?:\.([0-9]{1,2}))?(?:\s|\(|$)", value)
        if found:
            return f"{found[1]}.{int(found[2])}" if found[2] else found[1]
        return None
    if distro == "sles":
        parsed = re.fullmatch(r"(12|15|16)(?:\.|[\s-]+sp)([0-9]{1,2})(?:\s.*)?", value)
        if parsed:
            return f"{parsed[1]}.{int(parsed[2])}"
        # The collector may put the SP in PRETTY_NAME and only the major in
        # VERSION_ID. Do not override a conflicting/malformed VERSION_ID.
        major = value if value in ("12", "15", "16") else None
        named = re.search(r"\b(12|15|16)\s+sp([0-9]{1,2})\b", name.lower())
        if major and named and named[1] == major:
            return f"{major}.{int(named[2])}"
        return "16" if value == "16" and not named else None
    return None


def distro_id(name: str) -> str | None:
    name = name.strip().lower()
    if re.fullmatch(r"(?:red hat enterprise linux(?: server| workstation| client)?|rhel)(?:\s+[0-9].*)?", name):
        return "rhel"
    if re.fullmatch(r"(?:suse linux enterprise server|sles)(?:\s+[0-9].*)?", name):
        return "sles"
    if re.fullmatch(r"(?:amazon linux|amzn)(?:\s+(?:2|2023))?", name):
        return "amazonlinux"
    return None
