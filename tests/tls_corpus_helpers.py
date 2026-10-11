"""Shared readers for the recorded Nmap ``ssl-enum-ciphers`` output in the corpus.

The corpus (``tests/fixtures/nmap_pulse_corpus``) was recorded against a compose
stand; its Nmap XML is the only oracle the A-F grader is checked against. The
parsing here is deliberately its own small regex pass and does not call the
product parser, so a bug in one cannot hide a bug in the other.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import defusedxml.ElementTree as DET

CORPUS = Path(__file__).parent / "fixtures" / "nmap_pulse_corpus"

_VERSION = re.compile(r"^\s{2}(TLSv1\.[0-3]|SSLv3):\s*$")
_SUITE = re.compile(r"^\s{6}(TLS_\S+)\s+\(([^)]*)\)\s+-\s+([A-F])\s*$")


def kex_from_nmap_detail(detail: str) -> dict[str, Any]:
    """``rsa 2048`` / ``dh 2048`` -> bits; ``ecdh_x25519`` / ``secp256r1`` -> group."""
    d = detail.strip()
    m = re.match(r"^(rsa|dh|dsa)\s+(\d+)$", d)
    if m:
        return {"kex_bits": int(m.group(2))}
    return {"kex_group": d}


def nmap_enum_points() -> dict[tuple[str, str], list[dict[str, Any]]]:
    """(ip, port) -> [{version, server_preference, suites:[(name, detail, letter)]}]."""
    points: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for xml in sorted((CORPUS / "nmap").glob("*.xml")):
        root = DET.fromstring(xml.read_text(encoding="utf-8"))
        for host in root.findall("host"):
            addr = host.find("address").attrib["addr"]
            for port in host.findall("./ports/port"):
                for script in port.findall("script"):
                    if script.attrib.get("id") != "ssl-enum-ciphers":
                        continue
                    versions: list[dict[str, Any]] = []
                    for line in script.attrib["output"].splitlines():
                        vm = _VERSION.match(line)
                        if vm:
                            versions.append({"version": vm.group(1), "server_preference": None, "suites": []})
                            continue
                        sm = _SUITE.match(line)
                        if sm and versions:
                            versions[-1]["suites"].append((sm.group(1), sm.group(2), sm.group(3)))
                        elif "cipher preference: server" in line and versions:
                            versions[-1]["server_preference"] = True
                    points[(addr, port.attrib["portid"])] = versions
    return points


def nmap_suites() -> list[tuple[str, str, str, str, str]]:
    """Every recorded suite line: (ip, port, version, name, detail, letter) flattened."""
    out = []
    for (ip, port), versions in nmap_enum_points().items():
        for v in versions:
            for name, detail, letter in v["suites"]:
                out.append((ip, port, v["version"], name, detail, letter))
    return out  # type: ignore[return-value]


def synthetic_gendec34_row(ip: str, port: str, versions: list[dict[str, Any]], *, complete: bool = True) -> dict[str, Any]:
    """A ``tls[]`` row in the shape expected from GenDec#34, built from recorded Nmap output.

    SYNTHETIC: no engine emits this yet. Suites are named as Nmap names them
    (``TLS_AKE_WITH_*`` for TLS 1.3) on purpose -- the reader must cope.
    """
    return {
        "ip": ip,
        "host": ip,
        "port": int(port),
        "negotiated_protocol": "TLSv1_2",
        "enumeration": {
            "complete": complete,
            "versions": [
                {
                    "version": v["version"],
                    "accepted": True,
                    **({"server_preference": v["server_preference"]} if v["server_preference"] is not None else {}),
                    "ciphers": [
                        {"name": name, **kex_from_nmap_detail(detail)} for name, detail, _letter in v["suites"]
                    ],
                }
                for v in versions
            ],
        },
    }
