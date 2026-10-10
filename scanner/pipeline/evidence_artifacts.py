"""Offline adapters for a shadow finding-evidence artifact (#449, first stage).

Only read existing run files. No binary execution, network, tracker mutations
or inference of negative evidence from absent/partial scanner output.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from itertools import islice
from pathlib import Path
from typing import Any

from defusedxml.ElementTree import ParseError, fromstring
from defusedxml.common import DefusedXmlException

from .finding_evidence import aggregate, observation

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_OBSERVATIONS = 10_000
MAX_NMAP_FILES = 128
_CVE = re.compile(r"\bCVE-\d{4}-\d{3,7}\b", re.IGNORECASE)
_KIND = {"version_cve": "version_match", "keyword_cve": "keyword_hypothesis",
         "exposure": "exposure", "tls": "tls_observation", "plugin_script": "plugin_report"}


class EvidenceReader:
    """Bounded reader with explicit diagnostics, not a scan coverage reporter."""

    def __init__(self, root: Path, tenant_id: str, run_id: str):
        self.root = root.resolve(strict=True)
        if (not self.root.is_dir() or not tenant_id or not run_id
                or len(tenant_id) > 128 or len(run_id) > 128
                or any(ord(c) < 32 for c in tenant_id + run_id)):
            raise ValueError("run directory and explicit tenant/run context required")
        self.tenant_id, self.run_id = tenant_id, run_id
        self.rows: list[dict[str, Any]] = []
        self.diagnostics: list[dict[str, str]] = []
        self.bytes_read = 0
        self.limited = False

    def note(self, path: str, code: str) -> None:
        # Error text/raw values could contain secrets. Publish fixed codes only.
        diagnostic = {"artifact": path, "code": code}
        if diagnostic not in self.diagnostics:
            self.diagnostics.append(diagnostic)

    def read(self, path: str) -> tuple[str, str] | None:
        target = self.root / path
        try:
            if target.is_symlink() or not target.resolve().is_relative_to(self.root):
                self.note(path, "unsafe_path")
                return None
            if not target.is_file():
                self.note(path, "missing")
                return None
            remaining = max(0, min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - self.bytes_read))
            if not remaining:
                self.note(path, "size_limit")
                self.limited = True
                return None
            with target.open("rb") as handle:
                data = handle.read(remaining + 1)
            self.bytes_read += len(data)
            if len(data) > remaining:
                self.note(path, "size_limit")
                self.limited = True
                return None
            return data.decode("utf-8"), hashlib.sha256(data).hexdigest()
        except (OSError, ValueError, UnicodeError, RuntimeError):
            self.note(path, "unreadable")
            return None

    def add(self, row: dict[str, Any], source: str, path: str, sha: str, locator: str) -> None:
        if len(self.rows) >= MAX_OBSERVATIONS:
            self.note(path, "observation_limit")
            self.limited = True
            return
        try:
            self.rows.append(observation(
                row, tenant_id=self.tenant_id, run_id=self.run_id, source=source,
                artifact_ref={"path": path, "sha256": sha, "locator": locator},
            ))
        except (ValueError, TypeError, OverflowError, UnicodeError):
            self.note(path, "invalid_observation")

    def pulse(self) -> None:
        path = "pulse/raw.json"
        loaded = self.read(path)
        if loaded is None:
            return
        text, sha = loaded
        try:
            raw = json.loads(text)
            if not isinstance(raw, dict):
                raise ValueError
            meta = raw.get("meta") if isinstance(raw.get("meta"), dict) else {}
            field = "findings" if raw.get("findings") else "cves"
            rows = raw.get(field, [])
            if not isinstance(rows, list):
                raise ValueError
            adapter = raw.get("adapter") if isinstance(raw.get("adapter"), dict) else {}
            receipt = adapter.get("plugins") if isinstance(adapter.get("plugins"), dict) else {}
            plugin_shas = {str(p.get("name")): str(p.get("sha256")) for p in receipt.get("loaded") or []
                           if isinstance(p, dict)}
            for index, row in enumerate(rows):
                if not isinstance(row, dict):
                    self.note(path, "invalid_row")
                    continue
                cls = str(row.get("finding_class") or "")
                # The fallback identifies an observation, not a synthetic CVE.
                rule = row.get("rule_id") or row.get("cve_id")
                if not rule and cls in _KIND:
                    rule = f"{cls}:{row.get('title') or row.get('match_reason') or cls}"
                cve = row.get("cve_id")
                ruleset = row.get("ruleset_version") or meta.get("ruleset")
                if cls == "plugin_script":
                    # ``SCRIPT-<NAME>`` is Pulse's label for a plugin finding, not a CVE
                    # (observation() refuses it); the plugin is the rule, and its file's
                    # sha256 from the adapter receipt is the rule version.
                    plugin = str(row.get("match_reason") or "").removeprefix("rhai script ").strip()
                    cve = None
                    rule = f"plugin:{plugin or row.get('title') or 'unknown'}"
                    ruleset = f"sha256:{plugin_shas[plugin]}" if plugin in plugin_shas else None
                self.add({**row, "host": row.get("ip") or row.get("host"),
                          "protocol": row.get("protocol") or "tcp", "cve": cve,
                          "rule_id": rule, "evidence_kind": _KIND.get(cls, "unclassified"),
                          "engine_version": meta.get("version"),
                          "ruleset_version": ruleset,
                          "observed_at": row.get("timestamp"),
                          "evidence": row.get("evidence") or row.get("match_reason")},
                         "pulse", path, sha, f"/{field}/{index}")
            self.note(path, "read")
        except (ValueError, TypeError, RecursionError):
            self.note(path, "invalid_json")

    def nuclei(self) -> None:
        path = "nuclei_raw.jsonl"
        loaded = self.read(path)
        if loaded is None:
            return
        text, sha = loaded
        # JSONL records end at LF (CRLF leaves JSON whitespace before the LF).
        # splitlines() also splits legal Unicode characters inside JSON strings,
        # dropping observations and shifting their physical source-line locators.
        for index, line in enumerate(text.split("\n"), 1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                if not isinstance(raw, dict):
                    raise ValueError
                info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
                classification = info.get("classification")
                classification = classification if isinstance(classification, dict) else {}
                cves = classification.get("cve-id") or [None]
                if isinstance(cves, str):
                    cves = [cves]
                if not isinstance(cves, list):
                    raise ValueError
                event_type = str(raw.get("type") or "").lower()
                transport = raw.get("protocol") or ({"http": "tcp", "ssl": "tcp", "tcp": "tcp"}.get(event_type))
                for cve in cves:
                    self.add({"host": raw.get("host"), "port": raw.get("port"),
                              "matched_at": raw.get("matched-at"), "protocol": transport,
                              "sni": raw.get("sni"), "rule_id": raw.get("template-id"),
                              "matcher": raw.get("matcher-name"), "title": info.get("name"),
                              "severity": info.get("severity"), "cve": cve,
                              "observed_at": raw.get("timestamp"), "evidence_kind": "template_match",
                              "engine_version": raw.get("engine_version"),
                              "ruleset_version": raw.get("ruleset_version"),
                              "requires_confirmation": True,
                              "evidence_material": [raw.get("matcher-name"), raw.get("extracted-results")]}, "nuclei", path, sha, f"line:{index}")
            except (ValueError, TypeError, RecursionError):
                self.note(path, "invalid_jsonl_row")
        self.note(path, "read")

    def nmap(self) -> None:
        directory = self.root / "nmap"
        if directory.is_symlink():
            self.note("nmap", "unsafe_path")
            return
        files = list(islice(directory.rglob("*.xml"), MAX_NMAP_FILES + 1))
        if len(files) > MAX_NMAP_FILES:
            self.note("nmap", "file_limit")
            self.limited = True
            return
        if not files:
            self.note("nmap", "missing")
        for file in sorted(files):
            path = file.relative_to(self.root).as_posix()
            loaded = self.read(path)
            if loaded is None:
                continue
            text, sha = loaded
            try:
                root = fromstring(text)
                for hi, host in enumerate(root.findall("host")):
                    address = next((a.get("addr") for a in host.findall("address")
                                    if a.get("addrtype") in {"ipv4", "ipv6"}), None)
                    if not address:
                        self.note(path, "missing_host_address")
                        continue
                    for si, script in enumerate(host.findall("./hostscript/script")):
                        self.nse(script, address, None, "unknown", root.get("version"),
                                 path, sha, f"host:{hi}/hostscript:{si}")
                    for pi, port in enumerate(host.findall("./ports/port")):
                        state = port.find("state")
                        if state is None or state.get("state") != "open":
                            continue
                        for si, script in enumerate(port.findall("script")):
                            self.nse(script, address, port.get("portid"), port.get("protocol") or "unknown",
                                     root.get("version"), path, sha, f"host:{hi}/port:{pi}/script:{si}")
                self.note(path, "read")
            except (ParseError, DefusedXmlException, ValueError, RecursionError):
                self.note(path, "invalid_xml")

    def nse(self, script, host, port, protocol, version, path, sha, locator) -> None:
        output = script.get("output") or ""
        cves = sorted({cve.upper() for cve in _CVE.findall(output)})
        # A CVE mention is reported as an unverified NSE report, not an exploit.
        if not cves:
            # Do not turn "NOT VULNERABLE" into a positive observation.
            if "VULNERABLE" not in output.upper() or "NOT VULNERABLE" in output.upper():
                return
            cves = [None]
        for cve in cves:
            self.add({"host": host, "port": port, "protocol": protocol, "cve": cve,
                      "rule_id": script.get("id"), "engine_version": version,
                      "title": script.get("id"), "evidence": output, "preview": "",
                      "evidence_kind": "nse_report", "requires_confirmation": True},
                     "nmap-nse", path, sha, locator)

    def build(self) -> dict[str, Any]:
        self.pulse()
        self.nuclei()
        self.nmap()
        result = aggregate(self.rows)
        result["context"] = {"tenant_id": self.tenant_id, "run_id": self.run_id}
        result["diagnostics"] = sorted(self.diagnostics, key=lambda d: (d["artifact"], d["code"]))
        result["projection_incomplete"] = self.limited or not any(d["code"] == "read" for d in self.diagnostics) or any(
            d["code"] not in {"read", "missing"} for d in self.diagnostics
        )
        result["limits"] = {"file_bytes": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES,
                            "observations": MAX_OBSERVATIONS, "nmap_files": MAX_NMAP_FILES}
        return result


def write_evidence_artifact(root: Path, *, tenant_id: str, run_id: str) -> dict[str, Any]:
    """Write one atomic sidecar; never modify vulnerabilities.json or raw inputs."""
    reader = EvidenceReader(root, tenant_id, run_id)
    result = reader.build()
    temp: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=reader.root,
                                         prefix=".finding-evidence-", suffix=".tmp", delete=False) as handle:
            temp = handle.name
            json.dump(result, handle, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, reader.root / "finding_evidence.json")
    finally:
        if temp is not None:
            Path(temp).unlink(missing_ok=True)
    return result
