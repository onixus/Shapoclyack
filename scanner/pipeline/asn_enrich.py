"""ASN / org enrichment (MaxMind GeoLite2-ASN, DB-IP ASN Lite .mmdb, or JSON overlay).

Parallels geoip.py: resolve an IP to its Autonomous System number and holder
(org) name so the attack-surface graph can cluster hosts by network operator,
not just country. Same fail-soft, offline-first posture as GeoIP — a missing
database or unresolvable IP degrades to empty fields, never raises.

Distinct from asn_discovery.py (Phase 8.1), which expands *scan scope* from seed
domains via RIPEstat and is opt-in/online. This module is a per-host offline
lookup over a bundled database, mirroring the GeoIP enrichment path.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from pathlib import Path
from typing import Any

LOG = logging.getLogger(__name__)


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved


class AsnDatabase:
    """Resolve IPv4/IPv6 → {asn, asn_org}.

    Supports:
    - MaxMind GeoLite2-ASN / DB-IP ASN Lite ``.mmdb`` via the ``geoip2`` package
    - JSON overlay ``{ "1.2.3.4": {"asn": "AS13335", "asn_org": "Cloudflare"} }``
      for labs/tests without redistributing MaxMind data
    """

    def __init__(
        self,
        *,
        reader: Any | None = None,
        overlay: dict[str, dict[str, str]] | None = None,
    ) -> None:
        self._reader = reader
        self._overlay = overlay or {}

    @classmethod
    def load(cls, path: Path | None) -> AsnDatabase:
        if path is None or not path.is_file():
            return cls()
        suffix = path.suffix.lower()
        if suffix == ".json":
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                LOG.warning("Failed to load ASN JSON %s: %s", path, exc)
                return cls()
            if not isinstance(raw, dict):
                return cls()
            source = raw.get("entries") if isinstance(raw.get("entries"), dict) else raw
            overlay: dict[str, dict[str, str]] = {}
            for key, value in source.items():
                if isinstance(key, str) and isinstance(value, dict) and key not in (
                    "version",
                    "source",
                    "updated",
                ):
                    overlay[key] = {
                        "asn": str(value.get("asn") or ""),
                        "asn_org": str(value.get("asn_org") or value.get("org") or ""),
                    }
            LOG.info("Loaded ASN JSON overlay with %d entries from %s", len(overlay), path)
            return cls(overlay=overlay)

        try:
            import geoip2.database  # type: ignore[import-untyped]
        except ImportError:
            LOG.warning("geoip2 is not installed; ASN .mmdb lookup disabled")
            return cls()
        try:
            reader = geoip2.database.Reader(str(path))
        except Exception as exc:  # noqa: BLE001
            LOG.warning("Failed to open ASN database %s: %s", path, exc)
            return cls()
        LOG.info("Opened ASN database %s", path)
        return cls(reader=reader)

    def close(self) -> None:
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:  # noqa: BLE001
                pass
            self._reader = None

    def lookup(self, ip: str | None) -> dict[str, str]:
        empty = {"asn": "", "asn_org": ""}
        if not ip:
            return empty
        if ip in self._overlay:
            hit = self._overlay[ip]
            return {"asn": hit.get("asn") or "", "asn_org": hit.get("asn_org") or ""}
        if _is_private(ip):
            return empty
        if self._reader is None:
            return empty
        try:
            response = self._reader.asn(ip)
        except Exception:  # noqa: BLE001 — AddressNotFoundError and friends
            return empty
        try:
            number = response.autonomous_system_number
            org = response.autonomous_system_organization or ""
        except Exception:  # noqa: BLE001
            return empty
        return {"asn": f"AS{number}" if number is not None else "", "asn_org": org}


def enrich_hosts_asn(hosts: list[str], database: AsnDatabase) -> dict[str, dict[str, str]]:
    """Return ip → {asn, asn_org} for each host."""
    return {host: database.lookup(host) for host in hosts}


def attach_asn_to_records(records: list[dict], asn_map: dict[str, dict[str, str]]) -> None:
    for item in records:
        asn = asn_map.get(str(item.get("host") or ""), {})
        item["asn"] = asn.get("asn") or None
        item["asn_org"] = asn.get("asn_org") or None
