"""GeoIP lookup (MaxMind GeoLite2 .mmdb, DB-IP MMDB, or JSON overlay)."""

from __future__ import annotations

import ipaddress
import json
import logging
from pathlib import Path
from typing import Any

LOG = logging.getLogger(__name__)


def _private_geo(ip: str) -> dict[str, str] | None:
    """Label RFC1918 / loopback / link-local so lab scans are not all 'No GeoIP'."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_loopback:
        return {"country": "Private", "city": "localhost", "country_iso": ""}
    if addr.is_private or addr.is_link_local or addr.is_reserved:
        return {"country": "Private", "city": "LAN", "country_iso": ""}
    return None


class GeoIpDatabase:
    """Resolve IPv4/IPv6 → country / city.

    Supports:
    - MaxMind GeoLite2-City / DB-IP City Lite ``.mmdb`` via the ``geoip2`` package
    - JSON overlay ``{ "1.2.3.4": {"country": "...", "city": "...", "country_iso": "XX"} }``
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
    def load(cls, path: Path | None) -> GeoIpDatabase:
        if path is None or not path.is_file():
            return cls()
        suffix = path.suffix.lower()
        if suffix == ".json":
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                LOG.warning("Failed to load GeoIP JSON %s: %s", path, exc)
                return cls()
            if not isinstance(raw, dict):
                return cls()
            # Support both flat {ip: {...}} and wrapped {entries: {ip: {...}}} layouts.
            source = raw.get("entries") if isinstance(raw.get("entries"), dict) else raw
            overlay: dict[str, dict[str, str]] = {}
            for key, value in source.items():
                if isinstance(key, str) and isinstance(value, dict) and key not in (
                    "version",
                    "source",
                    "updated",
                ):
                    overlay[key] = {
                        "country": str(value.get("country") or ""),
                        "city": str(value.get("city") or ""),
                        "country_iso": str(value.get("country_iso") or value.get("iso") or ""),
                    }
            LOG.info("Loaded GeoIP JSON overlay with %d entries from %s", len(overlay), path)
            return cls(overlay=overlay)

        try:
            import geoip2.database  # type: ignore[import-untyped]
        except ImportError:
            LOG.warning("geoip2 is not installed; GeoIP .mmdb lookup disabled")
            return cls()
        try:
            reader = geoip2.database.Reader(str(path))
        except Exception as exc:  # noqa: BLE001
            LOG.warning("Failed to open GeoIP database %s: %s", path, exc)
            return cls()
        LOG.info("Opened GeoIP database %s", path)
        return cls(reader=reader)

    def close(self) -> None:
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:  # noqa: BLE001
                pass
            self._reader = None

    def lookup(self, ip: str | None) -> dict[str, str]:
        empty = {"country": "", "city": "", "country_iso": ""}
        if not ip:
            return empty
        if ip in self._overlay:
            hit = self._overlay[ip]
            return {
                "country": hit.get("country") or "",
                "city": hit.get("city") or "",
                "country_iso": hit.get("country_iso") or "",
            }
        private = _private_geo(ip)
        if private is not None:
            return private
        if self._reader is None:
            return empty
        try:
            response = self._reader.city(ip)
        except Exception:  # noqa: BLE001 — AddressNotFoundError and friends
            return empty
        country = ""
        city = ""
        iso = ""
        try:
            country = response.country.name or ""
            iso = response.country.iso_code or ""
            city = response.city.name or ""
        except Exception:  # noqa: BLE001
            return empty
        return {"country": country, "city": city, "country_iso": iso}


def enrich_hosts_geo(
    hosts: list[str],
    database: GeoIpDatabase,
) -> dict[str, dict[str, str]]:
    """Return ip → geo fields for each host."""
    out: dict[str, dict[str, str]] = {}
    for host in hosts:
        out[host] = database.lookup(host)
    return out


def attach_geo_to_records(records: list[dict], geo_map: dict[str, dict[str, str]]) -> None:
    for item in records:
        geo = geo_map.get(str(item.get("host") or ""), {})
        item["country"] = geo.get("country") or None
        item["city"] = geo.get("city") or None
        item["country_iso"] = geo.get("country_iso") or None
