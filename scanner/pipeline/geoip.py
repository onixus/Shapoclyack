"""GeoIP lookup (MaxMind GeoLite2 .mmdb, DB-IP MMDB, or JSON overlay)."""

from __future__ import annotations

import ipaddress
import json
import logging
from pathlib import Path
from typing import Any

LOG = logging.getLogger(__name__)


def _private_geo(ip: str) -> dict[str, Any] | None:
    """Label RFC1918 / loopback / link-local so lab scans are not all 'No GeoIP'.

    Deliberately carries no coordinates: a private address has no location on
    the planet, and inventing one would put lab hosts somewhere on the map as
    if they had been geolocated.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_loopback:
        return {"country": "Private", "city": "localhost", "country_iso": "", "latitude": None, "longitude": None}
    if addr.is_private or addr.is_link_local or addr.is_reserved:
        return {"country": "Private", "city": "LAN", "country_iso": "", "latitude": None, "longitude": None}
    return None


def _coordinate(value: Any, *, limit: float) -> float | None:
    """A finite coordinate inside ``±limit``, or None.

    Applied to every source, database or overlay: a latitude of 900 plots a
    marker off the map rather than failing visibly, so it is rejected here
    where the value enters the pipeline.
    """
    # bool before float: `float(True)` is 1.0, so a hand-written overlay with
    # `"latitude": true` would otherwise pass every check below and put a
    # marker at a plausible-looking, entirely fabricated position.
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number in (float("inf"), float("-inf")):  # NaN / ±inf
        return None
    if abs(number) > limit:
        return None
    return round(number, 4)


class GeoIpDatabase:
    """Resolve IPv4/IPv6 → country / city / coordinates.

    Supports:
    - MaxMind GeoLite2-City / DB-IP City Lite ``.mmdb`` via the ``geoip2``
      package, and Country editions of the same (see :meth:`_read`)
    - JSON overlay ``{ "1.2.3.4": {"country": "...", "city": "...", "country_iso": "XX",
      "latitude": 0.0, "longitude": 0.0} }`` for labs/tests without redistributing
      MaxMind data

    ``latitude``/``longitude`` come from the City database's ``location`` and are
    ``None`` whenever it does not carry one — a Country-only database, a record
    without a location, or a private address. They are what the Geo Map page
    plots; a host with neither coordinates nor a country ISO is reported as
    unlocated rather than placed somewhere plausible.

    The coordinates a GeoIP database returns are the *registered* position of a
    network, typically the centre of a city or of a whole country, and never
    the physical position of the machine. Consumers must present them at that
    precision.
    """

    def __init__(
        self,
        *,
        reader: Any | None = None,
        overlay: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._reader = reader
        self._overlay = overlay or {}
        # Which Reader method this database answers: "city" or "country",
        # decided on the first successful lookup (see _read).
        self._mode: str | None = None

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
                        # `lat`/`lon` accepted as aliases: the overlay is
                        # hand-written in labs and tests, where the short names
                        # are what people type.
                        "latitude": _coordinate(
                            value.get("latitude", value.get("lat")), limit=90.0
                        ),
                        "longitude": _coordinate(
                            value.get("longitude", value.get("lon")), limit=180.0
                        ),
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

    def _read(self, ip: str) -> Any | None:
        """One record from the open database, whichever edition it is.

        ``Reader.city()`` raises on a Country-edition database rather than
        degrading, so a GeoLite2-Country install used to resolve *nothing* —
        every public host came back empty, and with the Geo Map that reads as
        an estate with no location at all rather than a coarser one. The
        working method is remembered after the first call, so the fallback
        costs one exception per process, not one per host.
        """
        reader = self._reader
        if reader is None:
            return None
        for name in (self._mode,) if self._mode else ("city", "country"):
            try:
                response = getattr(reader, name)(ip)
            except Exception as exc:  # noqa: BLE001 — AddressNotFoundError and friends
                # "This database does not know that address" says nothing about
                # the edition — the method itself worked — so it settles the
                # mode instead of falling through to the other one.
                if type(exc).__name__ == "AddressNotFoundError":
                    self._mode = name
                    return None
                continue
            self._mode = name
            return response
        return None

    def lookup(self, ip: str | None) -> dict[str, Any]:
        empty: dict[str, Any] = {
            "country": "",
            "city": "",
            "country_iso": "",
            "latitude": None,
            "longitude": None,
        }
        if not ip:
            return empty
        if ip in self._overlay:
            hit = self._overlay[ip]
            # A private address has no position even when the overlay states
            # one: the overlay is hand-written, and an entry for 10.x with
            # coordinates would put a lab host on the world map as a
            # geolocated one. The operator's labels are kept; the position is
            # not, which is the same invariant _private_geo enforces below.
            private_hit = _private_geo(ip) is not None
            return {
                "country": hit.get("country") or "",
                "city": hit.get("city") or "",
                "country_iso": hit.get("country_iso") or "",
                "latitude": None if private_hit else hit.get("latitude"),
                "longitude": None if private_hit else hit.get("longitude"),
            }
        private = _private_geo(ip)
        if private is not None:
            return private
        if self._reader is None:
            return empty
        response = self._read(ip)
        if response is None:
            return empty
        country = ""
        city = ""
        iso = ""
        try:
            country = response.country.name or ""
            iso = response.country.iso_code or ""
            # Absent on a Country-edition response, which has no city at all.
            city = getattr(getattr(response, "city", None), "name", "") or ""
        except Exception:  # noqa: BLE001
            return empty
        # Read separately from the names above: a Country-edition database has
        # no `location` attribute at all, and losing the country because the
        # coordinates are missing would be a regression in what already worked.
        latitude: float | None = None
        longitude: float | None = None
        try:
            location = getattr(response, "location", None)
            latitude = _coordinate(getattr(location, "latitude", None), limit=90.0)
            longitude = _coordinate(getattr(location, "longitude", None), limit=180.0)
        except Exception:  # noqa: BLE001
            latitude = longitude = None
        return {
            "country": country,
            "city": city,
            "country_iso": iso,
            "latitude": latitude,
            "longitude": longitude,
        }


def enrich_hosts_geo(
    hosts: list[str],
    database: GeoIpDatabase,
) -> dict[str, dict[str, Any]]:
    """Return ip → geo fields for each host."""
    out: dict[str, dict[str, Any]] = {}
    for host in hosts:
        out[host] = database.lookup(host)
    return out


def attach_geo_to_records(records: list[dict], geo_map: dict[str, dict[str, Any]]) -> None:
    for item in records:
        geo = geo_map.get(str(item.get("host") or ""), {})
        item["country"] = geo.get("country") or None
        item["city"] = geo.get("city") or None
        item["country_iso"] = geo.get("country_iso") or None
        # `or None` would turn a legitimate 0.0 (the equator, the prime
        # meridian) into "no coordinate", so these two are passed through as-is.
        item["latitude"] = geo.get("latitude")
        item["longitude"] = geo.get("longitude")
