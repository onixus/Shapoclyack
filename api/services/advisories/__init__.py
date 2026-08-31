"""Vendor-advisory providers for software→CVE matching (ROADMAP Track E).

Two distributions in this milestone — Debian and Ubuntu — because that is what
the roadmap called for and because the cost of a provider is almost entirely in
knowing the vendor's own vocabulary, not in the plumbing. Adding a third means
writing a ``normalize_*`` function and one four-line subclass.

The registry is module-level and lazily built, mirroring how the enrichment
overlays are held: providers are stateless apart from a cached dataset that
invalidates on the file's mtime, so sharing one instance per process is both
safe and the point.
"""

from __future__ import annotations

from api.services.advisories.base import (
    STATE_NOT_AFFECTED,
    STATE_OPEN,
    STATE_RESOLVED,
    STATES,
    AdvisoryProvider,
    AdvisoryRecord,
    JsonAdvisoryProvider,
    load_dataset,
)
from api.services.advisories.debian import DebianAdvisoryProvider
from api.services.advisories.ubuntu import UbuntuAdvisoryProvider

__all__ = [
    "STATES",
    "STATE_NOT_AFFECTED",
    "STATE_OPEN",
    "STATE_RESOLVED",
    "AdvisoryProvider",
    "AdvisoryRecord",
    "DebianAdvisoryProvider",
    "JsonAdvisoryProvider",
    "UbuntuAdvisoryProvider",
    "get_provider",
    "load_dataset",
    "providers",
    "reload_providers",
    "status",
]

_PROVIDER_TYPES: tuple[type[JsonAdvisoryProvider], ...] = (
    DebianAdvisoryProvider,
    UbuntuAdvisoryProvider,
)

_registry: dict[str, JsonAdvisoryProvider] | None = None


def providers() -> dict[str, JsonAdvisoryProvider]:
    """Every provider, keyed by the ``package_identity`` distro it covers."""
    global _registry
    if _registry is None:
        _registry = {cls.distro: cls() for cls in _PROVIDER_TYPES}
    return _registry


def get_provider(distro: str | None) -> JsonAdvisoryProvider | None:
    """The provider covering ``distro``, or ``None`` when nothing does."""
    if not distro:
        return None
    return providers().get(distro.strip().lower())


def reload_providers() -> None:
    """Drop every cached dataset. Used by tests and after an opt-in fetch."""
    for provider in providers().values():
        provider.reload()


def status() -> list[dict[str, object]]:
    """Per-provider provenance, for ``GET /api/system``."""
    return [provider.status() for provider in providers().values()]
