"""Stable advisory data and explicit coverage failures for one matching pass.

Identity answers whether a package *can* be matched. This layer answers whether
this installation has data to do it (#358). No network or database access.
"""

from __future__ import annotations

from dataclasses import dataclass

from api.services.advisories.base import (
    AdvisoryDataset,
    AdvisoryProvider,
    AdvisoryRecord,
    JsonAdvisoryProvider,
)

NO_ADVISORY_DATA = "no_advisory_data"
ADVISORY_RELEASE_NOT_COVERED = "advisory_release_not_covered"


@dataclass(frozen=True)
class AdvisorySnapshot:
    """Hold the loaded dataset, not a provider that may reload between lookups.

    The loader replaces its dataset rather than mutating it. Holding this
    reference costs no copy of the index and keeps decisions and provenance
    on the same dataset until this device's pass ends.
    """

    name: str
    distro: str
    data: AdvisoryDataset
    case_sensitive_packages: bool = False

    def available(self) -> bool:
        return bool(self.data.records)

    def feed_date(self) -> str | None:
        return self.data.updated

    def entry_count(self) -> int:
        return len(self.data.records)

    def source_label(self) -> str | None:
        return self.data.source

    def releases(self) -> tuple[str, ...]:
        return self.data.releases

    def advisories_for(
        self, *, release: str, source_package: str
    ) -> tuple[AdvisoryRecord, ...]:
        package = (source_package or "").strip()
        if not self.case_sensitive_packages:
            package = package.lower()
        return self.data.lookup((release or "").strip().lower(), package)


def snapshot_provider(provider: AdvisoryProvider | None) -> AdvisoryProvider | None:
    """Pin JSON providers once; retain the existing custom-provider protocol.

    Only inherited JSON read methods can be replaced by a raw dataset view.
    A subclass/instance overriding availability, filtering or provenance owns
    its policy and consistency; bypassing those methods could enable a disabled
    provider or expose records it intentionally filters. The shared loader owns
    malformed-document handling for matching, status and closure alike.
    """
    if not isinstance(provider, JsonAdvisoryProvider):
        return provider
    methods = (
        "available", "feed_date", "entry_count", "source_label",
        "releases", "advisories_for",
    )
    if any(
        getattr(getattr(provider, method), "__func__", None)
        is not getattr(JsonAdvisoryProvider, method)
        for method in methods
    ):
        return provider
    return AdvisorySnapshot(
        name=provider.name, distro=provider.distro, data=provider.dataset(),
        case_sensitive_packages=provider.case_sensitive_packages,
    )


def coverage_reason(provider: AdvisoryProvider | None, *, release: str) -> str | None:
    """A missing feed/release is unknown, not evidence of a clean package.

    A release present in the data may still have no statement for a particular
    package. Keep that distinct: it means no matching entry in this dataset,
    not proof of absence of vulnerabilities or of complete vendor coverage.
    """
    if provider is None or not provider.available():
        return NO_ADVISORY_DATA
    if release not in provider.releases():
        return ADVISORY_RELEASE_NOT_COVERED
    return None
