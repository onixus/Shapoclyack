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
        return self.data.lookup(
            (release or "").strip().lower(), (source_package or "").strip().lower()
        )


def snapshot_provider(provider: AdvisoryProvider | None) -> AdvisoryProvider | None:
    """Pin JSON providers once; retain the existing custom-provider protocol.

    Invalid text or excessive JSON nesting cannot become a successful empty
    assessment. Other programming errors are not swallowed. Provider status
    and fetching keep their existing interfaces and are outside this layer.
    """
    if not isinstance(provider, JsonAdvisoryProvider):
        return provider
    try:
        dataset = provider.dataset()
    except (UnicodeError, RecursionError):
        dataset = AdvisoryDataset(present=True, error="invalid advisory document")
    return AdvisorySnapshot(name=provider.name, distro=provider.distro, data=dataset)


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
