"""Parking-page catalogue for brand-watch (M2).

A small, checked-in list of title and body markers that registrars and
parking networks put on a name that is registered and not in use. This is
data, not a crawler: nothing here fetches a page, follows a link, or names a
path to probe. The HTTP observer matches the markers against the single page
it already fetched.

Markers are lowercase substrings. A title marker matches the page title; a
body marker matches visible text. Both are specific enough that a news
article mentioning a brand, or a live site that happens to say "domain",
does not match. The date is when the strings were read from public parking
pages, not a live re-test.
"""

from __future__ import annotations

from dataclasses import dataclass

CHECKED = "2026-11-01"


@dataclass(frozen=True)
class ParkingMarker:
    """One registrar or parking network, and the strings its page carries."""

    id: str
    name: str
    title: tuple[str, ...] = ()
    body: tuple[str, ...] = ()


#: Title and body markers only. No URLs, no paths, no request of any kind.
PARKING_MARKERS: tuple[ParkingMarker, ...] = (
    ParkingMarker(
        "sedo",
        "Sedo parking",
        title=("this domain is for sale", "buy this domain"),
        body=("this domain is for sale", "sedo.com", "domain is available for purchase"),
    ),
    ParkingMarker(
        "godaddy",
        "GoDaddy parking",
        title=("this domain is parked", "godaddy"),
        body=("this domain is parked free", "courtesy of godaddy", "domain may be for sale"),
    ),
    ParkingMarker(
        "afternic",
        "Afternic parking",
        title=("domain for sale",),
        body=("this domain is for sale at afternic", "afternic.com"),
    ),
    ParkingMarker(
        "dan",
        "Dan.com parking",
        title=("is for sale",),
        body=("buy this domain", "the domain name", "dan.com"),
    ),
    ParkingMarker(
        "namecheap",
        "Namecheap parking",
        title=("this domain was recently registered",),
        body=("this domain was recently registered at namecheap", "namecheap.com"),
    ),
    ParkingMarker(
        "huge_domains",
        "HugeDomains parking",
        title=("is for sale",),
        body=("this domain is for sale", "hugedomains.com", "buy now"),
    ),
    ParkingMarker(
        "bodis",
        "Bodis parking",
        title=("related searches",),
        body=("related searches", "this domain may be for sale", "bodis.com"),
    ),
    ParkingMarker(
        "parkingcrew",
        "ParkingCrew",
        title=("domain parking",),
        body=("this webpage is parked", "parkingcrew.net", "domain is for sale"),
    ),
    ParkingMarker(
        "sav",
        "Sav.com parking",
        title=("domain is for sale",),
        body=("this domain is for sale", "sav.com"),
    ),
    ParkingMarker(
        "generic",
        "Generic parking",
        title=(
            "domain parked",
            "parked domain",
            "domain is parked",
            "coming soon",
            "website coming soon",
            "under construction",
            "this domain has expired",
            "domain has expired",
        ),
        body=(
            "this domain is parked",
            "domain is parked by",
            "buy this domain",
            "this domain name is for sale",
            "the domain has expired",
            "renew this domain",
        ),
    ),
)


def match_parking(title: str, visible_text: str) -> tuple[str, ...] | None:
    """Return ``(marker_id, matched_substring)`` or ``None``.

    Title markers are tried first. A body marker needs the substring in the
    visible text; a title-only marker does not require the body to repeat it.
    Comparison is case-insensitive and does not strip punctuation beyond what
    the caller already collapsed.
    """
    title_l = (title or "").casefold()
    body_l = (visible_text or "").casefold()
    for marker in PARKING_MARKERS:
        for needle in marker.title:
            if needle and needle in title_l:
                return marker.id, needle
        for needle in marker.body:
            if needle and needle in body_l:
                return marker.id, needle
    return None
