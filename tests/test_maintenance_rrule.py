"""The recurrence engine behind maintenance windows (#352).

No database: the RRULE subset, the occurrence generator and the asset-group
selector are pure, and the questions that actually bite — midnight, DST, a
month with no 31st — are answerable without one.
"""

from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from api.services import maintenance

BERLIN = ZoneInfo("Europe/Berlin")


def _utc(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def _spans(
    rrule: str,
    dtstart: str,
    *,
    tz: str = "Europe/Berlin",
    minutes: int = 240,
    since: str,
    until: str,
) -> list[tuple[datetime, datetime]]:
    return maintenance.occurrences(
        maintenance.parse_rrule(rrule),
        datetime.fromisoformat(dtstart),
        timezone=tz,
        duration_minutes=minutes,
        since=_utc(since),
        until=_utc(until),
    )


def _window(**overrides) -> dict:
    window = {
        "window_id": "mw_test",
        "tenant_id": "default",
        "name": "nightly",
        "kind": maintenance.KIND_BLACKOUT,
        "enabled": True,
        "timezone": "Europe/Berlin",
        "rrule": "FREQ=DAILY",
        "dtstart_local": "2027-03-27T23:00",
        "duration_minutes": 240,
        "scope_kind": maintenance.SCOPE_TENANT,
        "asset_group": None,
        "scope_targets": [],
    }
    window.update(overrides)
    return window


# --------------------------------------------------------------------------
# 1. The supported subset, and refusing everything else
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule",
    [
        "FREQ=DAILY",
        "FREQ=DAILY;INTERVAL=3",
        "RRULE:FREQ=WEEKLY;BYDAY=SA,SU",
        "freq=weekly;byday=mo",
        "FREQ=MONTHLY;BYMONTHDAY=1,15",
        "FREQ=WEEKLY;UNTIL=20271231T235959Z",
        "FREQ=DAILY;UNTIL=20271231",
    ],
)
def test_supported_rules_parse(rule: str):
    assert maintenance.parse_rrule(rule).freq in ("DAILY", "WEEKLY", "MONTHLY")


@pytest.mark.parametrize(
    "rule",
    [
        "",
        "FREQ=YEARLY",
        "FREQ=HOURLY",
        "INTERVAL=2",  # no FREQ
        "FREQ=WEEKLY;COUNT=10",
        "FREQ=WEEKLY;BYDAY=-1SU",
        "FREQ=DAILY;BYDAY=MO",
        "FREQ=WEEKLY;BYMONTHDAY=1",
        "FREQ=DAILY;BYHOUR=22",
        "FREQ=DAILY;INTERVAL=0",
        "FREQ=DAILY;UNTIL=next-tuesday",
        "FREQ=DAILY;NOTAKEY",
        "FREQ=MONTHLY;BYMONTHDAY=41",
    ],
)
def test_unsupported_rules_are_refused_by_name(rule: str):
    """A rule accepted and then read as something narrower than what the
    operator typed would be a blackout that does not blackout — and nothing
    would tell them. Every refusal names the part that is unsupported."""
    with pytest.raises(ValueError, match="unsupported RRULE"):
        maintenance.parse_rrule(rule)


def test_weekly_interval_counts_weeks_not_matching_days():
    """INTERVAL=2 with two BYDAYs keeps both days inside the same fortnight.

    Counting each matching day as its own step would put Monday and Friday in
    alternate weeks, which is not what "every other week, Mondays and Fridays"
    means to anyone.
    """
    spans = _spans(
        "FREQ=WEEKLY;INTERVAL=2;BYDAY=MO,FR",
        "2027-01-04T22:00",  # a Monday
        minutes=60,
        since="2027-01-04T00:00",
        until="2027-01-30T00:00",
    )
    local_days = sorted({start.astimezone(BERLIN).date().isoformat() for start, _ in spans})
    assert local_days == ["2027-01-04", "2027-01-08", "2027-01-18", "2027-01-22"]


def test_a_month_without_the_requested_day_simply_has_no_occurrence():
    spans = _spans(
        "FREQ=MONTHLY;BYMONTHDAY=31",
        "2027-01-31T01:00",
        minutes=60,
        since="2027-01-01T00:00",
        until="2027-04-30T00:00",
    )
    months = [start.astimezone(BERLIN).date().isoformat() for start, _ in spans]
    assert months == ["2027-01-31", "2027-03-31"]  # no February, no April


def test_until_ends_the_series_inclusively():
    """UNTIL is the last moment an occurrence may *start*, and it is inclusive
    (RFC 5545): the 3rd's 01:00 local is exactly 2027-01-03T00:00Z and still
    fires; a minute earlier it does not."""
    days = [
        start.astimezone(BERLIN).day
        for start, _ in _spans(
            "FREQ=DAILY;UNTIL=20270103T000000Z",
            "2027-01-01T01:00",
            minutes=60,
            since="2027-01-01T00:00",
            until="2027-01-10T00:00",
        )
    ]
    assert days == [1, 2, 3]

    days = [
        start.astimezone(BERLIN).day
        for start, _ in _spans(
            "FREQ=DAILY;UNTIL=20270102T235900Z",
            "2027-01-01T01:00",
            minutes=60,
            since="2027-01-01T00:00",
            until="2027-01-10T00:00",
        )
    ]
    assert days == [1, 2]


def test_a_date_only_until_covers_the_whole_of_that_day():
    """``UNTIL=20271231`` read as midnight would drop the final occurrence of
    every window whose wall clock falls later in the UTC day — a blackout
    written to cover New Year's Eve would be absent on New Year's Eve."""
    days = [
        start.astimezone(BERLIN).day
        for start, _ in _spans(
            "FREQ=DAILY;UNTIL=20271231",
            "2027-12-29T22:00",
            minutes=60,
            since="2027-12-29T00:00",
            until="2028-01-05T00:00",
        )
    ]
    assert days == [29, 30, 31]


# --------------------------------------------------------------------------
# 2. Time zones: the tenant's, not the server's
# --------------------------------------------------------------------------


def test_the_wall_clock_is_the_tenants_across_a_dst_change():
    """"Every Saturday at 22:00" is 22:00 for the customer in January and in
    July — which means two different UTC instants, and that is the point."""
    winter = _spans(
        "FREQ=WEEKLY;BYDAY=SA",
        "2027-01-09T22:00",
        minutes=60,
        since="2027-01-09T00:00",
        until="2027-01-10T00:00",
    )
    summer = _spans(
        "FREQ=WEEKLY;BYDAY=SA",
        "2027-01-09T22:00",
        minutes=60,
        since="2027-07-10T00:00",
        until="2027-07-11T00:00",
    )
    assert winter[0][0] == _utc("2027-01-09T21:00")  # CET, UTC+1
    assert summer[0][0] == _utc("2027-07-10T20:00")  # CEST, UTC+2
    assert {span[0].astimezone(BERLIN).hour for span in winter + summer} == {22}


def test_a_window_crossing_midnight_is_open_after_midnight_and_shut_after_its_end():
    window = _window(rrule="FREQ=DAILY", dtstart_local="2027-01-08T22:00", duration_minutes=240)
    # 00:30 local on the 9th — inside the window that opened on the 8th.
    assert maintenance.open_at(window, _utc("2027-01-08T23:30")) is not None
    # 02:30 local on the 9th — half an hour after it closed.
    assert maintenance.open_at(window, _utc("2027-01-09T01:30")) is None


def test_duration_is_absolute_time_across_a_spring_forward():
    """A four-hour window over the night Berlin loses an hour lasts four real
    hours — it ends at 04:00 local, not 03:00. A window computed in wall clock
    would reopen the estate an hour early on exactly the night somebody
    scheduled maintenance."""
    window = _window(dtstart_local="2027-03-27T23:00", duration_minutes=240)
    span = maintenance.open_at(window, _utc("2027-03-28T00:30"))
    assert span is not None
    start, end = span
    assert start == _utc("2027-03-27T22:00")
    assert end == _utc("2027-03-28T02:00")
    assert (end - start).total_seconds() == 4 * 3600
    assert end.astimezone(BERLIN).hour == 4  # CEST: five hours of wall clock
    # Still open half an hour after the clocks jumped …
    assert maintenance.open_at(window, _utc("2027-03-28T01:30")) is not None
    # … and shut on the instant it ends (the interval is half-open).
    assert maintenance.open_at(window, _utc("2027-03-28T02:00")) is None


def test_duration_is_absolute_time_across_a_fall_back():
    window = _window(dtstart_local="2027-10-30T23:00", duration_minutes=240)
    span = maintenance.open_at(window, _utc("2027-10-31T00:30"))
    assert span is not None
    start, end = span
    assert (end - start).total_seconds() == 4 * 3600
    assert end == _utc("2027-10-31T01:00")
    assert end.astimezone(BERLIN).hour == 2  # CET: three hours of wall clock


def test_a_wall_clock_the_clocks_skipped_still_produces_an_occurrence():
    """02:30 does not exist in Berlin on the spring-forward morning. zoneinfo
    resolves it with the pre-transition offset, which lands the window at 03:30
    local — half an hour late rather than silently missing. Dropping the
    occurrence would be the dangerous reading: the blackout the operator asked
    for would be absent on one night a year."""
    window = _window(
        rrule="FREQ=DAILY", dtstart_local="2027-03-01T02:30", duration_minutes=60
    )
    span = maintenance.open_at(window, _utc("2027-03-28T01:35"))
    assert span is not None
    assert span[0] == _utc("2027-03-28T01:30")
    assert span[0].astimezone(BERLIN).strftime("%H:%M") == "03:30"


def test_an_ambiguous_wall_clock_takes_the_first_of_the_two():
    window = _window(
        rrule="FREQ=DAILY", dtstart_local="2027-10-01T02:30", duration_minutes=30
    )
    span = maintenance.open_at(window, _utc("2027-10-31T00:35"))
    assert span is not None
    assert span[0] == _utc("2027-10-31T00:30")  # CEST, the earlier 02:30


def test_next_start_after_looks_forward_but_not_forever():
    window = _window(rrule="FREQ=DAILY", dtstart_local="2027-01-01T22:00")
    at = _utc("2027-01-05T12:00")
    assert maintenance.next_start_after(window, at) == _utc("2027-01-05T21:00")
    # A series that ended before `at` has no next start rather than a stale one.
    ended = _window(
        rrule="FREQ=DAILY;UNTIL=20270104T000000Z", dtstart_local="2027-01-01T22:00"
    )
    assert maintenance.next_start_after(ended, at) is None


def test_a_window_that_cannot_be_read_is_dropped_not_obeyed(caplog):
    """The hand-edited-database path: a row whose rule no longer parses must
    not stop every scan in the tenant, and it must be loud."""
    with caplog.at_level("ERROR"):
        assert maintenance.open_at(_window(rrule="FREQ=YEARLY"), _utc("2027-03-28T00:30")) is None
    assert "unreadable maintenance window" in caplog.text


# --------------------------------------------------------------------------
# 3. Which scans a window covers
# --------------------------------------------------------------------------


def test_a_tenant_window_covers_every_scan():
    assert maintenance._selector_covers(_window(), ["10.0.0.0/24"], []) is True  # noqa: SLF001


def test_an_asset_group_window_covers_a_scan_that_overlaps_it():
    """Overlap, not containment: a sweep of 10.0.0.0/16 does touch the group's
    10.0.5.0/24, and the scope rules' "is it inside an allowed range" question
    would answer no."""
    window = _window(
        scope_kind=maintenance.SCOPE_ASSET_GROUP,
        asset_group="payments",
        scope_targets=["10.0.5.0/24", "shop.example.com"],
    )
    covers = maintenance._selector_covers  # noqa: SLF001
    assert covers(window, ["10.0.0.0/16"], []) is True
    assert covers(window, ["10.0.5.7/32"], []) is True
    assert covers(window, ["192.168.4.0/24"], []) is False
    assert covers(window, [], ["www.shop.example.com"]) is True
    assert covers(window, [], ["shop.example.com.evil.test"]) is False
    # A scan with no targets runs on the installation defaults, and the control
    # plane cannot tell what it will touch: covered, so a blackout cannot be
    # dodged by leaving the target boxes empty.
    assert covers(window, [], []) is True
