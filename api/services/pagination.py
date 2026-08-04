"""Shared filter/sort/slice helpers for the paginated list endpoints (ROADMAP P3.2).

Used by the services whose collections live in memory (`jobs`, `agents`) or on
the filesystem (`runs`). Postgres-backed lists (`assets`, `scan_schedules`)
push the same semantics down into SQL instead — same query parameters, same
`(items, total)` return shape, so routes stay uniform.

Ordering rules shared by both paths:

* ``total`` counts rows **after** filtering, never the raw collection size;
* an unknown or empty ``sort`` falls back to the resource's documented default
  rather than erroring, so a stale client cannot break a list;
* sorting is stable and ``None`` sorts last in descending order (a job that
  never started should not outrank one that did).
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Sequence, TypeVar

T = TypeVar("T")

DEFAULT_LIMIT = 100
MAX_LIMIT = 5000


def _field(item: Any, name: str) -> Any:
    if isinstance(item, dict):
        return item.get(name)
    return getattr(item, name, None)


def matches_query(item: Any, q: str | None, fields: Sequence[str]) -> bool:
    """Case-insensitive substring match over ``fields``. Empty ``q`` matches all."""
    needle = (q or "").strip().lower()
    if not needle:
        return True
    for name in fields:
        value = _field(item, name)
        if value is None:
            continue
        if needle in str(value).lower():
            return True
    return False


def apply_query(items: Iterable[T], q: str | None, fields: Sequence[str]) -> list[T]:
    return [item for item in items if matches_query(item, q, fields)]


def apply_sort(
    items: list[T],
    sort: str | None,
    order: str | None,
    *,
    allowed: Sequence[str],
    default: str,
    key_overrides: dict[str, Callable[[Any], Any]] | None = None,
) -> list[T]:
    field = sort if sort in allowed else default
    descending = (order or "").lower() != "asc"
    override = (key_overrides or {}).get(field)

    def key(item: T) -> tuple[int, Any]:
        value = override(item) if override else _field(item, field)
        if value is None:
            # None last in both directions: sorted() reverses the whole tuple,
            # so the presence flag has to be pre-flipped for descending.
            return (0 if descending else 1, "")
        if isinstance(value, bool):
            value = int(value)
        if isinstance(value, (int, float)):
            return (1 if descending else 0, value)
        return (1 if descending else 0, str(value).lower())

    return sorted(items, key=key, reverse=descending)


def slice_page(items: Sequence[T], *, offset: int, limit: int) -> tuple[list[T], int]:
    """Return ``(page, total)`` for an already filtered and sorted sequence."""
    total = len(items)
    return list(items[offset : offset + limit]), total


def has_more(*, total: int, offset: int, returned: int) -> bool:
    return offset + returned < total
