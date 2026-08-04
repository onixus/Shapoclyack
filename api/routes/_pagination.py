"""Shared query-parameter dependency for paginated list routes (ROADMAP P3.2)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Query

from api.schemas import Page
from api.services.pagination import DEFAULT_LIMIT, MAX_LIMIT, has_more


@dataclass(frozen=True)
class PageQuery:
    offset: int
    limit: int
    q: str | None
    sort: str | None
    order: str


def page_query(
    offset: Annotated[int, Query(ge=0, description="Rows to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT, description="Rows per page")] = DEFAULT_LIMIT,
    q: Annotated[str | None, Query(description="Case-insensitive substring filter")] = None,
    sort: Annotated[str | None, Query(description="Sort field; unknown values fall back to the default")] = None,
    order: Annotated[str, Query(pattern="^(asc|desc)$")] = "desc",
) -> PageQuery:
    return PageQuery(offset=offset, limit=limit, q=q, sort=sort, order=order)


PageParams = Annotated[PageQuery, Depends(page_query)]


def build_page(items: list, total: int, params: PageQuery) -> Page:
    return Page(
        items=items,
        total=total,
        offset=params.offset,
        limit=params.limit,
        has_more=has_more(total=total, offset=params.offset, returned=len(items)),
    )
