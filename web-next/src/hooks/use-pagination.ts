"use client";

import { useCallback, useMemo, useState } from "react";
import type { PageParams } from "@/lib/api";
import { DEFAULT_PAGE_SIZE } from "@/lib/config/constants";

export type PaginationState = {
  /** Params to hand to a paginated fetcher/hook. */
  params: PageParams;
  offset: number;
  limit: number;
  setOffset: (offset: number) => void;
  /** Search text; changing it rewinds to the first page. */
  search: string;
  setSearch: (value: string) => void;
  /** Sort field/direction; changing either rewinds to the first page. */
  sort?: string;
  order: "asc" | "desc";
  setSort: (sort: string | undefined, order: "asc" | "desc") => void;
  /** Rewind after a filter that lives outside this hook (status dropdown, tenant switch). */
  reset: () => void;
};

/**
 * Server-side pagination state for one table (ROADMAP P3.3).
 *
 * Every mutation other than paging rewinds `offset` to 0 — an offset computed
 * against the previous filter or sort points at unrelated rows, and silently
 * showing page 4 of a freshly filtered list is worse than starting over.
 */
export function usePagination(options?: {
  limit?: number;
  sort?: string;
  order?: "asc" | "desc";
}): PaginationState {
  const limit = options?.limit ?? DEFAULT_PAGE_SIZE;
  const [offset, setOffset] = useState(0);
  const [search, setSearchValue] = useState("");
  const [sort, setSortValue] = useState<string | undefined>(options?.sort);
  const [order, setOrder] = useState<"asc" | "desc">(options?.order ?? "desc");

  const setSearch = useCallback((value: string) => {
    setSearchValue(value);
    setOffset(0);
  }, []);

  const setSort = useCallback((next: string | undefined, nextOrder: "asc" | "desc") => {
    setSortValue(next);
    setOrder(nextOrder);
    setOffset(0);
  }, []);

  const reset = useCallback(() => setOffset(0), []);

  const params = useMemo<PageParams>(
    () => ({
      offset,
      limit,
      q: search.trim() || undefined,
      sort,
      order,
    }),
    [offset, limit, search, sort, order],
  );

  return { params, offset, limit, setOffset, search, setSearch, sort, order, setSort, reset };
}
