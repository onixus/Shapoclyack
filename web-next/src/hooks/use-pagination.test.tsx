import { describe, expect, it } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { usePagination } from "@/hooks/use-pagination";

describe("usePagination", () => {
  it("starts on the first page with the requested defaults", () => {
    const { result } = renderHook(() => usePagination({ limit: 25, sort: "name", order: "asc" }));
    expect(result.current.params).toEqual({
      offset: 0,
      limit: 25,
      q: undefined,
      sort: "name",
      order: "asc",
    });
  });

  it("pages forward and back without touching the other params", () => {
    const { result } = renderHook(() => usePagination({ limit: 10 }));
    act(() => result.current.setOffset(10));
    expect(result.current.params.offset).toBe(10);
    act(() => result.current.setOffset(0));
    expect(result.current.params.offset).toBe(0);
  });

  it("rewinds to the first page when the search changes", () => {
    const { result } = renderHook(() => usePagination({ limit: 10 }));
    act(() => result.current.setOffset(30));
    act(() => result.current.setSearch("edge"));
    // An offset computed against the unfiltered list points at unrelated rows.
    expect(result.current.params).toMatchObject({ offset: 0, q: "edge" });
  });

  it("rewinds to the first page when the sort changes", () => {
    const { result } = renderHook(() => usePagination({ limit: 10, sort: "last_seen" }));
    act(() => result.current.setOffset(20));
    act(() => result.current.setSort("status", "asc"));
    expect(result.current.params).toMatchObject({ offset: 0, sort: "status", order: "asc" });
  });

  it("omits a blank search rather than sending an empty q", () => {
    const { result } = renderHook(() => usePagination());
    act(() => result.current.setSearch("   "));
    expect(result.current.params.q).toBeUndefined();
  });

  it("exposes reset for filters owned by the page (status, tenant)", () => {
    const { result } = renderHook(() => usePagination({ limit: 10 }));
    act(() => result.current.setOffset(40));
    act(() => result.current.reset());
    expect(result.current.params.offset).toBe(0);
  });
});
