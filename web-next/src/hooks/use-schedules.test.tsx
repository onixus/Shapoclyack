import { afterEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import type { ScanSchedule } from "@/lib/api";

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

vi.mock("@/lib/api", () => ({
  fetchSchedules: vi.fn(),
  createSchedule: vi.fn(),
  updateSchedule: vi.fn(),
  deleteSchedule: vi.fn(),
}));

import { fetchSchedules, deleteSchedule } from "@/lib/api";
import { useSchedules, useDeleteSchedule } from "@/hooks/use-schedules";

const SCHEDULE: ScanSchedule = {
  schedule_id: "sch_1",
  tenant_id: "default",
  name: "t1",
  enabled: true,
  cron: null,
  interval_seconds: 3600,
  scan_options: {
    mode: "balanced",
    delta: true,
    skip_nse: false,
    notify: false,
    export_defectdojo: false,
  },
  targets: { ranges: "10.0.0.0/24", domains: null, ports: null, ports_udp: null },
  next_run_at: null,
  last_run_at: null,
  last_job_id: null,
  created_at: null,
  created_by: null,
};

/** Paginated envelope the API returns since ROADMAP P3.2. */
const SCHEDULE_PAGE = {
  items: [SCHEDULE],
  total: 1,
  offset: 0,
  limit: 15,
  has_more: false,
};

function wrapper({ children }: { children: ReactNode }) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

afterEach(() => {
  vi.clearAllMocks();
});

describe("useSchedules", () => {
  it("returns the fetched schedules on the happy path", async () => {
    vi.mocked(fetchSchedules).mockResolvedValueOnce(SCHEDULE_PAGE);

    const { result } = renderHook(() => useSchedules(true), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(SCHEDULE_PAGE);
    expect(result.current.data?.items).toEqual([SCHEDULE]);
  });

  it("surfaces the error when the fetch fails", async () => {
    vi.mocked(fetchSchedules).mockRejectedValueOnce(new Error("network down"));

    const { result } = renderHook(() => useSchedules(true), { wrapper });

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toBe("network down");
  });

  it("does not fetch when disabled", () => {
    const { result } = renderHook(() => useSchedules(false), { wrapper });
    expect(result.current.fetchStatus).toBe("idle");
    expect(fetchSchedules).not.toHaveBeenCalled();
  });
});

describe("useDeleteSchedule", () => {
  it("deletes a schedule on the happy path", async () => {
    vi.mocked(deleteSchedule).mockResolvedValueOnce(undefined);

    const { result } = renderHook(() => useDeleteSchedule(), { wrapper });
    result.current.mutate("sch_1");

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(deleteSchedule).toHaveBeenCalledWith("sch_1");
  });

  it("surfaces the error when delete fails", async () => {
    vi.mocked(deleteSchedule).mockRejectedValueOnce(new Error("forbidden"));

    const { result } = renderHook(() => useDeleteSchedule(), { wrapper });
    result.current.mutate("sch_1");

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toBe("forbidden");
  });
});
