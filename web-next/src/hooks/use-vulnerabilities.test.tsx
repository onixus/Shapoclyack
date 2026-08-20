import { afterEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import type { TrackedVulnerability, VulnerabilitySummary } from "@/lib/api";

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

vi.mock("@/lib/api", () => ({
  fetchTrackedVulnerabilities: vi.fn(),
  fetchVulnerabilitySummary: vi.fn(),
  fetchTrackedVulnerability: vi.fn(),
  fetchVulnerabilityEvents: vi.fn(),
  transitionVulnerability: vi.fn(),
  assignVulnerability: vi.fn(),
  setVulnerabilityException: vi.fn(),
  clearVulnerabilityException: vi.fn(),
}));

import {
  assignVulnerability,
  fetchTrackedVulnerabilities,
  fetchVulnerabilitySummary,
  transitionVulnerability,
} from "@/lib/api";
import {
  useAssignVulnerability,
  useTrackedVulnerabilities,
  useTransitionVulnerability,
  useVulnerabilitySummary,
} from "@/hooks/use-vulnerabilities";

const VULN: TrackedVulnerability = {
  vuln_id: "vuln_1",
  tenant_id: "default",
  asset_id: "asset_1",
  finding_key: "abc",
  cve: "CVE-2024-1",
  cwe: [],
  script_id: null,
  title: "",
  port: "443",
  severity: "critical",
  risk_level: "very_high",
  contextual_score: 9.1,
  cvss: 9.8,
  in_kev: false,
  exploit_maturity: null,
  network_exposure: null,
  network_exposure_source: null,
  state: "OPEN",
  state_changed_at: null,
  state_changed_by: null,
  assignee: null,
  owner_team: null,
  due_at: "2026-09-01T00:00:00Z",
  sla_days: 15,
  sla_source: "default",
  sla_state: "on_track",
  exception_until: null,
  exception_reason: null,
  exception_by: null,
  first_seen_at: "2026-08-01T00:00:00Z",
  last_seen_at: "2026-08-18T00:00:00Z",
  sla_started_at: "2026-08-01T00:00:00Z",
  first_seen_run_id: "run_1",
  last_seen_run_id: "run_2",
  observation_count: 2,
  reopen_count: 0,
  closed_at: null,
  ticket_system: null,
  ticket_key: null,
  ticket_url: null,
};

const PAGE = {
  items: [VULN],
  total: 1,
  offset: 0,
  limit: 15,
  has_more: false,
};

const SUMMARY: VulnerabilitySummary = {
  total: 4,
  open_total: 3,
  untriaged: 2,
  unassigned: 2,
  estate_risk: "very_high",
  by_state: { OPEN: 2, FIXING: 1, CLOSED: 1 },
  by_severity_open: { critical: 1, high: 1, medium: 1, low: 0, unknown: 0 },
  by_risk_level_open: { very_low: 0, low: 0, moderate: 1, high: 1, very_high: 1 },
  by_sla: { on_track: 1, due_soon: 1, breached: 1, accepted: 0, none: 1 },
  breached: 1,
  worst_breached_severity: "critical",
  generated_at: "2026-08-18T00:00:00Z",
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

describe("useTrackedVulnerabilities", () => {
  it("returns the fetched page", async () => {
    vi.mocked(fetchTrackedVulnerabilities).mockResolvedValueOnce(PAGE);
    const { result } = renderHook(
      () => useTrackedVulnerabilities({ open_only: true }, { limit: 15 }),
      { wrapper },
    );
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(PAGE);
    expect(fetchTrackedVulnerabilities).toHaveBeenCalledWith({ open_only: true }, { limit: 15 });
  });
});

describe("useVulnerabilitySummary", () => {
  it("returns header counts", async () => {
    vi.mocked(fetchVulnerabilitySummary).mockResolvedValueOnce(SUMMARY);
    const { result } = renderHook(() => useVulnerabilitySummary(), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.breached).toBe(1);
  });
});

describe("useTransitionVulnerability", () => {
  it("posts the move and surfaces the new state", async () => {
    vi.mocked(transitionVulnerability).mockResolvedValueOnce({ ...VULN, state: "ACKNOWLEDGED" });
    const { result } = renderHook(() => useTransitionVulnerability("vuln_1"), { wrapper });
    result.current.mutate({ state: "ACKNOWLEDGED", note: "looking" });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(transitionVulnerability).toHaveBeenCalledWith("vuln_1", {
      state: "ACKNOWLEDGED",
      note: "looking",
    });
    expect(result.current.data?.state).toBe("ACKNOWLEDGED");
  });
});

describe("useAssignVulnerability", () => {
  it("sends only the assignment body", async () => {
    vi.mocked(assignVulnerability).mockResolvedValueOnce({ ...VULN, assignee: "ada" });
    const { result } = renderHook(() => useAssignVulnerability("vuln_1"), { wrapper });
    result.current.mutate({ assignee: "ada", owner_team: null });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(assignVulnerability).toHaveBeenCalledWith("vuln_1", {
      assignee: "ada",
      owner_team: null,
    });
  });
});
