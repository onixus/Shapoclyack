import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import VulnerabilitiesPage from "@/app/(dashboard)/vulnerabilities/page";
import * as apiModule from "@/lib/api";
import type { TrackedVulnerability } from "@/lib/api";

let searchParams = new URLSearchParams();

vi.mock("next/navigation", () => ({
  useSearchParams: () => searchParams,
}));

function vuln(overrides: Partial<TrackedVulnerability> = {}): TrackedVulnerability {
  return {
    vuln_id: "vln_scan",
    tenant_id: "default",
    asset_id: "ast_1",
    finding_key: "k1",
    source: "scan",
    device_id: null,
    cve: "CVE-2024-0001",
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
    network_exposure: "external",
    network_exposure_source: "operator-set",
    state: "OPEN",
    state_changed_at: null,
    state_changed_by: null,
    assignee: null,
    owner_team: null,
    due_at: "2026-10-01T00:00:00Z",
    sla_days: 15,
    sla_source: "default",
    sla_state: "on_track",
    exception_until: null,
    exception_reason: null,
    exception_by: null,
    exception_state: "none",
    exception_requested_by: null,
    exception_requested_at: null,
    exception_requested_until: null,
    exception_decided_by: null,
    exception_decided_at: null,
    exception_decision_note: null,
    exception_requested_reason: null,
    exception_approved_at: null,
    exception_approved_requested_by: null,
    exception_expired_at: null,
    first_seen_at: "2026-09-01T00:00:00Z",
    last_seen_at: "2026-09-01T00:00:00Z",
    sla_started_at: "2026-09-01T00:00:00Z",
    first_seen_run_id: null,
    last_seen_run_id: null,
    observation_count: 1,
    reopen_count: 0,
    closed_at: null,
    ticket_system: null,
    ticket_key: null,
    ticket_url: null,
    ...overrides,
  };
}

const SOFTWARE = vuln({
  vuln_id: "vln_soft",
  source: "endpoint_software",
  device_id: "dev_1",
  cve: "CVE-2023-38545",
  // The API puts the upgrade in the title, because a software finding has no
  // port to locate it by.
  title: "curl 7.68.0-1ubuntu2.1 → 7.68.0-1ubuntu2.20",
  port: null,
});

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <VulnerabilitiesPage />
    </QueryClientProvider>,
  );
}

describe("Vulnerability Center", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    searchParams = new URLSearchParams();
    vi.spyOn(apiModule, "fetchVulnerabilitySummary").mockResolvedValue({
      total: 1,
      open_total: 1,
      untriaged: 1,
      unassigned: 1,
      estate_risk: "very_high",
      by_state: { OPEN: 1 },
      by_severity_open: { critical: 1 },
      by_risk_level_open: { very_high: 1 },
      by_sla: { on_track: 1 },
      breached: 0,
      worst_breached_severity: null,
      generated_at: "2026-09-08T00:00:00Z",
    });
  });

  it("shows an installed package where a software finding has no port", async () => {
    vi.spyOn(apiModule, "fetchTrackedVulnerabilities").mockResolvedValue({
      items: [SOFTWARE],
      total: 1,
      offset: 0,
      limit: 25,
      has_more: false,
    });
    renderPage();

    expect(await screen.findByText("CVE-2023-38545")).toBeInTheDocument();
    expect(
      screen.getByText("curl 7.68.0-1ubuntu2.1 → 7.68.0-1ubuntu2.20"),
    ).toBeInTheDocument();
    // Never "no port": the absence of a port is a property of the finding
    // kind, not missing data about it.
    expect(screen.queryByText("no port")).not.toBeInTheDocument();
    expect(screen.getByText("endpoint")).toBeInTheDocument();
  });

  it("keeps the port on a scan finding", async () => {
    vi.spyOn(apiModule, "fetchTrackedVulnerabilities").mockResolvedValue({
      items: [vuln()],
      total: 1,
      offset: 0,
      limit: 25,
      has_more: false,
    });
    renderPage();

    expect(await screen.findByText("port 443")).toBeInTheDocument();
    expect(screen.getByText("scan")).toBeInTheDocument();
  });

  it("asks for every source by default", async () => {
    const fetchSpy = vi
      .spyOn(apiModule, "fetchTrackedVulnerabilities")
      .mockResolvedValue({ items: [], total: 0, offset: 0, limit: 25, has_more: false });
    renderPage();
    await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
    expect(fetchSpy.mock.calls[0][0]).toMatchObject({ source: "" });
  });

  it("carries a ?source= deep link into the query", async () => {
    // How the endpoint panel and the estate views link into a filtered
    // Vulnerability Center, so the parameter has to survive the round trip.
    searchParams = new URLSearchParams({ source: "endpoint_software" });
    const fetchSpy = vi
      .spyOn(apiModule, "fetchTrackedVulnerabilities")
      .mockResolvedValue({ items: [], total: 0, offset: 0, limit: 25, has_more: false });
    renderPage();

    await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
    expect(fetchSpy.mock.calls[0][0]).toMatchObject({ source: "endpoint_software" });
  });
});
