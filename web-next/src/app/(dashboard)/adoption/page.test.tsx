import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AdoptionPage, { hours, share } from "@/app/(dashboard)/adoption/page";
import * as apiModule from "@/lib/api";
import type { AdoptionMetrics } from "@/lib/api";

function metrics(overrides: Partial<AdoptionMetrics> = {}): AdoptionMetrics {
  return {
    tenant_id: "default",
    window_days: 90,
    generated_at: "2026-09-02T10:00:00Z",
    findings: {
      open: 12,
      accepted_open: 2,
      closed_in_window: 8,
      machine_verified_closed: 6,
      machine_verified_share: 75,
      closed_within_sla_share: 62.5,
      mttr_hours: 96,
      mttr_hours_by_severity: { critical: 20, high: 96, medium: null, low: null, info: null, unknown: null },
      reopened_share: 5,
      open_per_asset: 0.4,
    },
    assets: {
      active: 30,
      with_owner_share: 40,
      with_context_share: 20,
      scanned_recently_share: 90,
      dual_source_share: 10,
      coverage_days: 30,
      unowned: 18,
    },
    analysts: [
      { analyst: "alice", closed: 5, machine_verified: 5 },
      { analyst: "unassigned", closed: 3, machine_verified: 1 },
    ],
    onboarding: {
      tenant_created_at: "2026-06-01T00:00:00Z",
      first_successful_scan_at: "2026-06-01T02:00:00Z",
      first_tracked_finding_at: "2026-06-01T02:30:00Z",
      hours_to_first_scan: 2,
      hours_to_first_finding: 2.5,
    },
    enrichment: [
      { name: "epss", present: true, age_days: 3.2, stale: false },
      { name: "kev", present: true, age_days: 40, stale: true },
      { name: "geoip", present: false, age_days: null, stale: false },
    ],
    ...overrides,
  };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <AdoptionPage />
    </QueryClientProvider>,
  );
}

describe("share and hours formatting", () => {
  it("never turns an absent denominator into a percentage", () => {
    expect(share(null)).toBe("n/a");
    expect(share(0)).toBe("0%");
    expect(share(100)).toBe("100%");
  });

  it("switches to days past two of them", () => {
    expect(hours(null)).toBe("n/a");
    expect(hours(20)).toBe("20 h");
    expect(hours(96)).toBe("4 d");
  });
});

describe("AdoptionPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows outcomes, the per-analyst table and overlay staleness", async () => {
    vi.spyOn(apiModule, "fetchAdoption").mockResolvedValue(metrics());
    renderPage();

    expect(await screen.findByText("75%")).toBeInTheDocument();
    expect(screen.getByText("62.5%")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByText(/18 of 30 active assets/)).toBeInTheDocument();
    expect(screen.getByText("40 d, stale")).toBeInTheDocument();
    expect(screen.getByText("missing")).toBeInTheDocument();
  });

  it("reports an empty estate as n/a rather than as 0% or 100%", async () => {
    vi.spyOn(apiModule, "fetchAdoption").mockResolvedValue(
      metrics({
        findings: {
          open: 0,
          accepted_open: 0,
          closed_in_window: 0,
          machine_verified_closed: 0,
          machine_verified_share: null,
          closed_within_sla_share: null,
          mttr_hours: null,
          mttr_hours_by_severity: {},
          reopened_share: null,
          open_per_asset: null,
        },
        analysts: [],
      }),
    );
    renderPage();

    expect(await screen.findByText(/nobody to attribute a closure to/i)).toBeInTheDocument();
    expect(screen.queryByText("0%")).not.toBeInTheDocument();
    expect(screen.queryByText("100%")).not.toBeInTheDocument();
    expect(screen.getAllByText("n/a").length).toBeGreaterThanOrEqual(3);
  });
});
