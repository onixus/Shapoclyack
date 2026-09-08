import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AdoptionPage from "@/app/(dashboard)/adoption/page";
import { hours, scanHistoryReason, scopeReason, share } from "@/lib/adoption-format";
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
      false_positive_in_window: 3,
      machine_verified_closed: 6,
      machine_verified_share: 75,
      closed_within_sla_share: 62.5,
      mttr_hours: 96,
      mttr_hours_by_severity: { critical: 20, high: 96, medium: null, low: null, info: null, unknown: null },
      reopened_share: 5,
      open_per_asset: 0.4,
    },
    false_positives: {
      in_window: 3,
      share_of_closures: 27.3,
      by_severity: { critical: 0, high: 1, medium: 2, low: 0, info: 0, unknown: 0 },
      by_source: [
        { source: "ssl-dh-params", closed: 40, false_positive: 12, false_positive_share: 30 },
        { source: "unknown", closed: 3, false_positive: 1, false_positive_share: null },
      ],
      by_origin: [
        {
          source: "endpoint_software",
          closed: 30,
          false_positive: 11,
          false_positive_share: 36.7,
        },
        { source: "scan", closed: 25, false_positive: 0, false_positive_share: 0 },
      ],
      source_threshold: 20,
      suppressions_active: 5,
      suppressions_lapsed: 2,
      overridden_in_window: 1,
      median_hours_to_verdict: 18,
    },
    coverage: {
      coverage_days: 30,
      assets_with_scan_history: 27,
      scan_history_share: 90,
      scan_history_reason: null,
      scanned_share: 90,
      vuln_scanned_share: 70,
      approved_entries: 5,
      denied_entries: 1,
      measurable_entries: 5,
      unmeasurable_entries: [],
      scope_covered_entries: 4,
      scope_covered_share: 80,
      scope_uncovered_entries: ["10.9.0.0/24"],
      scope_unbounded_reason: null,
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

  it("says why a coverage share is absent, because n/a alone does not", () => {
    // "No share" and "0% covered" print the same dash and mean the opposite
    // things; the reason is the only thing separating them for the reader.
    expect(scopeReason("no_measurable_scope")).toMatch(/wildcard or a domain suffix/i);
    expect(scopeReason("no_scope")).toMatch(/nothing has been approved/i);
    // A scope share riding on columns that have not filled in is withheld for
    // the scan block's reason, and says so rather than borrowing a scope one.
    expect(scopeReason("no_scan_history")).toMatch(/no coverage data/i);
    expect(scanHistoryReason("partial_scan_history")).toMatch(/too few assets/i);
    expect(scopeReason(null)).toBeNull();
    expect(scopeReason("something-new")).toBeNull();
    expect(scanHistoryReason("something-new")).toBeNull();
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
          false_positive_in_window: 0,
          machine_verified_closed: 0,
          machine_verified_share: null,
          closed_within_sla_share: null,
          mttr_hours: null,
          mttr_hours_by_severity: {},
          reopened_share: null,
          open_per_asset: null,
        },
        // An estate with nothing closed and nothing scanned: every share here
        // has no denominator, and none of them may render as a number.
        false_positives: {
          in_window: 0,
          share_of_closures: null,
          by_severity: {},
          by_source: [],
          by_origin: [],
          source_threshold: 20,
          suppressions_active: 0,
          suppressions_lapsed: 0,
          overridden_in_window: 0,
          median_hours_to_verdict: null,
        },
        coverage: {
          coverage_days: 30,
          assets_with_scan_history: 0,
          scan_history_share: null,
          scan_history_reason: "no_scan_history",
          scanned_share: null,
          vuln_scanned_share: null,
          approved_entries: 0,
          denied_entries: 0,
          measurable_entries: 0,
          unmeasurable_entries: [],
          scope_covered_entries: null,
          scope_covered_share: null,
          scope_uncovered_entries: [],
          scope_unbounded_reason: "no_scope",
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

  it("keeps noise out of the closure count and names the noisy observer", async () => {
    vi.spyOn(apiModule, "fetchAdoption").mockResolvedValue(metrics());
    renderPage();

    // The Closed card counts remediation only, and says where the rest went —
    // otherwise mass false-positive marking reads as a productive quarter.
    expect(await screen.findByText(/3 closed as noise are counted under Noise/)).toBeInTheDocument();
    expect(screen.getByText("ssl-dh-params")).toBeInTheDocument();
    expect(screen.getByText("endpoint_software")).toBeInTheDocument();
    // The quiet observer is listed too, or the noisy one has nothing to be
    // compared against.
    expect(screen.getByText("scan")).toBeInTheDocument();
    // Suppressions that expired are a review queue, and it is on the page.
    expect(screen.getByText(/2 have expired and are waiting/)).toBeInTheDocument();
  });

  it("withholds a detector's rate below the observation threshold", async () => {
    vi.spyOn(apiModule, "fetchAdoption").mockResolvedValue(metrics());
    renderPage();

    // "unknown" has 1 verdict out of 3 closures — 33% would be a number about
    // nothing, so the row shows its counts and no rate.
    // "unknown" is also a severity bucket on this page, so pick the cell that
    // is actually in the detector table.
    const cells = await screen.findAllByText("unknown");
    const row = cells.map((cell) => cell.closest("tr")).find((node) => node !== null);
    expect(row).toBeDefined();
    expect(row!).toHaveTextContent("n/a");
    expect(screen.getByText(/at least 20 closures behind it/)).toBeInTheDocument();
  });

  it("names the approved ranges nothing has reached, which is the actionable half", async () => {
    vi.spyOn(apiModule, "fetchAdoption").mockResolvedValue(metrics());
    renderPage();

    expect(await screen.findByText("10.9.0.0/24")).toBeInTheDocument();
    expect(
      screen.getByText(/4 of 5 approved ranges contain an asset a scan reached/),
    ).toBeInTheDocument();
  });

  it("explains an unmeasurable scope instead of printing a coverage number", async () => {
    vi.spyOn(apiModule, "fetchAdoption").mockResolvedValue(
      metrics({
        coverage: {
          coverage_days: 30,
          assets_with_scan_history: 27,
          scan_history_share: 90,
          scan_history_reason: null,
          scanned_share: 90,
          vuln_scanned_share: 70,
          approved_entries: 1,
          denied_entries: 0,
          measurable_entries: 0,
          unmeasurable_entries: ["example.com"],
          scope_covered_entries: null,
          scope_covered_share: null,
          scope_uncovered_entries: [],
          scope_unbounded_reason: "no_measurable_scope",
        },
      }),
    );
    renderPage();

    expect(
      await screen.findByText(/wildcard or a domain suffix, and neither is an address space/i),
    ).toBeInTheDocument();
    // ...and the entry it could not measure is named rather than silently
    // dropped out of the denominator.
    expect(screen.getByText("example.com")).toBeInTheDocument();
  });
});
