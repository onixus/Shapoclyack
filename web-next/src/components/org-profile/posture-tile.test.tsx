import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  OrgPostureTile,
  orgProfileHref,
  postureCounts,
  postureVerdict,
} from "@/components/org-profile/posture-tile";
import * as apiModule from "@/lib/api";
import type { OrgProfileControlsSummary } from "@/lib/api";

function control(
  overrides: Partial<apiModule.ControlItem> & { control: string },
): apiModule.ControlItem {
  return {
    title: overrides.control,
    status: "ok",
    impact: "medium",
    risk_level: "very_low",
    coverage: { checked: 1, total: 1 },
    findings_by_severity: {},
    top_findings: [],
    evidence: [],
    why: "",
    ...overrides,
  };
}

const summary: OrgProfileControlsSummary = {
  overall_verdict: "fail",
  overall_risk: "high",
  evaluated_at: "2026-08-30T10:00:00Z",
  controls: [
    control({ control: "dns_structure", status: "ok" }),
    control({ control: "mail_protection", status: "fail" }),
    control({ control: "credential_leaks", status: "not_checked" }),
  ],
};

function renderWithQuery(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>);
}

describe("org posture tile", () => {
  it("percent-encodes the run id in the link", () => {
    expect(orgProfileHref("run/1 x")).toBe("/org-profile?runId=run%2F1%20x");
  });

  it("reports a missing matrix as not_checked, never as ok", () => {
    // The module invariant: absence of data is "requires a check", not a pass.
    expect(postureVerdict(undefined)).toBe("not_checked");
    expect(postureCounts(undefined)).toEqual({ failing: 0, total: 0, notChecked: 0 });
  });

  it("counts failing and unchecked controls", () => {
    expect(postureCounts(summary)).toEqual({ failing: 1, total: 3, notChecked: 1 });
  });

  it("renders the verdict of the newest run", async () => {
    vi.spyOn(apiModule, "fetchRunControls").mockResolvedValue(summary);

    renderWithQuery(<OrgPostureTile runId="run-1" />);

    expect(await screen.findByText("fail")).toBeInTheDocument();
    expect(screen.getByText(/1 of 3 controls failing/)).toBeInTheDocument();
  });

  it("falls back to not checked when the run has no controls artifact", async () => {
    vi.spyOn(apiModule, "fetchRunControls").mockRejectedValue(new Error("Not found"));

    renderWithQuery(<OrgPostureTile runId="run-missing" />);

    expect(await screen.findByText("not checked")).toBeInTheDocument();
    expect(screen.getByText(/org_profile stage not evaluated/)).toBeInTheDocument();
  });

  it("says so when there is no run at all", () => {
    renderWithQuery(<OrgPostureTile runId="" />);

    expect(screen.getByText("not checked")).toBeInTheDocument();
    expect(screen.getByText("no runs yet")).toBeInTheDocument();
  });
});
