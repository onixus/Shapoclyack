import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import CompliancePage from "@/app/(dashboard)/compliance/page";
import * as apiModule from "@/lib/api";
import type { CompliancePosture } from "@/lib/api";

function posture(overrides: Partial<CompliancePosture> = {}): CompliancePosture {
  return {
    framework_id: "pci-dss-4.0",
    name: "PCI DSS",
    version: "4.0",
    scope_note: "Covers the requirements this platform can produce evidence for.",
    generated_at: "2026-08-31T10:00:00Z",
    asset_count: 12,
    open_findings: 7,
    controls_total: 3,
    controls_assessed: 2,
    controls_passed: 1,
    controls_failed: 1,
    controls_not_assessed: 1,
    coverage_score: 50,
    controls: [
      {
        control_id: "6.3.3",
        title: "Security patches are installed within the defined window",
        status: "failed",
        rationale: "A critical finding past its SLA deadline.",
        signals: ["overdue_remediation"],
        combinations: [],
        severity_floor: "high",
        failing_count: 2,
        accepted_count: 1,
        evidence: [
          {
            kind: "finding",
            ref_id: "vln_1",
            label: "CVE-2024-0001",
            severity: "critical",
            detail: "asset a1, port 443",
            signals: ["overdue_remediation"],
            accepted: false,
          },
        ],
        not_assessed_reason: null,
      },
      {
        control_id: "12.5.1",
        title: "An inventory of in-scope system components is maintained",
        status: "not_assessed",
        rationale: "Assets with no classification.",
        signals: ["stale_asset"],
        combinations: [],
        severity_floor: "low",
        failing_count: 0,
        accepted_count: 0,
        evidence: [],
        not_assessed_reason: "no assets data in this tenant",
      },
    ],
    ...overrides,
  };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <CompliancePage />
    </QueryClientProvider>,
  );
}

describe("CompliancePage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(apiModule, "fetchComplianceFrameworks").mockResolvedValue([
      {
        framework_id: "pci-dss-4.0",
        name: "PCI DSS",
        version: "4.0",
        scope_note: "subset",
        control_count: 10,
      },
    ]);
  });

  it("shows the score as assessed controls and refuses to call it compliance", async () => {
    vi.spyOn(apiModule, "fetchCompliancePosture").mockResolvedValue(posture());
    renderPage();

    expect(await screen.findByText("1/2")).toBeInTheDocument();
    expect(screen.getByText("50%")).toBeInTheDocument();
    expect(
      screen.getByText(/not a statement of compliance with PCI DSS 4\.0/i),
    ).toBeInTheDocument();
  });

  it("expands a control to its evidence, and says why one was not assessed", async () => {
    vi.spyOn(apiModule, "fetchCompliancePosture").mockResolvedValue(posture());
    renderPage();

    const failing = await screen.findByText(
      "Security patches are installed within the defined window",
    );
    await userEvent.click(failing);
    await waitFor(() => expect(screen.getByText("CVE-2024-0001")).toBeInTheDocument());

    await userEvent.click(
      screen.getByText("An inventory of in-scope system components is maintained"),
    );
    expect(await screen.findByText(/no assets data in this tenant/i)).toBeInTheDocument();
  });

  it("does not present an unassessable estate as a pass", async () => {
    vi.spyOn(apiModule, "fetchCompliancePosture").mockResolvedValue(
      posture({
        controls_assessed: 0,
        controls_passed: 0,
        controls_failed: 0,
        coverage_score: null,
      }),
    );
    renderPage();

    expect(await screen.findByText("0/0")).toBeInTheDocument();
    expect(screen.queryByText("100%")).not.toBeInTheDocument();
  });
});
