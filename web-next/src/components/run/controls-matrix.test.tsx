import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ControlsMatrix } from "@/components/run/controls-matrix";
import * as apiModule from "@/lib/api";
import type { OrgProfileControlsSummary } from "@/lib/api";

const mockSummary: OrgProfileControlsSummary = {
  overall_verdict: "fail",
  overall_risk: "high",
  evaluated_at: "2026-08-30T10:00:00Z",
  controls: [
    {
      control: "dns_structure",
      title: "DNS структура",
      status: "ok",
      impact: "medium",
      risk_level: "very_low",
      coverage: { checked: 5, total: 5 },
      findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
      top_findings: [],
      evidence: ["dns_hygiene.json"],
      why: "All 5 domains passed DNS hygiene checks",
    },
    {
      control: "mail_protection",
      title: "Почтовая защита",
      status: "fail",
      impact: "high",
      risk_level: "high",
      coverage: { checked: 2, total: 2 },
      findings_by_severity: { critical: 0, high: 2, medium: 1, low: 0 },
      top_findings: [
        {
          id: "dmarc_policy_none",
          domain: "example.com",
          severity: "high",
          detail: "DMARC policy is none",
        },
      ],
      evidence: ["mail_posture.json"],
      why: "2 high/critical mail posture issues (SPF/DMARC/MX)",
    },
    {
      control: "credential_leaks",
      title: "Утечки учетных данных",
      status: "not_checked",
      impact: "critical",
      risk_level: "unassessed",
      coverage: { checked: 0, total: 0 },
      findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
      top_findings: [],
      evidence: [],
      why: "Credential leaks check was not configured or run",
    },
  ],
};

function renderWithQuery(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });
  return render(<QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>);
}

describe("ControlsMatrix Component", () => {
  it("renders the posture overview and control rows", async () => {
    vi.spyOn(apiModule, "fetchRunControls").mockResolvedValue(mockSummary);

    renderWithQuery(<ControlsMatrix runId="run-test-123" />);

    expect(await screen.findByText("Organization Security Posture Matrix")).toBeInTheDocument();
    expect(screen.getByText("DNS структура")).toBeInTheDocument();
    expect(screen.getByText("Почтовая защита")).toBeInTheDocument();
    expect(screen.getByText("Утечки учетных данных")).toBeInTheDocument();

    expect(screen.getAllByText("FAIL").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("OK").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("NOT CHECKED").length).toBeGreaterThanOrEqual(1);
  });

  it("expands control row details on click", async () => {
    vi.spyOn(apiModule, "fetchRunControls").mockResolvedValue(mockSummary);

    renderWithQuery(<ControlsMatrix runId="run-test-123" />);

    const mailRow = await screen.findByText("Почтовая защита");
    fireEvent.click(mailRow);

    expect(screen.getByText("dmarc_policy_none")).toBeInTheDocument();
    expect(screen.getByText(/DMARC policy is none/)).toBeInTheDocument();
    expect(screen.getByText("mail_posture.json")).toBeInTheDocument();
  });

  it("renders empty/fallback state when controls are unavailable", async () => {
    vi.spyOn(apiModule, "fetchRunControls").mockRejectedValue(new Error("Not found"));

    renderWithQuery(<ControlsMatrix runId="run-missing" />);

    expect(
      await screen.findByText(/Controls matrix telemetry is not available for this run/i)
    ).toBeInTheDocument();
  });
});
