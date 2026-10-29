import type { ReactNode } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import DashboardPage from "./page";
import { useAppearanceStore } from "@/lib/appearance";

vi.mock("@tremor/react", () => ({
  Card: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  Title: ({ children }: { children: ReactNode }) => <h2>{children}</h2>,
  AreaChart: (props: unknown) => <div data-testid="area-chart">{JSON.stringify(props)}</div>,
  BarChart: (props: unknown) => <div data-testid="bar-chart">{JSON.stringify(props)}</div>,
  DonutChart: () => <div />,
}));
vi.mock("@/components/dashboard/scan-ops-panel", () => ({ ScanOpsPanel: () => null }));
vi.mock("@/components/org-profile/posture-tile", () => ({ OrgPostureTile: () => null }));
const trigger = vi.fn();
vi.mock("@/hooks/use-vulnerabilities", () => ({
  useTriggerRiskSnapshot: () => ({ mutate: trigger, isPending: false }),
  useRiskHistory: () => ({
    data: [
      {
        recorded_at: "2026-10-28T12:00:00Z",
        open_total: 26,
        by_severity_open: { critical: 1, high: 2 },
        breached: 4,
      },
    ],
  }),
  useVulnerabilitySummary: () => ({
    data: {
      total: 26,
      open_total: 26,
      estate_risk: "moderate",
      untriaged: 26,
      unassigned: 26,
      by_severity_open: { high: 2 },
      by_risk_level_open: { moderate: 26 },
      breached: 0,
    },
    refetch: vi.fn(),
  }),
  useTrackedVulnerabilities: () => ({
    data: {
      items: [
        {
          vuln_id: "vln_1",
          tenant_id: "default",
          asset_id: "asset_1",
          title: "EternalBlue (SMBv1 RCE)",
          script_id: "pulse:exposure:445:eternalblue-smbv1-rce",
          cve: null,
          risk_level: "moderate",
          sla_state: "on_track",
          severity: "medium",
          due_at: null,
          assignee: null,
        },
      ],
    },
    refetch: vi.fn(),
  }),
}));
vi.mock("@/hooks/use-assets", () => ({
  useAssetSummary: () => ({
    data: { total: 3, unowned: 2, by_status: { active: 3 }, by_criticality: { "1": 3 } },
    refetch: vi.fn(),
  }),
}));
vi.mock("@/hooks/use-runs", () => ({
  useRuns: () => ({
    data: {
      items: [
        {
          run_id: "run_1",
          started_at: "2026-10-28T12:00:00Z",
          has_summary: true,
          alive_hosts: 7,
          potential_vulnerabilities: 8,
        },
      ],
    },
    refetch: vi.fn(),
  }),
}));
beforeEach(() => {
  useAppearanceStore.setState({ locale: "ru" });
  trigger.mockClear();
});
afterEach(() => useAppearanceStore.setState({ locale: "en" }));
describe("Russian risk overview", () => {
  it("shows a readable finding name and keeps the source and identifiers in collapsed details", async () => {
    render(<DashboardPage />);
    const link = screen.getByRole("link", {
      name: "Доступен SMB: проверьте защиту от EternalBlue",
    });
    expect(link).toHaveAttribute("href", "/vulnerabilities/view?vulnId=vln_1");
    const technical = screen.getByText("pulse:exposure:445:eternalblue-smbv1-rce");
    expect(technical).not.toBeVisible();
    expect(screen.getByText("EternalBlue (SMBv1 RCE)")).not.toBeVisible();
    await userEvent.click(screen.getByText("Технические данные"));
    expect(technical).toBeVisible();
    expect(screen.getByText("asset_1")).toBeVisible();
    expect(screen.getByRole("link", { name: "Карточка актива" })).toHaveAttribute(
      "href",
      "/assets/view?assetId=asset_1",
    );
    expect(screen.getByRole("columnheader", { name: "Риск" })).toBeInTheDocument();
  });
  it("translates chart legends and leaves counts and snapshot actions unchanged", () => {
    render(<DashboardPage />);
    const charts = screen.getAllByTestId("area-chart").map((n) => JSON.parse(n.textContent!));
    expect(charts[0].categories).toEqual([
      "Открытые находки",
      "Критические и высокие",
      "Нарушения SLA",
    ]);
    expect(charts[0].data[0]).toMatchObject({
      "Открытые находки": 26,
      "Критические и высокие": 3,
      "Нарушения SLA": 4,
    });
    expect(charts[1].categories).toEqual(["Хосты", "Находки"]);
    expect(charts[1].data[0]).toMatchObject({ Хосты: 7, Находки: 8 });
    expect(JSON.parse(screen.getByTestId("bar-chart").textContent!).categories).toEqual(["Активы"]);
    expect(screen.getByRole("button", { name: "Сохранить снимок риска" })).toBeInTheDocument();
    expect(screen.getByText(/Отсутствие данных не означает/)).toBeInTheDocument();
    expect(trigger).not.toHaveBeenCalled();
  });
  it("retains the English interface when English is selected", () => {
    useAppearanceStore.setState({ locale: "en" });
    render(<DashboardPage />);
    expect(screen.getByRole("button", { name: "Capture Snapshot" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Risk" })).toBeInTheDocument();
    expect(JSON.parse(screen.getAllByTestId("area-chart")[0].textContent!).categories).toEqual([
      "Open Vulns",
      "Critical & High",
      "SLA Breached",
    ]);
  });
});
