import { useAppearanceStore } from "@/lib/appearance";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import RunDetailPage from "@/app/(dashboard)/runs/view/page";
import type { Me } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { canOperate as canOperateIn } from "@/lib/authz";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams("runId=run-a&tab=screenshots"),
}));
vi.mock("@/hooks/use-run-report", () => ({
  useRunReport: () => ({
    detail: { run_id: "run-a", artifacts: [] },
    filters: { host: null, port: null, severity: "all" },
    hosts: [],
    ports: [],
    vulns: [],
    grouped: {},
    severityCounts: {},
  }),
}));
vi.mock("@/components/run/run-metrics", () => ({ RunMetrics: () => null }));
vi.mock("@/components/run/severity-filter", () => ({ SeverityFilter: () => null }));
vi.mock("@/components/run/findings-list", () => ({
  FindingsList: () => <div>Existing findings</div>,
}));
vi.mock("@/components/run/controls-matrix", () => ({ ControlsMatrix: () => null }));
vi.mock("@/components/run/related-domains", () => ({ RelatedDomainsPanel: () => null }));
vi.mock("@/components/run/artifacts-panel", () => ({ ArtifactsPanel: () => null }));
vi.mock("@/components/run/screenshots-panel", () => ({
  ScreenshotsPanel: () => <div>Screenshot gallery</div>,
}));

function member(tenantRole: string): Me {
  return {
    username: `acme-${tenantRole}`,
    role: "viewer",
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: false,
    tenant_role: tenantRole,
    permissions: [],
    scoped_tenant: "default",
  };
}

function signIn(user: Me | null) {
  useAuthStore.setState({
    user,
    canOperate: user ? canOperateIn(user) : false,
    activeTenant: "default",
    hydrated: true,
    loading: false,
  });
}

describe("RunDetailPage screenshot tab", () => {
  beforeEach(() => {
    useAppearanceStore.setState({ locale: "en" });
    signIn(member("viewer"));
  });

  it("translates run headings and tabs without changing tab routing", () => {
    useAppearanceStore.setState({ locale: "ru" });
    render(<RunDetailPage />);
    expect(screen.getByRole("heading", { name: /Прогон run-a/ })).toBeVisible();
    expect(screen.getByRole("tab", { name: /Находки/ })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: /Хосты/ })).toBeVisible();
    expect(screen.getByRole("tab", { name: /Порты/ })).toBeVisible();
    expect(screen.getByRole("tab", { name: /Файлы отчёта/ })).toBeVisible();
  });

  it("redirects a viewer with ?tab=screenshots to findings and does not mount the fetch", () => {
    render(<RunDetailPage />);
    expect(screen.queryByRole("tab", { name: /screenshots/i })).not.toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /findings/i })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("Existing findings")).toBeVisible();
    expect(screen.queryByText("Screenshot gallery")).not.toBeInTheDocument();
  });

  it("shows the screenshots tab to an operator", () => {
    signIn(member("operator"));
    render(<RunDetailPage />);
    expect(screen.getByRole("tab", { name: /screenshots/i })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("Screenshot gallery")).toBeVisible();
  });
});
