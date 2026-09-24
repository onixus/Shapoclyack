import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ScanOperations } from "@/components/scans/scan-operations";
import * as apiModule from "@/lib/api";
import type { AgentFleetSummary, Me, SystemStatus } from "@/lib/api";
import { useAppearanceStore } from "@/lib/appearance";
import { useAuthStore } from "@/lib/auth-store";
import { canOperate as canOperateIn } from "@/lib/authz";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));

function member(role: string, permissions: string[], global: Me["role"] = "viewer"): Me {
  return {
    username: "on-call",
    role: global,
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: false,
    tenant_role: role,
    permissions,
    scoped_tenant: "default",
  };
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <ScanOperations surface={null} />
    </QueryClientProvider>,
  );
}

const DENIED = /role privileges required/i;

describe("ScanOperations access", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuthStore.setState({ user: null, canOperate: false });
  });

  it("keeps the page shut for a viewer", () => {
    useAuthStore.setState({ user: member("viewer", []), canOperate: false });
    renderPage();
    expect(screen.getByText(DENIED)).toBeInTheDocument();
  });

  it("opens for a scan-operator, whose global role is viewer", () => {
    // The API gates `GET /api/jobs` on the operator rank *in the tenant*, which
    // a `scan-operator` has (#318); the console gated it on the global role and
    // so hid the whole page — and with it the Cancel button docs/ui.md promises
    // — from the role the permission exists for. `canOperate` is set the way
    // the store sets it, so what is pinned is the page, not a hand-built flag.
    const user = member("scan-operator", ["scan.cancel"]);
    useAuthStore.setState({ user, canOperate: canOperateIn(user) });
    renderPage();
    expect(screen.queryByText(DENIED)).not.toBeInTheDocument();
  });

  // The one control on this page that is *not* about the active tenant: it
  // links to /tenants, whose two listings hang off `require_role` on the
  // account. Asking `role === "admin"` there hid it from a global operator the
  // API serves, and showed it to a tenant admin the API answers 403 to.
  it("shows the scope link to a global operator", () => {
    const operator = member("operator", ["config.read", "scan.cancel"], "operator");
    useAuthStore.setState({ user: operator, canOperate: canOperateIn(operator) });
    renderPage();
    expect(screen.getByRole("link", { name: /Manage scope/i })).toBeInTheDocument();
  });

  it("hides the scope link from a tenant admin whose account is a viewer", () => {
    const tenantAdmin = member("admin", ["audit.read"]);
    useAuthStore.setState({ user: tenantAdmin, canOperate: canOperateIn(tenantAdmin) });
    renderPage();
    expect(screen.queryByRole("link", { name: /Manage scope/i })).not.toBeInTheDocument();
  });
});

describe("ScanOperations with no sensor", () => {
  const operator = member("operator", ["config.read", "scan.cancel"], "operator");

  function agentMode(): SystemStatus {
    return {
      app_version: "0.46",
      tools: [],
      enrichment: [],
      scan_config: { profiles: [], nse_profiles: [], stages: {} },
      runtime: { allow_scan_start: true, job_execution_mode: "agent" },
      inventory: { tenants: 1, agents_total: 0, agents_online: 0 },
      endpoint_inventory: {
        enabled: false,
        devices_total: null,
        devices_stale: null,
        stale_hours: 24,
        retention_enabled: false,
        snapshot_retention_days: 30,
        change_retention_days: 90,
        retention_interval_seconds: 3600,
        retention_last_run_at: null,
      },
    } as unknown as SystemStatus;
  }

  function fleet(ready: number): AgentFleetSummary {
    return {
      total_agents: ready,
      online_agents: ready,
      scan_ready_agents: ready,
      busy_agents: 0,
      stale_agents: 0,
      error_agents: 0,
      outdated_agents: 0,
      latest_version: "",
      by_tenant: {},
    } as AgentFleetSummary;
  }

  beforeEach(() => {
    vi.restoreAllMocks();
    useAppearanceStore.setState({ locale: "en" });
    useAuthStore.setState({ user: operator, canOperate: canOperateIn(operator) });
    vi.spyOn(apiModule, "fetchSystemStatus").mockResolvedValue(agentMode());
  });

  // Agent mode accepts and queues a scan whether or not anything can run it.
  // Before an executor is enrolled — or for a tenant whose key it does not
  // hold, or after that key expires — the page used to look exactly like a
  // busy queue (#338).
  it("says so above the launcher", async () => {
    vi.spyOn(apiModule, "fetchAgentSummary").mockResolvedValue(fleet(0));
    renderPage();
    expect(await screen.findByText(/No sensor of this tenant is online/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open Sensor Fleet" })).toHaveAttribute("href", "/agents");
  });

  it("says nothing once one is online", async () => {
    const summary = vi.spyOn(apiModule, "fetchAgentSummary").mockResolvedValue(fleet(1));
    renderPage();
    await waitFor(() => expect(summary).toHaveBeenCalled());
    expect(screen.queryByText(/No sensor of this tenant is online/)).toBeNull();
  });
});
