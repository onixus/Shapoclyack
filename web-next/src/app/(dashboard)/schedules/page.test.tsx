import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import SchedulesPage from "@/app/(dashboard)/schedules/page";
import * as apiModule from "@/lib/api";
import type { Me, ScanSchedule } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { canOperate as canOperateIn } from "@/lib/authz";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

/** An account whose authority is the membership: globally a viewer, something
 * else in the tenant the console is scoped to (#318). */
function member(tenantRole: string, permissions: string[] = []): Me {
  return {
    username: `acme-${tenantRole}`,
    role: "viewer",
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: false,
    tenant_role: tenantRole,
    permissions,
    scoped_tenant: "default",
  };
}

const SCHEDULE: ScanSchedule = {
  schedule_id: "sch_1",
  tenant_id: "default",
  name: "nightly-external",
  enabled: true,
  cron: null,
  interval_seconds: 3600,
  scan_options: {
    mode: "balanced",
    delta: true,
    skip_nse: false,
    notify: false,
    export_defectdojo: false,
  },
  targets: { ranges: "10.0.0.0/24", domains: null, ports: null, ports_udp: null },
  next_run_at: null,
  last_run_at: null,
  last_job_id: null,
  created_at: null,
  created_by: null,
};

function renderPage(user: Me) {
  useAuthStore.setState({
    user,
    canOperate: canOperateIn(user),
    activeTenant: "default",
    hydrated: true,
    loading: false,
  });
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <SchedulesPage />
    </QueryClientProvider>,
  );
}

describe("SchedulesPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(apiModule, "fetchSchedules").mockResolvedValue({
      items: [SCHEDULE],
      total: 1,
      offset: 0,
      limit: 15,
      has_more: false,
    });
  });

  it("opens for a scan-operator, whose operator rank is the tenant's", async () => {
    // `require_tenant(Role.operator)` on every schedule route, and a
    // `scan-operator` is a `viewer` globally (#318) — so reading the account's
    // role shut this page against the role granted for running scans.
    renderPage(member("scan-operator", ["config.read", "scan.cancel"]));

    expect(await screen.findByText("nightly-external")).toBeInTheDocument();
    // Deleting one is the tenant admin's, which this is not.
    expect(screen.queryByRole("button", { name: /Delete schedule/i })).not.toBeInTheDocument();
  });

  it("gives the tenant's own admin the delete action, though the account is a viewer", async () => {
    // `PUT …/maintenance` and the delete are `require_tenant(Role.admin)`, and
    // the tenant's admin holds exactly that while being globally a viewer.
    renderPage(member("admin", ["audit.read", "tenant.member.read"]));

    expect(await screen.findByText("nightly-external")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Delete schedule/i })).toBeInTheDocument();
  });
});
