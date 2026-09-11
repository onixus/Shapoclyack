import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import TenantsPage from "@/app/(dashboard)/tenants/page";
import * as apiModule from "@/lib/api";
import type { Me, TenantInfo } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { canOperate as canOperateIn } from "@/lib/authz";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

/** `role` is the account's and `tenant_role` is the membership's — the whole
 * distinction this page turns on. */
function principal(role: Me["role"], tenantRole: string, permissions: string[] = []): Me {
  return {
    username: "someone",
    role,
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: false,
    tenant_role: tenantRole,
    permissions,
    scoped_tenant: "default",
  };
}

function tenant(overrides: Partial<TenantInfo> = {}): TenantInfo {
  return {
    tenant_id: "default",
    name: "Default",
    status: "active",
    created_at: "2026-09-01T10:00:00Z",
    ...overrides,
  };
}

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
      <TenantsPage />
    </QueryClientProvider>,
  );
}

const DENIED = /Operator or admin role required/i;

describe("TenantsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(apiModule, "fetchTenants").mockResolvedValue([tenant()]);
    vi.spyOn(apiModule, "fetchTenantPosture").mockResolvedValue([]);
  });

  // This is the one page in the console that must **not** read the membership
  // (#318). Both listings behind it — `GET /api/tenants` and
  // `/api/tenants/posture` — resolve their own tenant set and hang off
  // `require_role` on the account, so the tenant role answers a question the
  // API never asks.
  it("refuses a tenant admin whose account is a viewer, as the API does", async () => {
    renderPage(principal("viewer", "admin", ["audit.read", "tenant.member.read"]));

    expect(await screen.findByText(DENIED)).toBeInTheDocument();
    expect(apiModule.fetchTenants).not.toHaveBeenCalled();
  });

  it("lists for a global operator who is only a viewer in this tenant", async () => {
    renderPage(principal("operator", "viewer", []));

    expect(await screen.findByText("Default")).toBeInTheDocument();
    expect(screen.queryByText(DENIED)).not.toBeInTheDocument();
    // Creating one is `platform.tenant.manage` — the global admin's alone.
    expect(screen.queryByRole("button", { name: /Create New Tenant/i })).not.toBeInTheDocument();
  });

  it("offers creation to the global admin", async () => {
    renderPage(principal("admin", "viewer", []));

    expect(await screen.findByText("Default")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Create New Tenant/i })).toBeInTheDocument();
  });
});
