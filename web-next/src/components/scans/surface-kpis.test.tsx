import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SurfaceKpis } from "@/components/scans/surface-kpis";
import * as apiModule from "@/lib/api";
import type { Me } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

function principal(role: Me["role"], tenantRole: string, permissions?: string[]): Me {
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

function renderKpis(user: Me) {
  useAuthStore.setState({ user, activeTenant: "default", hydrated: true, loading: false });
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <SurfaceKpis surface="external" canOperate />
    </QueryClientProvider>,
  );
}

describe("SurfaceKpis scope card", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // An empty scope is an answer — the tenant scans nothing — so the card
    // renders either way; what is under test is whether it is asked for.
    vi.spyOn(apiModule, "fetchScanScope").mockResolvedValue([]);
    vi.spyOn(apiModule, "fetchPromotedDomains").mockResolvedValue([]);
  });

  // The two reads behind this card are gated on the named permission
  // `scan_scope.read`, not on a rank (api/routes/tenants.py). Gating the card
  // on `user.role === "admin"` asked a third question again — and the roles
  // that exist to read a scope are read-only accounts.
  it("shows the scope card to an auditor, who is nobody's admin", async () => {
    renderKpis(principal("viewer", "auditor", ["audit.read", "scan_scope.read"]));

    expect(await screen.findByText("Approved domains")).toBeInTheDocument();
    expect(apiModule.fetchScanScope).toHaveBeenCalled();
  });

  it("shows it to the tenant's own admin, whose account is a viewer", async () => {
    renderKpis(
      principal("viewer", "admin", ["audit.read", "scan_scope.read", "tenant.member.read"]),
    );

    expect(await screen.findByText("Approved domains")).toBeInTheDocument();
  });

  it("hides it from a scan-operator, who may run scans and not read the scope", async () => {
    renderKpis(principal("viewer", "scan-operator", ["config.read", "scan.cancel"]));

    expect(await screen.findByText("Endpoints inventoried")).toBeInTheDocument();
    expect(screen.queryByText("Approved domains")).not.toBeInTheDocument();
    expect(apiModule.fetchScanScope).not.toHaveBeenCalled();
  });

  it("keeps the pre-#318 answer when the API sends no permission list", async () => {
    // No list is an API older than #318, not "holds nothing": the card has to
    // keep rendering for the global admin it used to render for.
    renderKpis(principal("admin", "admin", undefined));

    expect(await screen.findByText("Approved domains")).toBeInTheDocument();
  });
});
