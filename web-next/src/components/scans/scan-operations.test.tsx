import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ScanOperations } from "@/components/scans/scan-operations";
import type { Me } from "@/lib/api";
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
