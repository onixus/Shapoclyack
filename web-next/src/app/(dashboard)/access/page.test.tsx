import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AccessPage from "@/app/(dashboard)/access/page";
import type { Me } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { canOperate as canOperateIn } from "@/lib/authz";

// The panels have their own tests (tenant-roles-panel.test.tsx); what is
// pinned here is the page's one decision — who gets them — so they render as
// markers carrying the props the page handed down.
vi.mock("@/components/tenant-roles-panel", () => ({
  TenantRolesPanel: ({ tenantId, canManage }: { tenantId: string; canManage: boolean }) => (
    <div data-testid="roles-panel">{`${tenantId}:${canManage ? "manage" : "read"}`}</div>
  ),
}));
vi.mock("@/components/tenant-members-panel", () => ({
  TenantMembersPanel: ({ tenantId, canManage }: { tenantId: string; canManage: boolean }) => (
    <div data-testid="members-panel">{`${tenantId}:${canManage ? "manage" : "read"}`}</div>
  ),
}));

/** `role` is the account's *global* role; the rest is what it holds in the
 * tenant the switcher is on. */
function signIn(overrides: Partial<Me>) {
  const user: Me = {
    username: "alice",
    role: "viewer",
    tenants: ["acme"],
    default_tenant: "acme",
    is_platform_admin: false,
    ...overrides,
  };
  useAuthStore.setState({
    user,
    loading: false,
    hydrated: true,
    canOperate: canOperateIn(user),
    activeTenant: "acme",
  });
}

describe("Access page", () => {
  beforeEach(() => {
    useAuthStore.setState({ user: null, canOperate: false, hydrated: true, loading: false });
  });

  it("opens for a tenant admin who is only a viewer globally", () => {
    // The defect the page exists to close: gated on the global role, the
    // tenant admin was kept out of the screen the API serves it.
    signIn({
      role: "viewer",
      tenant_role: "admin",
      tenant_rank: 3,
      permissions: ["tenant.member.read", "tenant.member.manage"],
    });
    render(<AccessPage />);

    expect(screen.getByTestId("roles-panel")).toHaveTextContent("acme:manage");
    expect(screen.getByTestId("members-panel")).toHaveTextContent("acme:manage");
    expect(screen.queryByText(/needs the tenant.member.read permission/)).toBeNull();
  });

  it("opens read-only for a tenant role that reads members and manages none", () => {
    signIn({
      role: "viewer",
      tenant_role: "hr-reader",
      tenant_rank: 1,
      permissions: ["tenant.member.read"],
    });
    render(<AccessPage />);

    expect(screen.getByTestId("members-panel")).toHaveTextContent("acme:read");
  });

  it("stays shut for a global admin who holds nothing in this tenant", () => {
    // The mirror: the account's role is not the answer in either direction.
    signIn({ role: "admin", tenant_role: "viewer", tenant_rank: 1, permissions: [] });
    render(<AccessPage />);

    expect(screen.getByText(/needs the tenant.member.read permission/)).toBeInTheDocument();
    expect(screen.queryByTestId("roles-panel")).toBeNull();
  });
});
