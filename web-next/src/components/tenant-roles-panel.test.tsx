import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TenantMembersPanel } from "@/components/tenant-members-panel";
import { TenantRolesPanel } from "@/components/tenant-roles-panel";
import * as apiModule from "@/lib/api";
import type { Me, MembershipInfo, PermissionInfo, RoleInfo } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

function role(overrides: Partial<RoleInfo> = {}): RoleInfo {
  return {
    role_id: "viewer",
    tenant_id: null,
    description: "",
    builtin: true,
    rank: 1,
    permissions: [],
    member_count: 0,
    ...overrides,
  };
}

const CATALOGUE: RoleInfo[] = [
  role({ role_id: "viewer" }),
  role({ role_id: "operator", rank: 2, permissions: ["config.read", "scan.cancel"] }),
  role({
    role_id: "admin",
    rank: 3,
    permissions: ["audit.read", "tenant.member.manage", "tenant.member.read"],
  }),
  role({
    role_id: "scope-approver",
    permissions: ["scan_scope.approve", "scan_scope.read"],
  }),
  role({
    role_id: "analyst",
    tenant_id: "acme",
    builtin: false,
    rank: 2,
    permissions: ["audit.read"],
    member_count: 2,
  }),
  role({
    role_id: "people-ops",
    tenant_id: "acme",
    builtin: false,
    permissions: ["scan_scope.read", "tenant.member.manage", "tenant.member.read"],
    member_count: 1,
  }),
  role({ role_id: "spare", tenant_id: "acme", builtin: false }),
];

const PERMISSIONS: PermissionInfo[] = [
  { permission_key: "audit.read", description: "Read the trail", tenant_grantable: true },
  { permission_key: "config.write", description: "Installation config", tenant_grantable: false },
  { permission_key: "scan_scope.approve", description: "Approve scope", tenant_grantable: true },
  { permission_key: "scan_scope.read", description: "Read scope", tenant_grantable: true },
  { permission_key: "tenant.member.read", description: "List members", tenant_grantable: true },
];

/** A global viewer holding the tenant-defined `people-ops` role: rank 1, may
 * manage members, holds scan_scope.read and nothing else — the principal the
 * ceiling exists for. */
function signInAsPeopleOps(overrides: Partial<Me> = {}) {
  useAuthStore.setState({
    user: {
      username: "hr",
      role: "viewer",
      tenants: ["acme"],
      default_tenant: "acme",
      is_platform_admin: false,
      tenant_role: "people-ops",
      tenant_rank: 1,
      permissions: ["scan_scope.read", "tenant.member.manage", "tenant.member.read"],
      ...overrides,
    },
    activeTenant: "acme",
    hydrated: true,
    loading: false,
  });
}

function renderWith(node: React.ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={queryClient}>{node}</QueryClientProvider>);
}

describe("TenantRolesPanel", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    signInAsPeopleOps();
    vi.spyOn(apiModule, "fetchRoleCatalogue").mockResolvedValue(CATALOGUE);
    vi.spyOn(apiModule, "fetchPermissionCatalogue").mockResolvedValue(PERMISSIONS);
  });

  it("lists only the tenant's own roles, and edits none above the principal", async () => {
    renderWith(<TenantRolesPanel tenantId="acme" canManage />);
    expect(await screen.findByText("analyst")).toBeInTheDocument();
    expect(screen.getByText("people-ops")).toBeInTheDocument();
    // The built-ins are granted on the members list, not edited here.
    expect(screen.queryByText("scope-approver")).not.toBeInTheDocument();

    // `analyst` is rank 2 with audit.read — above a rank-1 people-ops — so
    // the API would refuse both; the console does not offer them.
    expect(screen.queryByRole("button", { name: "Edit analyst" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete analyst" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit people-ops" })).toBeInTheDocument();
  });

  it("offers only the ranks and permissions the principal may hand out", async () => {
    const create = vi
      .spyOn(apiModule, "createTenantRole")
      .mockResolvedValue(role({ role_id: "scope-desk", tenant_id: "acme", builtin: false }));
    renderWith(<TenantRolesPanel tenantId="acme" canManage />);
    await userEvent.click(await screen.findByRole("button", { name: /new role/i }));

    const dialog = screen.getByRole("dialog");
    const rank = within(dialog).getByLabelText("Rank");
    expect(
      within(rank)
        .getAllByRole("option")
        .map((o) => o.textContent),
    ).toEqual(["Read"]);
    // Only what it holds: never the platform's, never one it lacks, and not
    // an approval — staffing those without holding them is the admin rank's.
    expect(await within(dialog).findByText("scan_scope.read")).toBeInTheDocument();
    expect(within(dialog).getByText("tenant.member.read")).toBeInTheDocument();
    expect(within(dialog).queryByText("scan_scope.approve")).not.toBeInTheDocument();
    expect(within(dialog).queryByText("audit.read")).not.toBeInTheDocument();
    expect(within(dialog).queryByText("config.write")).not.toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Name"), "Scope-Desk");
    await userEvent.click(screen.getByRole("checkbox", { name: /scan_scope\.read/ }));
    await userEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(create).toHaveBeenCalledWith("acme", {
        role_id: "scope-desk",
        description: "",
        rank: 1,
        permissions: ["scan_scope.read"],
      }),
    );
  });

  it("offers the approvals to a member manager at the admin rank", async () => {
    signInAsPeopleOps({ tenant_role: "tenant-owner", tenant_rank: 3 });
    renderWith(<TenantRolesPanel tenantId="acme" canManage />);
    await userEvent.click(await screen.findByRole("button", { name: /new role/i }));

    const dialog = screen.getByRole("dialog");
    expect(await within(dialog).findByText("scan_scope.approve")).toBeInTheDocument();
  });

  it("will not delete a held role without saying where its members go", async () => {
    signInAsPeopleOps({ is_platform_admin: true });
    const remove = vi.spyOn(apiModule, "deleteTenantRole").mockResolvedValue({
      role_id: "analyst",
      reassigned_to: "viewer",
      memberships_reassigned: 2,
    });
    renderWith(<TenantRolesPanel tenantId="acme" canManage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete analyst" }));

    const confirm = screen.getByRole("button", { name: "Delete role" });
    expect(confirm).toBeDisabled();
    await userEvent.selectOptions(screen.getByLabelText(/regrant its members/i), "viewer");
    await userEvent.click(confirm);
    await waitFor(() => expect(remove).toHaveBeenCalledWith("acme", "analyst", "viewer"));
  });

  it("deletes a role nobody holds without asking for a target", async () => {
    const remove = vi.spyOn(apiModule, "deleteTenantRole").mockResolvedValue({
      role_id: "spare",
      reassigned_to: null,
      memberships_reassigned: 0,
    });
    renderWith(<TenantRolesPanel tenantId="acme" canManage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete spare" }));
    expect(screen.queryByLabelText(/regrant its members/i)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Delete role" }));
    await waitFor(() => expect(remove).toHaveBeenCalledWith("acme", "spare", undefined));
  });

  it("is read-only without tenant.member.manage", async () => {
    renderWith(<TenantRolesPanel tenantId="acme" canManage={false} />);
    expect(await screen.findByText("analyst")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /new role/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit people-ops" })).not.toBeInTheDocument();
  });
});

describe("TenantMembersPanel", () => {
  const MEMBERS: MembershipInfo[] = [
    { username: "boss", tenant_id: "acme", role: "admin", created_at: null, created_by: null },
    {
      username: "lead",
      tenant_id: "acme",
      role: "analyst",
      created_at: null,
      created_by: null,
    },
    { username: "newbie", tenant_id: "acme", role: "viewer", created_at: null, created_by: null },
  ];

  beforeEach(() => {
    vi.restoreAllMocks();
    signInAsPeopleOps();
    vi.spyOn(apiModule, "fetchRoleCatalogue").mockResolvedValue(CATALOGUE);
    vi.spyOn(apiModule, "fetchTenantMembers").mockResolvedValue(MEMBERS);
  });

  it("grants a tenant-defined role, and offers nothing above the granter", async () => {
    const grant = vi.spyOn(apiModule, "grantMembership").mockResolvedValue(MEMBERS[2]);
    renderWith(<TenantMembersPanel tenantId="acme" canManage />);
    await screen.findByText("boss");

    const offered = within(screen.getByLabelText("Role in tenant")).getAllByRole("option");
    const names = offered.map((option) => option.textContent);
    expect(names).toContain("people-ops");
    // An approval role is the admin rank's to staff, not a rank-1 granter's.
    expect(names).not.toContain("scope-approver");
    expect(names).not.toContain("admin");
    expect(names).not.toContain("operator");
    expect(names).not.toContain("analyst");

    await userEvent.type(screen.getByLabelText(/grant or change access/i), "newbie");
    await userEvent.selectOptions(screen.getByLabelText("Role in tenant"), "people-ops");
    await userEvent.click(screen.getByRole("button", { name: /grant access/i }));
    await waitFor(() => expect(grant).toHaveBeenCalledWith("acme", "newbie", "people-ops"));
  });

  it("shows a member above the granter as a fact, not as a control", async () => {
    renderWith(<TenantMembersPanel tenantId="acme" canManage />);
    await screen.findByText("boss");
    // The API refuses to change or revoke `boss` (admin) and `lead` (rank-2
    // analyst) for a rank-1 granter, so neither row is a select.
    expect(screen.queryByLabelText(/role for boss/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/role for lead/i)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/role for newbie/i)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Revoke" })).toHaveLength(1);
  });

  it("lists without a single control for a member reader", async () => {
    renderWith(<TenantMembersPanel tenantId="acme" canManage={false} />);
    await screen.findByText("boss");
    expect(screen.queryByRole("button", { name: /grant access/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
  });
});
