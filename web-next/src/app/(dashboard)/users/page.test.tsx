import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import UsersPage from "@/app/(dashboard)/users/page";
import * as apiModule from "@/lib/api";
import type { MembershipInfo, Me, TenantInfo, UserInfo } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

function account(overrides: Partial<UserInfo> = {}): UserInfo {
  return {
    username: "analyst",
    role: "operator",
    disabled: false,
    has_password: true,
    created_at: "2026-09-01T10:00:00Z",
    updated_at: null,
    disabled_at: null,
    password_changed_at: null,
    created_by: "admin",
    email: null,
    email_verified: false,
    sso_linked: false,
    ...overrides,
  };
}

function tenant(overrides: Partial<TenantInfo> = {}): TenantInfo {
  return {
    tenant_id: "acme",
    name: "ACME",
    status: "active",
    created_at: "2026-08-01T10:00:00Z",
    ...overrides,
  };
}

function membership(overrides: Partial<MembershipInfo> = {}): MembershipInfo {
  return {
    username: "analyst",
    tenant_id: "acme",
    role: "viewer",
    created_at: "2026-09-02T10:00:00Z",
    created_by: "admin",
    ...overrides,
  };
}

function signIn(user: Partial<Me> = {}) {
  useAuthStore.setState({
    user: {
      username: "admin",
      role: "admin",
      tenants: ["acme"],
      default_tenant: "acme",
      is_platform_admin: true,
      ...user,
    },
    activeTenant: null,
    hydrated: true,
    loading: false,
  });
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <UsersPage />
    </QueryClientProvider>,
  );
  return queryClient;
}

/** Matches on the username cell only: every row also carries a role picker
 * whose options are literally "viewer", "operator" and "admin". */
function rowFor(username: string) {
  const row = screen.getAllByRole("row").find((candidate) => {
    const first = within(candidate).queryAllByRole("cell")[0];
    return first?.textContent?.trim().startsWith(username) ?? false;
  });
  return row as HTMLElement;
}

describe("UsersPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuthStore.setState({ user: null, activeTenant: null });
    vi.spyOn(apiModule, "fetchTenants").mockResolvedValue([tenant()]);
  });

  it("shows an admin the accounts and what can be done to them", async () => {
    vi.spyOn(apiModule, "fetchUsers").mockResolvedValue([
      account(),
      account({ username: "auditor", role: "viewer", disabled: true, email: "a@example.test" }),
    ]);
    signIn();
    renderPage();

    expect(await screen.findByText("analyst")).toBeInTheDocument();
    expect(screen.getByText("auditor")).toBeInTheDocument();
    expect(screen.getByText("a@example.test")).toBeInTheDocument();

    const row = rowFor("analyst");
    expect(within(row).getByRole("button", { name: /reset password/i })).toBeInTheDocument();
    expect(within(row).getByRole("button", { name: /set email/i })).toBeInTheDocument();
    expect(within(row).getByRole("button", { name: /^disable$/i })).toBeInTheDocument();
    expect(within(row).getByRole("button", { name: /delete/i })).toBeInTheDocument();
    // The disabled account offers the way back, not the same action again.
    expect(
      within(rowFor("auditor")).getByRole("button", { name: /^enable$/i }),
    ).toBeInTheDocument();
  });

  it("gives a viewer their own password form and nothing else", async () => {
    const users = vi.spyOn(apiModule, "fetchUsers").mockResolvedValue([account()]);
    signIn({ username: "analyst", role: "viewer", is_platform_admin: false });
    renderPage();

    expect(await screen.findByLabelText("Current password")).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Users" })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Tenant membership" })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Sign-in audit" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /create user/i })).not.toBeInTheDocument();
    // The list is admin-only, so it is never asked for rather than asked for
    // and refused with a 403.
    expect(users).not.toHaveBeenCalled();
  });

  it("creates the account with the username, password and role that were chosen", async () => {
    vi.spyOn(apiModule, "fetchUsers").mockResolvedValue([]);
    const create = vi
      .spyOn(apiModule, "createUser")
      .mockResolvedValue(account({ username: "newbie", role: "operator" }));
    const setEmail = vi.spyOn(apiModule, "setUserEmail");
    signIn();
    renderPage();

    await userEvent.click(await screen.findByRole("button", { name: /create user/i }));
    await userEvent.type(screen.getByLabelText("Username"), "newbie");
    await userEvent.type(screen.getByLabelText("Initial password"), "correct-horse-battery");
    await userEvent.selectOptions(screen.getByLabelText("Role"), "operator");
    await userEvent.click(screen.getByRole("button", { name: /create account/i }));

    await waitFor(() =>
      expect(create).toHaveBeenCalledWith({
        username: "newbie",
        password: "correct-horse-battery",
        role: "operator",
        email: null,
      }),
    );
    // The address rides in the same request; the separate email call is for edits only.
    expect(setEmail).not.toHaveBeenCalled();
  });

  it("does not offer to delete the account the admin is signed in as", async () => {
    vi.spyOn(apiModule, "fetchUsers").mockResolvedValue([
      account(),
      account({ username: "admin", role: "admin" }),
    ]);
    signIn({ username: "admin" });
    renderPage();

    await screen.findByText("analyst");
    const own = rowFor("admin");
    expect(within(own).queryByRole("button", { name: /delete/i })).not.toBeInTheDocument();
    expect(within(own).getByText(/cannot be deleted/i)).toBeInTheDocument();
    // Somebody else's account still can be.
    expect(within(rowFor("analyst")).getByRole("button", { name: /delete/i })).toBeInTheDocument();
  });

  it("grants a membership in the selected tenant with the chosen role", async () => {
    vi.spyOn(apiModule, "fetchUsers").mockResolvedValue([account()]);
    vi.spyOn(apiModule, "fetchTenantMembers").mockResolvedValue([membership()]);
    const grant = vi
      .spyOn(apiModule, "grantMembership")
      .mockResolvedValue(membership({ username: "newbie", role: "operator" }));
    signIn();
    renderPage();

    await userEvent.click(await screen.findByRole("tab", { name: "Tenant membership" }));
    expect(await screen.findByText(/platform admin reaches every tenant/i)).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Grant or change access"), "newbie");
    await userEvent.selectOptions(screen.getByLabelText("Role in tenant"), "operator");
    await userEvent.click(screen.getByRole("button", { name: "Grant access" }));

    await waitFor(() => expect(grant).toHaveBeenCalledWith("acme", "newbie", "operator"));
  });
});
