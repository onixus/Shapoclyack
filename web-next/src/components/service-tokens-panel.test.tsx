import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ServiceTokensPanel } from "@/components/service-tokens-panel";
import * as apiModule from "@/lib/api";
import type { Me, ServiceTokenInfo } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

function token(overrides: Partial<ServiceTokenInfo> = {}): ServiceTokenInfo {
  return {
    token_id: "st_1",
    tenant_id: "acme",
    name: "ci-pipeline",
    token_prefix: "octo_st_abcdef0123456789",
    scopes: ["runs:read"],
    role: "viewer",
    status: "active",
    created_by: "admin",
    created_at: "2026-08-01T00:00:00Z",
    expires_at: "2026-11-01T00:00:00Z",
    last_used_at: null,
    revoked_at: null,
    ...overrides,
  };
}

function renderPanel(canManage = true) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <ServiceTokensPanel tenantId="acme" canManage={canManage} />
    </QueryClientProvider>,
  );
  return queryClient;
}

/** Signs somebody in with a role *in the selected tenant* — which is what the
 * issuance ceiling compares against (#318). */
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
    activeTenant: "acme",
    hydrated: true,
    loading: false,
  });
}

describe("ServiceTokensPanel", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    signIn();
  });

  it("names the permission instead of showing the form without it", () => {
    // Not "managed by a platform administrator": since #318 the tenant's own
    // admin and its token-admin manage these, so that sentence sent exactly
    // the people who can do this to file a ticket with somebody who need not
    // be involved.
    const list = vi.spyOn(apiModule, "fetchServiceTokens");
    renderPanel(false);
    expect(screen.getByText(/tenant\.credential\.manage/)).toBeInTheDocument();
    expect(screen.queryByText(/platform administrator/i)).not.toBeInTheDocument();
    expect(list).not.toHaveBeenCalled();
  });

  it("lists a tenant's tokens by prefix, never by secret", async () => {
    vi.spyOn(apiModule, "fetchServiceTokens").mockResolvedValue([token()]);
    renderPanel();
    expect(await screen.findByText("ci-pipeline")).toBeInTheDocument();
    expect(screen.getByText("octo_st_abcdef0123456789")).toBeInTheDocument();
    expect(screen.getByText("runs:read")).toBeInTheDocument();
  });

  it("shows a created token once, with a warning that it cannot be read again", async () => {
    vi.spyOn(apiModule, "fetchServiceTokens").mockResolvedValue([]);
    const create = vi
      .spyOn(apiModule, "createServiceToken")
      .mockResolvedValue(token({ token: "octo_st_abcdef0123456789_secretvalue" }));

    renderPanel();
    await userEvent.type(await screen.findByLabelText("Name"), "ci-pipeline");
    await userEvent.clear(screen.getByLabelText("Scopes"));
    await userEvent.type(screen.getByLabelText("Scopes"), "runs:read vulnerabilities:read");
    await userEvent.click(screen.getByRole("button", { name: /issue token/i }));

    expect(create).toHaveBeenCalledWith("acme", {
      name: "ci-pipeline",
      scopes: ["runs:read", "vulnerabilities:read"],
      role: "viewer",
    });
    expect(await screen.findByText(/shown only once/i)).toBeInTheDocument();
    expect(screen.getByText("octo_st_abcdef0123456789_secretvalue")).toBeInTheDocument();

    // Dismissing it removes the plaintext from the DOM for good.
    await userEvent.click(screen.getByRole("button", { name: /i have copied it/i }));
    await waitFor(() =>
      expect(screen.queryByText("octo_st_abcdef0123456789_secretvalue")).not.toBeInTheDocument(),
    );
  });

  it("revokes a token and offers no revoke action for one already dead", async () => {
    vi.spyOn(apiModule, "fetchServiceTokens").mockResolvedValue([
      token(),
      token({ token_id: "st_2", name: "old", status: "revoked" }),
    ]);
    const revoke = vi
      .spyOn(apiModule, "revokeServiceToken")
      .mockResolvedValue(token({ status: "revoked" }));

    renderPanel();
    await screen.findByText("ci-pipeline");
    const revokeButtons = screen.getAllByRole("button", { name: "Revoke" });
    expect(revokeButtons).toHaveLength(1);

    await userEvent.click(revokeButtons[0]);
    await waitFor(() => expect(revoke).toHaveBeenCalledWith("acme", "st_1"));
  });

  it("surfaces a rejected creation instead of an unhandled rejection", async () => {
    vi.spyOn(apiModule, "fetchServiceTokens").mockResolvedValue([]);
    vi.spyOn(apiModule, "createServiceToken").mockRejectedValue(
      new Error("422 invalid scope 'runs:delete'"),
    );
    const unhandled = vi.fn();
    window.addEventListener("unhandledrejection", unhandled);

    renderPanel();
    await userEvent.type(await screen.findByLabelText("Name"), "ci-pipeline");
    await userEvent.clear(screen.getByLabelText("Scopes"));
    await userEvent.type(screen.getByLabelText("Scopes"), "runs:delete");
    await userEvent.click(screen.getByRole("button", { name: /issue token/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "422 invalid scope 'runs:delete'",
    );
    // What the operator typed survives, so the scope can be corrected in place.
    expect(screen.getByLabelText("Name")).toHaveValue("ci-pipeline");
    expect(unhandled).not.toHaveBeenCalled();
    window.removeEventListener("unhandledrejection", unhandled);
  });

  it("surfaces a failed load rather than showing an empty list", async () => {
    vi.spyOn(apiModule, "fetchServiceTokens").mockRejectedValue(new Error("403 Forbidden"));
    renderPanel();
    expect(await screen.findByText("403 Forbidden")).toBeInTheDocument();
  });

  it("offers a token-admin only the role it can actually issue", async () => {
    // `token-admin` holds `tenant.credential.manage` at rank 1, so the server
    // refuses `operator` and `admin` (`_refuse_escalation`). Showing them was
    // showing two choices that could only ever answer 403.
    vi.spyOn(apiModule, "fetchServiceTokens").mockResolvedValue([]);
    signIn({
      username: "keymaster",
      role: "viewer",
      is_platform_admin: false,
      tenant_role: "token-admin",
      permissions: ["tenant.credential.manage"],
    });
    renderPanel();

    const picker = await screen.findByLabelText("Role");
    expect(within(picker).getByRole("option", { name: "viewer" })).toBeInTheDocument();
    expect(within(picker).queryByRole("option", { name: "operator" })).toBeNull();
    expect(within(picker).queryByRole("option", { name: "admin" })).toBeNull();
    expect(screen.getByText(/cannot be stronger than the hand issuing it/i)).toBeInTheDocument();
  });

  it("leaves the full list to a tenant admin", async () => {
    vi.spyOn(apiModule, "fetchServiceTokens").mockResolvedValue([]);
    signIn({
      username: "acme-admin",
      role: "viewer",
      is_platform_admin: false,
      tenant_role: "admin",
      permissions: ["tenant.credential.manage"],
    });
    renderPanel();

    const picker = await screen.findByLabelText("Role");
    for (const role of ["viewer", "operator", "admin"]) {
      expect(within(picker).getByRole("option", { name: role })).toBeInTheDocument();
    }
    expect(screen.queryByText(/cannot be stronger than the hand issuing it/i)).toBeNull();
  });
});
