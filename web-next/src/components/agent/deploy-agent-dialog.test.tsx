import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DeployAgentDialog } from "@/components/agent/deploy-agent-dialog";
import type { Me } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

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

async function openDialog(user: Me) {
  useAuthStore.setState({ user, activeTenant: "default", hydrated: true, loading: false });
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <DeployAgentDialog />
    </QueryClientProvider>,
  );
  await userEvent.click(screen.getByRole("button", { name: /Deploy Agent/i }));
}

const REFUSED = /takes tenant admin/i;

describe("DeployAgentDialog", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("offers the push to a token-admin, who holds the permission it needs", async () => {
    // Both credential-handing actions here mint a provisioning key, which is
    // `tenant.credential.manage` — held by the tenant admin *and* by a
    // `token-admin`, both of them `viewer` accounts (#318). Asking the account
    // instead named a role the API does not consult.
    await openDialog(principal("viewer", "token-admin", ["tenant.credential.manage"]));

    expect(screen.queryByText(REFUSED)).not.toBeInTheDocument();
    // The other half of the same permission: minting the key the snippets
    // embed, on the tab that shows them.
    await userEvent.click(screen.getByRole("tab", { name: /Linux One-Liner/i }));
    expect(screen.getByRole("button", { name: /Generate key/i })).toBeEnabled();
  });

  it("refuses a tenant operator, who does not", async () => {
    await openDialog(principal("viewer", "operator", ["config.read", "scan.cancel"]));

    expect(screen.getByText(REFUSED)).toBeInTheDocument();
  });

  it("keeps the pre-#318 answer when the API sends no permission list", async () => {
    // An installation that has not been upgraded sends no list; falling back
    // to the account's role is what keeps this dialog working there rather
    // than refusing everybody.
    await openDialog(principal("admin", "admin", undefined));

    expect(screen.queryByText(REFUSED)).not.toBeInTheDocument();
  });
});
