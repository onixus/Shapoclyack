import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DeployAgentDialog } from "@/components/agent/deploy-agent-dialog";
import type { Me } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

function principal(
  role: Me["role"],
  tenantRole: string,
  permissions?: string[],
  tenantRank?: number,
): Me {
  return {
    username: "someone",
    role,
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: false,
    tenant_role: tenantRole,
    permissions,
    scoped_tenant: "default",
    ...(tenantRank === undefined ? {} : { tenant_rank: tenantRank }),
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
  await userEvent.click(screen.getByRole("button", { name: /Deploy Sensor/i }));
}

/** The mint notice. Names the permission rather than "tenant admin": a
 * tenant role at rank 3 without the permission *is* at the tenant admin rank,
 * and `token-admin` is not, yet holds it (#504). */
const REFUSED = /Minting one takes the tenant\.credential\.manage permission/i;
const PUSH_REFUSED = /The push takes the tenant admin rank and the tenant\.credential\.manage/i;

describe("DeployAgentDialog", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("offers a token-admin the key but not the push", async () => {
    // Minting a provisioning key is `tenant.credential.manage` — held by the
    // tenant admin *and* by a `token-admin`, both of them `viewer` accounts
    // (#318). The SSH push mints one as well, but the API also asks for the
    // tenant admin rank, which `token-admin` (rank 1) does not have (#504):
    // offering it the push or the host-key probe would only produce a 403.
    await openDialog(
      principal("viewer", "token-admin", ["tenant.credential.manage"], 1),
    );

    expect(screen.getByText(PUSH_REFUSED)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Start Installation/i })).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/Target Host/i), "192.168.10.50");
    expect(screen.getByRole("button", { name: /Read from host/i })).toBeDisabled();

    await userEvent.click(screen.getByRole("tab", { name: /Linux One-Liner/i }));
    expect(screen.getByRole("button", { name: /Generate key/i })).toBeEnabled();
  });

  it("offers the push to the tenant admin, who has both", async () => {
    await openDialog(
      principal("viewer", "admin", ["tenant.credential.manage", "tenant.member.manage"], 3),
    );

    expect(screen.queryByText(PUSH_REFUSED)).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(/Target Host/i), "192.168.10.50");
    expect(screen.getByRole("button", { name: /Read from host/i })).toBeEnabled();
  });

  it("refuses the push to a rank-3 role without the credential", async () => {
    // The other half: the rank alone used to be the gate, and minted keys.
    await openDialog(principal("viewer", "deployer", ["config.read"], 3));

    expect(screen.getByText(PUSH_REFUSED)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /Linux One-Liner/i }));
    expect(screen.getByText(REFUSED)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Generate key/i })).toBeDisabled();
  });

  it("refuses a tenant operator, who does not", async () => {
    await openDialog(principal("viewer", "operator", ["config.read", "scan.cancel"]));

    expect(screen.getByText(PUSH_REFUSED)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /Linux One-Liner/i }));
    expect(screen.getByText(REFUSED)).toBeInTheDocument();
  });

  it("keeps the pre-#318 answer when the API sends no permission list", async () => {
    // An installation that has not been upgraded sends no list; falling back
    // to the account's role is what keeps this dialog working there rather
    // than refusing everybody.
    await openDialog(principal("admin", "admin", undefined));

    expect(screen.queryByText(PUSH_REFUSED)).not.toBeInTheDocument();
  });
});
