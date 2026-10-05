import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AgentsPage from "@/app/(dashboard)/agents/page";
import * as apiModule from "@/lib/api";
import type { AgentDeploymentSnippetResponse, AgentFleetSummary, Me } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

function principal(tenantRole: string, permissions: string[], tenantRank: number): Me {
  return {
    username: "someone",
    role: "viewer",
    tenants: ["acme"],
    default_tenant: "acme",
    is_platform_admin: false,
    tenant_role: tenantRole,
    permissions,
    tenant_rank: tenantRank,
    scoped_tenant: "acme",
  };
}

const SUMMARY: AgentFleetSummary = {
  total_agents: 3,
  online_agents: 2,
  busy_agents: 0,
  stale_agents: 1,
  error_agents: 0,
  outdated_agents: 0,
  latest_version: "1.0.0",
  by_tenant: { acme: 3 },
};

const SNIPPETS: AgentDeploymentSnippetResponse = {
  tenant_id: "acme",
  provisioning_key: null,
  key_minted: false,
  server_url: "https://shapoclyack.example",
  systemd_oneliner: "curl … <PROVISIONING_KEY>",
  docker_run: "docker run … <PROVISIONING_KEY>",
  docker_compose: "services: {}",
  kubernetes_yaml: "kind: Deployment",
  kubernetes_secret_command: "kubectl create secret …",
};

function renderPage(user: Me) {
  useAuthStore.setState({ user, activeTenant: "acme", hydrated: true, loading: false });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <AgentsPage />
    </QueryClientProvider>,
  );
}

describe("AgentsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(apiModule, "fetchAgentSummary").mockResolvedValue(SUMMARY);
    vi.spyOn(apiModule, "fetchAgentDeploymentSnippets").mockResolvedValue(SNIPPETS);
  });

  it("gives a token-admin the Deploy Agent dialog without asking for the fleet (#504)", async () => {
    // `token-admin` reaches this page for the dialog's key mint
    // (`tenant.credential.manage`); `GET /api/agents` stays at operator, so
    // asking for it would only put a 403 where the table is.
    const list = vi.spyOn(apiModule, "fetchAgents");
    renderPage(principal("token-admin", ["tenant.credential.manage"], 1));

    expect(screen.getByRole("button", { name: /Deploy Sensor/i })).toBeInTheDocument();
    expect(await screen.findByText(/The sensor list takes the operator role/i)).toBeInTheDocument();
    expect(list).not.toHaveBeenCalled();
  });

  it("still lists the fleet for an operator", async () => {
    const list = vi
      .spyOn(apiModule, "fetchAgents")
      .mockResolvedValue({ items: [], total: 0, offset: 0, limit: 25, has_more: false });
    renderPage(principal("operator", [], 2));

    expect(screen.getByRole("button", { name: /Deploy Sensor/i })).toBeInTheDocument();
    await vi.waitFor(() => expect(list).toHaveBeenCalled());
    expect(screen.queryByText(/The sensor list takes the operator role/i)).not.toBeInTheDocument();
  });
});
