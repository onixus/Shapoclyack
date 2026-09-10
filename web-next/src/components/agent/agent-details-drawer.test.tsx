import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi } from "vitest";
import { AgentDetailsDrawer } from "@/components/agent/agent-details-drawer";
import * as apiModule from "@/lib/api";
import type { AgentInfo } from "@/lib/api";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

function agent(overrides: Partial<AgentInfo> = {}): AgentInfo {
  return {
    agent_id: "edge-01",
    hostname: "edge-01.lab",
    version: "0.44.0",
    labels: {},
    status: "idle",
    current_job_id: null,
    detail: null,
    registered_at: "2026-09-01T10:00:00Z",
    last_seen_at: "2026-09-01T10:00:00Z",
    online: true,
    tenant_id: "default",
    lifecycle_status: "active",
    lifecycle_reason: null,
    lifecycle_message: null,
    ...overrides,
  };
}

function renderDrawer(detail: AgentInfo) {
  vi.spyOn(apiModule, "fetchAgentDetail").mockResolvedValue(detail);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <AgentDetailsDrawer agentId={detail.agent_id} open onOpenChange={() => {}} />
    </QueryClientProvider>,
  );
}

describe("AgentDetailsDrawer deregistration", () => {
  /** #308: revoking the key stops every agent that holds it, and one key
   * commonly provisions a whole fleet. The number has to be in front of the
   * operator before the click, not in the response afterwards. */
  it("warns how many other agents the key revocation would stop", async () => {
    const user = userEvent.setup();
    renderDrawer(agent({ other_agents_on_key: 12 }));

    await user.click(await screen.findByRole("button", { name: /Deregister Agent/i }));
    // The warning belongs to the checkbox, not to the delete itself: without
    // it the delete strands nothing else.
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    await user.click(screen.getByLabelText("Revoke provisioning key"));
    expect(screen.getByRole("alert")).toHaveTextContent(
      /12 other agents .* revoking it stops all of them/i,
    );
  });

  it("says nothing when this agent is the only one on the key", async () => {
    const user = userEvent.setup();
    renderDrawer(agent({ other_agents_on_key: 0 }));

    await user.click(await screen.findByRole("button", { name: /Deregister Agent/i }));
    await user.click(screen.getByLabelText("Revoke provisioning key"));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
