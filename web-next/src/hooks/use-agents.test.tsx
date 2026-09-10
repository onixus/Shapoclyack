import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { AxiosResponse, InternalAxiosRequestConfig } from "axios";
import type { ReactNode } from "react";
import { api, type AgentInfo } from "@/lib/api";
import { useDeleteAgent, useUpdateAgentStatus } from "@/hooks/use-agents";
import { queryKeys } from "@/lib/query-keys";

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

import { toast } from "sonner";

const AGENT: AgentInfo = {
  agent_id: "agent_1",
  hostname: "edge-1",
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
};

type Reply = { status: number; data: unknown };
type Sent = { method: string; url: string; body: unknown };

let client: QueryClient;
let originalAdapter: typeof api.defaults.adapter;

/** Only the transport is stubbed, as in use-scan-scope.test.tsx: the URL
 * `api.ts` builds is half of what these tests are about — `revoke_key` has to
 * reach the server or the delete is the pause #308 is closing. */
function installTransport(answers: { patch?: Reply[]; delete?: Reply[] }) {
  const sent: Sent[] = [];
  const queues: Record<string, Reply[]> = {
    patch: [...(answers.patch ?? [])],
    delete: [...(answers.delete ?? [])],
  };
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    const method = (config.method ?? "get").toLowerCase();
    sent.push({
      method,
      url: String(config.url),
      body: config.data ? JSON.parse(String(config.data)) : null,
    });
    const queue = queues[method] ?? [];
    const reply = queue.length > 1 ? (queue.shift() as Reply) : queue[0];
    if (!reply) throw new Error(`unexpected ${method.toUpperCase()} ${config.url}`);
    const response = {
      data: reply.data,
      status: reply.status,
      statusText: "",
      headers: {},
      config,
    } as AxiosResponse;
    if (reply.status >= 400) {
      throw Object.assign(new Error(`Request failed with status code ${reply.status}`), {
        isAxiosError: true,
        config,
        response,
      });
    }
    return response;
  };
  return sent;
}

/** jsdom in this setup exposes no Storage implementation, and the request
 * interceptor reads the bearer token out of one. */
function installLocalStorage() {
  const store = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => void store.set(key, String(value)),
      removeItem: (key: string) => void store.delete(key),
      clear: () => store.clear(),
    },
  });
}

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  installLocalStorage();
  originalAdapter = api.defaults.adapter;
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
});

afterEach(() => {
  api.defaults.adapter = originalAdapter;
  vi.clearAllMocks();
});

describe("useUpdateAgentStatus", () => {
  it("sends the state and the reason, and caches what the server stored", async () => {
    const stored: AgentInfo = {
      ...AGENT,
      lifecycle_status: "quarantined",
      lifecycle_reason: "credential leak",
      lifecycle_message: "This agent is quarantined by an operator; …",
    };
    const sent = installTransport({ patch: [{ status: 200, data: stored }] });

    const { result } = renderHook(() => useUpdateAgentStatus(), { wrapper });
    result.current.mutate({
      agentId: "agent_1",
      status: "quarantined",
      reason: "credential leak",
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(sent).toEqual([
      {
        method: "patch",
        url: "/agents/agent_1",
        body: { status: "quarantined", reason: "credential leak" },
      },
    ]);
    // From the response, not from what was asked for: the API drops the reason
    // on a return to `active`, and the drawer must render what was stored.
    expect(client.getQueryData(queryKeys.agentDetail("agent_1"))).toEqual(stored);
    expect(vi.mocked(toast.success).mock.calls[0]?.[0]).toBe("Agent is now quarantined");
  });

  it("carries the API's refusal into the failure toast", async () => {
    installTransport({ patch: [{ status: 403, data: { detail: "Role 'admin' or higher required" } }] });

    const { result } = renderHook(() => useUpdateAgentStatus(), { wrapper });
    result.current.mutate({ agentId: "agent_1", status: "disabled" });

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(vi.mocked(toast.error).mock.calls[0]?.[1]).toEqual({
      description: "Role 'admin' or higher required",
    });
  });
});

describe("useDeleteAgent", () => {
  it("does not revoke the provisioning key unless asked to", async () => {
    const sent = installTransport({
      delete: [
        {
          status: 200,
          data: {
            status: "deleted",
            agent_id: "agent_1",
            provisioning_key_id: "pk_1",
            key_revoked: false,
          },
        },
      ],
    });

    const { result } = renderHook(() => useDeleteAgent(), { wrapper });
    result.current.mutate({ agentId: "agent_1" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(sent[0]?.url).toBe("/agents/agent_1?revoke_key=false");
    // The operator is told the host can still re-register — silence here is
    // what made "delete" read as permanent when it was not (#308).
    expect(vi.mocked(toast.success).mock.calls[0]?.[1]).toEqual({
      description: "Its provisioning key is still valid; revoke it to stop re-registration",
    });
  });

  it("asks for the revocation and reports it when the server did it", async () => {
    const sent = installTransport({
      delete: [
        {
          status: 200,
          data: {
            status: "deleted",
            agent_id: "agent_1",
            provisioning_key_id: "pk_1",
            key_revoked: true,
          },
        },
      ],
    });

    const { result } = renderHook(() => useDeleteAgent(), { wrapper });
    result.current.mutate({ agentId: "agent_1", revokeKey: true });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(sent[0]?.url).toBe("/agents/agent_1?revoke_key=true");
    expect(vi.mocked(toast.success).mock.calls[0]?.[0]).toBe(
      "Agent deregistered and its provisioning key revoked",
    );
  });

  it("says so when there was no key on record to revoke", async () => {
    // An agent that registered before the key was tracked, or a legacy
    // shared-token one. Reporting success on the revocation would leave the
    // operator believing a live credential is dead.
    installTransport({
      delete: [
        {
          status: 200,
          data: {
            status: "deleted",
            agent_id: "agent_1",
            provisioning_key_id: null,
            key_revoked: false,
          },
        },
      ],
    });

    const { result } = renderHook(() => useDeleteAgent(), { wrapper });
    result.current.mutate({ agentId: "agent_1", revokeKey: true });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(vi.mocked(toast.success).mock.calls[0]?.[1]).toEqual({
      description: "No provisioning key on record for this agent — nothing to revoke",
    });
  });
});
