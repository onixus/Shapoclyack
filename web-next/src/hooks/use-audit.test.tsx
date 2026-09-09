import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { AxiosResponse, InternalAxiosRequestConfig } from "axios";
import type { ReactNode } from "react";
import { api, type AuditEventInfo } from "@/lib/api";
import { useAuditEvents, useAuditExport } from "@/hooks/use-audit";

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

import { toast } from "sonner";

const EVENT: AuditEventInfo = {
  id: 7,
  occurred_at: "2026-09-09T10:00:00Z",
  tenant_id: "acme",
  actor: "admin",
  actor_type: "user",
  action: "user.role_change",
  resource_type: "user",
  resource_id: "amy",
  before: { role: "viewer" },
  after: { role: "operator" },
  client_ip: "198.51.100.7",
  user_agent: "console",
  request_id: "req-1",
};

type Reply = { status: number; data: unknown };

let client: QueryClient;
let originalAdapter: typeof api.defaults.adapter;

/** Only the transport is stubbed, so the URL `api.ts` builds — which is the
 * whole of what these filters are — stays under test. Every request is
 * recorded; the last answer stands for each further call. */
function installTransport(reply: Reply) {
  const urls: string[] = [];
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    urls.push(String(config.url));
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
  return urls;
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

describe("useAuditEvents", () => {
  it("returns the page on the happy path", async () => {
    installTransport({
      status: 200,
      data: { items: [EVENT], total: 1, offset: 0, limit: 50, has_more: false },
    });

    const { result } = renderHook(() => useAuditEvents(true), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.items).toEqual([EVENT]);
  });

  it("sends every filter it was given, and nothing it was not", async () => {
    const urls = installTransport({
      status: 200,
      data: { items: [], total: 0, offset: 0, limit: 50, has_more: false },
    });

    const { result } = renderHook(
      () =>
        useAuditEvents(
          true,
          { offset: 0, limit: 25 },
          {
            tenantId: "acme",
            action: "user.role_change",
            actor: "admin",
            from: "2026-09-01T00:00:00.000Z",
          },
        ),
      { wrapper },
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    const url = urls[0];
    expect(url).toContain("tenant_id=acme");
    expect(url).toContain("action=user.role_change");
    expect(url).toContain("actor=admin");
    expect(url).toContain("limit=25");
    // Absent filters must not become empty parameters: `resource_id=` is a
    // filter for the empty string, not for "no filter".
    expect(url).not.toContain("resource_id=");
    expect(url).not.toContain("to=");
  });

  it("does not fetch for a caller the page has not enabled", () => {
    installTransport({ status: 200, data: { items: [], total: 0 } });

    const { result } = renderHook(() => useAuditEvents(false), { wrapper });

    expect(result.current.fetchStatus).toBe("idle");
  });

  it("surfaces a refusal as an error rather than an empty trail", async () => {
    installTransport({ status: 403, data: { detail: "Role 'admin' or higher required" } });

    const { result } = renderHook(() => useAuditEvents(true), { wrapper });

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(String(result.current.error)).toContain("admin");
  });
});

describe("useAuditExport", () => {
  it("asks for the format, carries the filters, and takes no page bounds", async () => {
    const urls = installTransport({ status: 200, data: new Blob(["id\n"]) });
    // jsdom implements neither of these, and the download helper uses both.
    const createObjectURL = vi.fn(() => "blob:audit");
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });

    const { result } = renderHook(() => useAuditExport({ action: "user.create" }), { wrapper });
    result.current.mutate("csv");

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(urls[0]).toContain("format=csv");
    expect(urls[0]).toContain("action=user.create");
    expect(urls[0]).not.toContain("limit=");
    expect(createObjectURL).toHaveBeenCalled();
  });

  it("reports a failed export instead of leaving a silent empty file", async () => {
    installTransport({ status: 500, data: { detail: "boom" } });

    const { result } = renderHook(() => useAuditExport(), { wrapper });
    result.current.mutate("ndjson");

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(toast.error).toHaveBeenCalled();
  });
});
