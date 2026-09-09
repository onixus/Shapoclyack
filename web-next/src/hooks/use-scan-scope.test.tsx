import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { AxiosResponse, InternalAxiosRequestConfig } from "axios";
import type { ReactNode } from "react";
import { api, type ScanScopeEntry } from "@/lib/api";
import { scanScopeSignature, useReplaceScanScope, useScanScope } from "@/hooks/use-scan-scope";
import { queryKeys } from "@/lib/query-keys";

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

import { toast } from "sonner";

const ENTRY: ScanScopeEntry = {
  id: 1,
  tenant_id: "default",
  effect: "allow",
  kind: "cidr",
  value: "198.51.100.0/28",
  note: "lab",
  approved_by: "admin",
  approved_at: "2026-09-01T10:00:00Z",
};

type Reply = { status: number; data: unknown };

let client: QueryClient;
let originalAdapter: typeof api.defaults.adapter;

/** Only the transport is stubbed: `api.ts` — the request it builds and, more
 * to the point, the error text it makes out of a 422 — is what these tests are
 * about, so mocking `@/lib/api` would leave exactly the interesting part
 * untested. Each method is answered from its own queue; the last answer stands
 * for every further call of that method. */
function installTransport(answers: { get?: Reply[]; put?: Reply[] }) {
  const sent: unknown[] = [];
  const queues: Record<string, Reply[]> = {
    get: [...(answers.get ?? [])],
    put: [...(answers.put ?? [])],
  };
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    const method = (config.method ?? "get").toLowerCase();
    if (method === "put") sent.push(JSON.parse(String(config.data)));
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

describe("useScanScope", () => {
  it("returns the approved entries on the happy path", async () => {
    installTransport({ get: [{ status: 200, data: [ENTRY] }] });

    const { result } = renderHook(() => useScanScope("default"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([ENTRY]);
  });

  it("keeps an empty scope as an answer rather than an error", async () => {
    installTransport({ get: [{ status: 200, data: [] }] });

    const { result } = renderHook(() => useScanScope("default"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([]);
  });

  it("does not fetch for a caller without the admin role", () => {
    installTransport({ get: [{ status: 200, data: [ENTRY] }] });

    const { result } = renderHook(() => useScanScope("default", false), { wrapper });

    expect(result.current.fetchStatus).toBe("idle");
  });
});

describe("useReplaceScanScope", () => {
  it("sends the whole scope and caches what the server stored, not what was sent", async () => {
    // The API normalises: a host address inside a /24 comes back as the
    // network, and the editor is entitled to be corrected by that answer.
    const stored: ScanScopeEntry[] = [{ ...ENTRY, value: "10.0.0.0/24" }];
    const sent = installTransport({
      get: [{ status: 200, data: [ENTRY] }],
      put: [{ status: 200, data: stored }],
    });

    const { result } = renderHook(() => useReplaceScanScope("default"), { wrapper });
    result.current.mutate({
      entries: [{ effect: "allow", kind: "cidr", value: "10.0.0.5/24", note: "lab" }],
      baseline: scanScopeSignature([ENTRY]),
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(sent).toEqual([
      { entries: [{ effect: "allow", kind: "cidr", value: "10.0.0.5/24", note: "lab" }] },
    ]);
    expect(result.current.data).toEqual(stored);
    expect(client.getQueryData(queryKeys.scanScope("default"))).toEqual(stored);
  });

  it("says so when the tenant is left unable to scan anything", async () => {
    installTransport({ get: [{ status: 200, data: [ENTRY] }], put: [{ status: 200, data: [] }] });

    const { result } = renderHook(() => useReplaceScanScope("default"), { wrapper });
    result.current.mutate({ entries: [], baseline: scanScopeSignature([ENTRY]) });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(vi.mocked(toast.success).mock.calls[0]?.[1]).toEqual({
      description: "default can no longer scan anything",
    });
  });

  it("carries the API's 422 detail into the failure toast", async () => {
    // Verbatim what api/services/scan_scopes.py `_validated` raises: the admin
    // is told which value was refused, not that "the request failed".
    installTransport({
      get: [{ status: 200, data: [ENTRY] }],
      put: [{ status: 422, data: { detail: "not an IP or CIDR: '10.0.0'" } }],
    });

    const { result } = renderHook(() => useReplaceScanScope("default"), { wrapper });
    result.current.mutate({
      entries: [{ effect: "allow", kind: "cidr", value: "10.0.0", note: "" }],
      baseline: scanScopeSignature([ENTRY]),
    });

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toBe("not an IP or CIDR: '10.0.0'");
    expect(vi.mocked(toast.error).mock.calls[0]?.[1]).toEqual({
      description: "not an IP or CIDR: '10.0.0'",
    });
  });

  it("refuses to overwrite a scope that changed since the editor was seeded", async () => {
    const moved: ScanScopeEntry[] = [ENTRY, { ...ENTRY, id: 2, effect: "deny", value: "10.0.0.0/8" }];
    const sent = installTransport({ get: [{ status: 200, data: moved }] });

    const { result } = renderHook(() => useReplaceScanScope("default"), { wrapper });
    result.current.mutate({
      entries: [{ effect: "allow", kind: "cidr", value: "198.51.100.0/28", note: "lab" }],
      baseline: scanScopeSignature([ENTRY]),
    });

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(sent).toEqual([]);
    expect(vi.mocked(toast.error).mock.calls[0]?.[1]).toEqual({
      description: "Scan scope changed since you opened it — review the new entries and try again",
    });
    // The scope it found is left in the cache for the editor to reseed from.
    expect(client.getQueryData(queryKeys.scanScope("default"))).toEqual(moved);
  });

  it("does not mistake a re-approval of the same entries for a change", async () => {
    // Only what a PUT carries is compared: another admin approving the very
    // same scope restamps `approved_by`/`approved_at`, and that is not a scope
    // the editing admin needs to review.
    const restamped: ScanScopeEntry[] = [
      { ...ENTRY, approved_by: "root", approved_at: "2026-09-08T09:00:00Z" },
    ];
    const sent = installTransport({
      get: [{ status: 200, data: restamped }],
      put: [{ status: 200, data: restamped }],
    });

    const { result } = renderHook(() => useReplaceScanScope("default"), { wrapper });
    result.current.mutate({
      entries: [{ effect: "allow", kind: "cidr", value: "198.51.100.0/28", note: "lab" }],
      baseline: scanScopeSignature([ENTRY]),
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(sent).toHaveLength(1);
  });
});
