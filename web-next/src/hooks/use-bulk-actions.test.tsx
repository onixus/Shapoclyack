import { afterEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { toast } from "sonner";
import type { ReactNode } from "react";
import type { BulkActionReport } from "@/lib/api";

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}));

// A counter, not a constant: a mock that returns the same key on every call
// cannot tell "the key is held for this submission" from "a fresh key per
// attempt", which is what the console actually shipped.
let minted = 0;
vi.mock("@/lib/api", () => ({
  bulkVulnerabilityAction: vi.fn(),
  bulkAssetAction: vi.fn(),
  newBulkIdempotencyKey: vi.fn(() => `console:bulk:${++minted}`),
}));

import { bulkAssetAction, bulkVulnerabilityAction } from "@/lib/api";
import {
  bulkFailureDetail,
  bulkSummary,
  useBulkAssetAction,
  useBulkSelection,
  useBulkVulnerabilityAction,
} from "@/hooks/use-bulk-actions";
import { useAuthStore } from "@/lib/auth-store";

function report(overrides: Partial<BulkActionReport> = {}): BulkActionReport {
  return {
    action: "assign",
    requested: 2,
    succeeded: 2,
    failed: 0,
    results: [
      { id: "vln_1", ok: true, outcome: "ok", error: null },
      { id: "vln_2", ok: true, outcome: "ok", error: null },
    ],
    replayed: false,
    ...overrides,
  };
}

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

afterEach(() => {
  vi.clearAllMocks();
  minted = 0;
});

function keyOfCall(index: number): string | undefined {
  return vi.mocked(bulkVulnerabilityAction).mock.calls[index][1]?.idempotencyKey;
}

describe("bulkSummary", () => {
  it("counts what applied, not what was requested", () => {
    expect(bulkSummary(report(), "finding")).toBe("2 findings updated");
    expect(bulkSummary(report({ succeeded: 1, failed: 1 }), "finding")).toBe(
      "1 finding updated, 1 skipped",
    );
  });

  it("says how many ids are left when the server ran out of time", () => {
    // The ids the batch never reached are not failures — nothing was asked of
    // them — and calling them "skipped" would tell the operator the selection
    // was rejected rather than that it is half done.
    const cut = report({
      succeeded: 1,
      // Not a failure: `failed` is what the API refused, and it refused
      // nothing here.
      failed: 0,
      not_attempted: 1,
      deadline: true,
      results: [
        { id: "vln_1", ok: true, outcome: "ok", error: null },
        { id: "vln_2", ok: false, outcome: "deadline", error: "not attempted" },
      ],
    });
    expect(bulkSummary(cut, "finding")).toBe(
      "1 finding updated, 1 left — select them again to finish",
    );
  });

  it("counts a refusal and an id nobody reached separately", () => {
    // The two live side by side in one report and mean different things: one
    // finding was refused, one was never asked. Reading `failed` as "both"
    // was what made the toast say two were skipped.
    const mixed = report({
      requested: 3,
      succeeded: 1,
      failed: 1,
      not_attempted: 1,
      deadline: true,
      results: [
        { id: "vln_1", ok: true, outcome: "ok", error: null },
        { id: "vln_2", ok: false, outcome: "conflict", error: "already CLOSED" },
        { id: "vln_3", ok: false, outcome: "deadline", error: "not attempted" },
      ],
    });
    expect(bulkSummary(mixed, "finding")).toBe(
      "1 finding updated, 1 skipped, 1 left — select them again to finish",
    );
    // And the toast's description names the refusal, not the budget message.
    expect(bulkFailureDetail(mixed)).toBe("already CLOSED");
  });

  it("says a replay applied nothing now", () => {
    // The batch was applied by the earlier request this one is a retry of;
    // reporting it as fresh work would tell the operator the click landed
    // twice.
    expect(bulkSummary(report({ replayed: true }), "finding")).toBe(
      "2 findings updated (already applied — replayed)",
    );
  });
});

describe("bulkFailureDetail", () => {
  it("is undefined when nothing failed", () => {
    expect(bulkFailureDetail(report())).toBeUndefined();
  });

  it("groups the reasons and counts the repeats", () => {
    const detail = bulkFailureDetail(
      report({
        succeeded: 0,
        failed: 3,
        results: [
          { id: "a", ok: false, outcome: "conflict", error: "already ACKNOWLEDGED" },
          { id: "b", ok: false, outcome: "conflict", error: "already ACKNOWLEDGED" },
          { id: "c", ok: false, outcome: "not_found", error: "not found in this tenant" },
        ],
      }),
    );
    expect(detail).toBe("already ACKNOWLEDGED (×2); not found in this tenant");
  });
});

describe("useBulkVulnerabilityAction", () => {
  it("sends an idempotency key", async () => {
    vi.mocked(bulkVulnerabilityAction).mockResolvedValue(report());
    const { result } = renderHook(() => useBulkVulnerabilityAction(), { wrapper });

    result.current.mutate({
      action: "assign",
      vuln_ids: ["vln_1", "vln_2"],
      payload: { assignee: "ada" },
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(keyOfCall(0)).toMatch(/^console:bulk:/);
    expect(toast.success).toHaveBeenCalledWith("2 findings updated");
  });

  it("retries the same submission under the same key", async () => {
    // The scenario: the proxy cuts the connection on a batch of two hundred,
    // the operator clicks Apply again. A new key would be a batch the server
    // has never seen, and two hundred transitions would apply twice.
    const body = {
      action: "assign" as const,
      vuln_ids: ["vln_1", "vln_2"],
      payload: { assignee: "ada" },
    };
    vi.mocked(bulkVulnerabilityAction).mockRejectedValueOnce(new Error("504 Gateway Timeout"));
    vi.mocked(bulkVulnerabilityAction).mockResolvedValue(report());
    const { result } = renderHook(() => useBulkVulnerabilityAction(), { wrapper });

    result.current.mutate(body);
    await waitFor(() => expect(result.current.isError).toBe(true));
    result.current.mutate(body);
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(vi.mocked(bulkVulnerabilityAction)).toHaveBeenCalledTimes(2);
    expect(keyOfCall(1)).toBe(keyOfCall(0));
  });

  it("gives the operator's next, different batch its own key", async () => {
    vi.mocked(bulkVulnerabilityAction).mockResolvedValue(report());
    const { result } = renderHook(() => useBulkVulnerabilityAction(), { wrapper });

    result.current.mutate({
      action: "assign",
      vuln_ids: ["vln_1"],
      payload: { assignee: "ada" },
    });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    result.current.mutate({
      action: "assign",
      vuln_ids: ["vln_2"],
      payload: { assignee: "grace" },
    });
    await waitFor(() => expect(vi.mocked(bulkVulnerabilityAction)).toHaveBeenCalledTimes(2));

    // Reusing the first key for a different body is the server's 409, and
    // calling a second, deliberate batch a replay of the first would be worse.
    expect(keyOfCall(1)).not.toBe(keyOfCall(0));
  });

  it("warns rather than congratulating when part of the batch was skipped", async () => {
    vi.mocked(bulkVulnerabilityAction).mockResolvedValue(
      report({
        succeeded: 1,
        failed: 1,
        results: [
          { id: "vln_1", ok: true, outcome: "ok", error: null },
          { id: "vln_2", ok: false, outcome: "not_found", error: "not found in this tenant" },
        ],
      }),
    );
    const { result } = renderHook(() => useBulkVulnerabilityAction(), { wrapper });

    result.current.mutate({
      action: "assign",
      vuln_ids: ["vln_1", "vln_2"],
      payload: { assignee: "ada" },
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(toast.success).not.toHaveBeenCalled();
    expect(toast.warning).toHaveBeenCalledWith("1 finding updated, 1 skipped", {
      description: "not found in this tenant",
    });
  });

  it("reports a request that never landed as an error", async () => {
    vi.mocked(bulkVulnerabilityAction).mockRejectedValue(new Error("Idempotency-Key taken"));
    const { result } = renderHook(() => useBulkVulnerabilityAction(), { wrapper });

    result.current.mutate({
      action: "assign",
      vuln_ids: ["vln_1"],
      payload: { assignee: "ada" },
    });

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(toast.error).toHaveBeenCalledWith("Bulk action failed", {
      description: "Idempotency-Key taken",
    });
  });
});

describe("useBulkAssetAction", () => {
  it("posts the selection and its context payload", async () => {
    vi.mocked(bulkAssetAction).mockResolvedValue(
      report({ action: "context", requested: 1, succeeded: 1, results: [
        { id: "ast_1", ok: true, outcome: "ok", error: null },
      ] }),
    );
    const { result } = renderHook(() => useBulkAssetAction(), { wrapper });

    result.current.mutate({
      action: "context",
      asset_ids: ["ast_1"],
      payload: { owner_email: "ada@example.com" },
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(vi.mocked(bulkAssetAction).mock.calls[0][0]).toEqual({
      action: "context",
      asset_ids: ["ast_1"],
      payload: { owner_email: "ada@example.com" },
    });
    expect(toast.success).toHaveBeenCalledWith("1 asset updated");
  });
});

describe("useBulkSelection", () => {
  it("drops the selection when the tenant changes", () => {
    useAuthStore.setState({ activeTenant: "acme" });
    const { result } = renderHook(() => useBulkSelection());

    act(() => result.current[1](["vln_1", "vln_2"]));
    expect(result.current[0]).toEqual(["vln_1", "vln_2"]);

    // Those ids belong to acme. Kept across a tenant switch they come back
    // `not_found`, and at the 200-id ceiling they disable every checkbox on a
    // page where nothing is selected at all.
    act(() => useAuthStore.setState({ activeTenant: "other" }));
    expect(result.current[0]).toEqual([]);
  });

  it("keeps a selection that is still being built in one tenant", () => {
    useAuthStore.setState({ activeTenant: "acme" });
    const { result, rerender } = renderHook(() => useBulkSelection());

    act(() => result.current[1](["vln_1"]));
    // A poll, a page or a filter change re-renders the page; the selection is
    // the operator's work and survives all three.
    rerender();
    expect(result.current[0]).toEqual(["vln_1"]);
  });
});
