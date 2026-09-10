import { afterEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { toast } from "sonner";
import type { ReactNode } from "react";
import type { BulkActionReport } from "@/lib/api";

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}));

vi.mock("@/lib/api", () => ({
  bulkVulnerabilityAction: vi.fn(),
  bulkAssetAction: vi.fn(),
  newBulkIdempotencyKey: vi.fn(() => "console:bulk:fixed"),
}));

import { bulkAssetAction, bulkVulnerabilityAction } from "@/lib/api";
import {
  bulkFailureDetail,
  bulkSummary,
  useBulkAssetAction,
  useBulkVulnerabilityAction,
} from "@/hooks/use-bulk-actions";

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
});

describe("bulkSummary", () => {
  it("counts what applied, not what was requested", () => {
    expect(bulkSummary(report(), "finding")).toBe("2 findings updated");
    expect(bulkSummary(report({ succeeded: 1, failed: 1 }), "finding")).toBe(
      "1 finding updated, 1 skipped",
    );
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
  it("sends an idempotency key so a retried batch is not applied twice", async () => {
    vi.mocked(bulkVulnerabilityAction).mockResolvedValue(report());
    const { result } = renderHook(() => useBulkVulnerabilityAction(), { wrapper });

    result.current.mutate({
      action: "assign",
      vuln_ids: ["vln_1", "vln_2"],
      payload: { assignee: "ada" },
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(vi.mocked(bulkVulnerabilityAction).mock.calls[0][1]).toEqual({
      idempotencyKey: "console:bulk:fixed",
    });
    expect(toast.success).toHaveBeenCalledWith("2 findings updated");
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
