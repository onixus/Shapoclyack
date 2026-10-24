import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import { operatorApi } from "@/lib/operator-api";

beforeEach(() => vi.restoreAllMocks());
describe("operator transport boundaries", () => {
  it("resolves run summary citations with digest and snapshot revalidation", async () => {
    const get = vi.spyOn(api, "get").mockResolvedValue({ data: {} });
    await operatorApi.evidence("a", {
      source_type: "run",
      source_id: "run1",
      source_hash: "b".repeat(64),
      snapshot_id: "snap",
    });
    expect(get).toHaveBeenCalledWith(
      "/operator/evidence/runs/run1/summary",
      expect.objectContaining({
        params: { tenant_id: "a", source_hash: "b".repeat(64), snapshot_id: "snap" },
      }),
    );
  });
  it("always pins tenant and passes cancellation to read requests", async () => {
    const get = vi.spyOn(api, "get").mockResolvedValue({ data: {} });
    const signal = new AbortController().signal;
    await operatorApi.session("a", "s/foreign", signal);
    expect(get).toHaveBeenCalledWith("/operator/sessions/s%2Fforeign", {
      params: { tenant_id: "a" },
      signal,
    });
  });
  it("resolves source IDs through the fixed authenticated endpoint, never a model URL", async () => {
    const get = vi.spyOn(api, "get").mockResolvedValue({ data: {} });
    await operatorApi.evidence("a", {
      source_id: "https://evil.test/beacon",
      source_hash: "b".repeat(64),
      snapshot_id: "s",
    });
    expect(get).toHaveBeenCalledWith(
      "/operator/evidence/https%3A%2F%2Fevil.test%2Fbeacon",
      expect.objectContaining({
        params: { tenant_id: "a", source_hash: "b".repeat(64), snapshot_id: "s" },
      }),
    );
  });
  it("refuses empty tenant without sending a request", async () => {
    const get = vi.spyOn(api, "get");
    await expect(operatorApi.status(" ")).rejects.toThrow("Explicit tenant required");
    expect(get).not.toHaveBeenCalled();
  });
});
