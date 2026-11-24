import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import { operatorApi } from "@/lib/operator-api";

beforeEach(() => vi.restoreAllMocks());
describe("operator transport boundaries", () => {
  it("binds finding remediation and source reads to fixed tenant-scoped routes", async () => {
    const get = vi.spyOn(api, "get").mockResolvedValue({ data: {} });
    await operatorApi.findingRemediation("a", "finding/1", "en");
    expect(get).toHaveBeenLastCalledWith(
      "/operator/remediation/findings/finding%2F1",
      expect.objectContaining({ params: { tenant_id: "a", language: "en" } }),
    );
    await operatorApi.findingRemediationSource("a", "finding/1", {
      source_id: "guide/1",
      snapshot_id: "snap",
      source_hash: "hash",
    });
    expect(get).toHaveBeenLastCalledWith(
      "/operator/remediation/findings/finding%2F1/sources/guide%2F1",
      expect.objectContaining({
        params: { tenant_id: "a", snapshot_id: "snap", source_hash: "hash" },
      }),
    );
  });
  it("queues planner requests with an explicit tenant and the caller's idempotency key", async () => {
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: {} });
    const body = {
      request: "Summarize selected run",
      language: "en" as const,
      context: { run_id: "run1" },
    };
    await operatorApi.plan("a", "s/foreign", body, "same-request");
    expect(post).toHaveBeenCalledWith("/operator/sessions/s%2Fforeign/plan", body, {
      params: { tenant_id: "a" },
      signal: undefined,
      headers: { "Idempotency-Key": "same-request" },
    });
  });
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
  it("deletes a session and closes an unresolved proposal on tenant-scoped routes", async () => {
    const del = vi.spyOn(api, "delete").mockResolvedValue({ data: undefined });
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: {} });
    await operatorApi.deleteSession("a", "s/1");
    expect(del).toHaveBeenCalledWith("/operator/sessions/s%2F1", {
      params: { tenant_id: "a" },
      signal: undefined,
    });
    await operatorApi.closeProposal("a", "p/1", "no_effect");
    expect(post).toHaveBeenCalledWith(
      "/operator/proposals/p%2F1/close",
      { resolution: "no_effect" },
      { params: { tenant_id: "a" }, signal: undefined },
    );
  });
  it("posts an applicability review without inferring evidence", async () => {
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: {} });
    const body = {
      finding_sha256: "a".repeat(64),
      source_sha256: "b".repeat(64),
      product: "apache_httpd" as const,
      version: "2.4.62",
      evidence_kind: "authenticated_process_inventory" as const,
      evidence_sha256: "c".repeat(64),
      reviewed: true as const,
    };
    await operatorApi.reviewApplicability("a", "finding/1", body);
    expect(post).toHaveBeenCalledWith(
      "/operator/remediation/findings/finding%2F1/applicability-review",
      body,
      { params: { tenant_id: "a" }, signal: undefined },
    );
  });
  it("refuses empty tenant without sending a request", async () => {
    const get = vi.spyOn(api, "get");
    await expect(operatorApi.status(" ")).rejects.toThrow("Explicit tenant required");
    expect(get).not.toHaveBeenCalled();
  });
});
