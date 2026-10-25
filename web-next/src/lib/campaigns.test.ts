import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import {
  campaignsApi,
  dueAtFromInput,
  findingFilterParams,
  localDateInput,
  problemsApi,
  selectionFromFilters,
} from "@/lib/campaigns";

afterEach(() => vi.restoreAllMocks());

describe("problem and campaign request contracts (#579)", () => {
  it("sends the findings list's filters under the same names", () => {
    expect(
      findingFilterParams({
        state: "",
        open_only: true,
        severity: "high",
        asset_id: "a1",
        unassigned: true,
        sla: "breached",
        in_kev: true,
        stale_days: 30,
        network_exposure: "unknown",
      }),
    ).toEqual({
      open_only: "true",
      severity: "high",
      asset_id: "a1",
      unassigned: "true",
      sla: "breached",
      in_kev: "true",
      network_exposure: "unknown",
      stale_days: "30",
    });
    // The drill-down key is not a list filter of the aggregate itself.
    expect(findingFilterParams({ problem_key: "cve:CVE-2024-1" })).toEqual({});
  });

  it("lists problems with filters and server-side sort", async () => {
    const get = vi.spyOn(api, "get").mockResolvedValue({ data: { items: [], aggregates: {} } });
    await problemsApi.list({ severity: "critical" }, { offset: 50, limit: 25, sort: "instances", order: "desc" });
    expect(get).toHaveBeenCalledWith("/problems", {
      params: { severity: "critical", offset: 50, limit: 25, sort: "instances", order: "desc" },
    });
  });

  it("asks the drill-down for drift with the row's own count and time", async () => {
    const get = vi.spyOn(api, "get").mockResolvedValue({ data: { items: [], drift: null } });
    await problemsApi.instances("cve:CVE-2024-1", { severity: "high" }, { limit: 1 }, {
      as_of: "2026-10-24T10:00:00Z",
      expected_instances: 7,
    });
    expect(get).toHaveBeenCalledWith("/problems/instances", {
      params: {
        severity: "high",
        limit: 1,
        problem_key: "cve:CVE-2024-1",
        as_of: "2026-10-24T10:00:00Z",
        expected_instances: 7,
      },
    });
  });

  it("creates a campaign with an Idempotency-Key and the reviewed composition hash", async () => {
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: { campaign_id: "cmp_1" } });
    const body = {
      name: "Upgrade openssl",
      selection: { problem_keys: ["cve:CVE-2024-1"] },
      composition_hash: "abc",
    };
    await campaignsApi.create(body, "console:bulk:k1");
    expect(post).toHaveBeenCalledWith("/remediation-campaigns", body, {
      headers: { "Idempotency-Key": "console:bulk:k1" },
    });
  });

  it("escapes campaign ids and sends a reason with every membership change", async () => {
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: {} });
    await campaignsApi.excludeMembers("cmp/1", ["v1"], "decommissioned");
    expect(post).toHaveBeenCalledWith("/remediation-campaigns/cmp%2F1/members/exclude", {
      vuln_ids: ["v1"],
      reason: "decommissioned",
    });
    await campaignsApi.addMembers("cmp_1", { vuln_ids: ["v2"] }, "same class");
    expect(post).toHaveBeenLastCalledWith("/remediation-campaigns/cmp_1/members", {
      selection: { vuln_ids: ["v2"] },
      reason: "same class",
    });
  });

  it("verifies all ready members by default and only the named ones otherwise", async () => {
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: { results: [], summary: {} } });
    await campaignsApi.verify("cmp_1");
    expect(post).toHaveBeenLastCalledWith("/remediation-campaigns/cmp_1/verify", {}, undefined);
    await campaignsApi.verify("cmp_1", ["v1"], "k2");
    expect(post).toHaveBeenLastCalledWith(
      "/remediation-campaigns/cmp_1/verify",
      { vuln_ids: ["v1"] },
      { headers: { "Idempotency-Key": "k2" } },
    );
  });

  it("builds a selection whose filters narrow problem keys only", () => {
    expect(
      selectionFromFilters(["cve:CVE-2024-1"], [], { open_only: true, severity: "high", unassigned: true, stale_days: 14 }),
    ).toEqual({
      problem_keys: ["cve:CVE-2024-1"],
      filters: { severity: "high", unassigned: true, stale_days: 14 },
    });
    // Explicit findings are taken as they are: filters never drop one silently.
    expect(selectionFromFilters([], ["v1", "v2"], { severity: "high" })).toEqual({ vuln_ids: ["v1", "v2"] });
  });
});

describe("campaign due dates in a negative UTC offset", () => {
  const original = process.env.TZ;
  beforeAll(() => {
    process.env.TZ = "America/Los_Angeles"; // UTC-8 in November
  });
  afterAll(() => {
    if (original === undefined) delete process.env.TZ;
    else process.env.TZ = original;
  });

  it("shows the local day and saves the same instant back", () => {
    // End of 29 November local time is already 30 November in UTC.
    const stored = "2026-11-30T07:59:59.000Z";
    expect(localDateInput(stored)).toBe("2026-11-29");
    expect(dueAtFromInput("2026-11-29")).toBe(stored);
    expect(dueAtFromInput("")).toBeNull();
    expect(localDateInput(null)).toBe("");
  });
});
