import { describe, expect, it } from "vitest";
import type { TrackedVulnerability } from "@/lib/api";
import { canDropOn, groupByState } from "@/lib/remediation";

function stub(overrides: Partial<TrackedVulnerability>): TrackedVulnerability {
  return {
    vuln_id: "v1",
    tenant_id: "default",
    asset_id: "a1",
    finding_key: "k",
    cve: "CVE-1",
    script_id: null,
    title: "",
    port: "443",
    severity: "high",
    risk_level: "high",
    contextual_score: 7,
    cvss: 7,
    in_kev: false,
    exploit_maturity: null,
    state: "OPEN",
    state_changed_at: null,
    state_changed_by: null,
    assignee: null,
    owner_team: null,
    due_at: null,
    sla_days: 30,
    sla_source: "default",
    sla_state: "on_track",
    exception_until: null,
    exception_reason: null,
    exception_by: null,
    first_seen_at: null,
    last_seen_at: null,
    sla_started_at: null,
    first_seen_run_id: null,
    last_seen_run_id: null,
    observation_count: 1,
    reopen_count: 0,
    closed_at: null,
    ticket_system: null,
    ticket_key: null,
    ticket_url: null,
    ...overrides,
  };
}

describe("groupByState", () => {
  it("puts each finding in its lifecycle column", () => {
    const grouped = groupByState([
      stub({ vuln_id: "o", state: "OPEN" }),
      stub({ vuln_id: "f", state: "FIXING" }),
      stub({ vuln_id: "c", state: "CLOSED" }),
    ]);
    expect(grouped.OPEN.map((row) => row.vuln_id)).toEqual(["o"]);
    expect(grouped.FIXING.map((row) => row.vuln_id)).toEqual(["f"]);
    expect(grouped.CLOSED.map((row) => row.vuln_id)).toEqual(["c"]);
    expect(grouped.PLANNED).toEqual([]);
  });
});

describe("canDropOn", () => {
  it("allows documented skips and refuses same-state or illegal moves", () => {
    expect(canDropOn("OPEN", "FIXING")).toBe(true);
    expect(canDropOn("OPEN", "OPEN")).toBe(false);
    expect(canDropOn("VERIFYING", "PLANNED")).toBe(false);
    expect(canDropOn("CLOSED", "OPEN")).toBe(true);
  });
});
