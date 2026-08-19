import { describe, expect, it } from "vitest";
import {
  assetDetailHref,
  findingLabel,
  legalTransitions,
  VULN_PRIMARY_NEXT,
  VULN_STATES,
  VULN_TRANSITIONS,
  vulnDetailHref,
  vulnListHref,
} from "@/lib/vuln-lifecycle";

describe("legalTransitions", () => {
  it("matches the backend happy path and the documented skips", () => {
    expect(legalTransitions("OPEN")).toEqual(["ACKNOWLEDGED", "PLANNED", "FIXING", "CLOSED"]);
    expect(legalTransitions("VERIFYING")).toEqual(["FIXING", "CLOSED"]);
    expect(legalTransitions("CLOSED")).toEqual(["OPEN"]);
  });

  it("never lists a same-state move", () => {
    for (const state of VULN_STATES) {
      expect(VULN_TRANSITIONS[state]).not.toContain(state);
      expect(legalTransitions(state)).toContain(VULN_PRIMARY_NEXT[state]);
    }
  });
});

describe("href helpers", () => {
  it("build static-export query URLs", () => {
    expect(vulnDetailHref("vuln_1")).toBe("/vulnerabilities/view?vulnId=vuln_1");
    expect(vulnDetailHref("vuln_1", "acme")).toBe(
      "/vulnerabilities/view?vulnId=vuln_1&tenantId=acme",
    );
    expect(assetDetailHref("asset_1", "acme")).toBe("/assets/view?assetId=asset_1&tenantId=acme");
    expect(vulnListHref({ assetId: "asset_1", sla: "breached" })).toBe(
      "/vulnerabilities?assetId=asset_1&sla=breached",
    );
    expect(vulnListHref({ unassigned: true, severity: "critical" })).toBe(
      "/vulnerabilities?severity=critical&unassigned=1",
    );
  });
});

describe("findingLabel", () => {
  it("prefers CVE, then script, then title", () => {
    expect(findingLabel({ cve: "CVE-2024-1", script_id: "ssl", title: "t" })).toBe("CVE-2024-1");
    expect(findingLabel({ cve: null, script_id: "ssl-cert", title: "t" })).toBe("ssl-cert");
    expect(findingLabel({ cve: null, script_id: null, title: "expired cert" })).toBe(
      "expired cert",
    );
    expect(findingLabel({ cve: null, script_id: null, title: "" })).toBe("finding");
  });
});
