import { describe, expect, it } from "vitest";
import type { AgentInfo } from "@/lib/api";
import { SEVERITIES } from "@/lib/run-data";
import {
  AGENT_STATUS,
  ASSET_STATUS,
  JOB_STATUS,
  SEVERITY_STATUS,
  TENANT_STATUS,
  agentEffectiveStatus,
} from "@/lib/config/statuses";

function makeAgent(overrides: Partial<AgentInfo>): AgentInfo {
  return {
    agent_id: "a1",
    hostname: "host",
    version: "1.0",
    labels: {},
    status: "idle",
    current_job_id: null,
    detail: null,
    registered_at: null,
    last_seen_at: null,
    online: true,
    ...overrides,
  };
}

describe("status maps", () => {
  it("cover every expected status value", () => {
    expect(Object.keys(JOB_STATUS).sort()).toEqual(["failed", "queued", "running", "succeeded"]);
    expect(Object.keys(AGENT_STATUS).sort()).toEqual(["busy", "error", "idle", "offline", "stale"]);
    expect(Object.keys(TENANT_STATUS).sort()).toEqual(["active", "disabled"]);
    expect(Object.keys(ASSET_STATUS).sort()).toEqual(["active", "decommissioned", "stale"]);
    expect(Object.keys(SEVERITY_STATUS).sort()).toEqual([...SEVERITIES].sort());
  });

  it("give every entry a label and either a variant or a color class", () => {
    for (const map of [JOB_STATUS, AGENT_STATUS, TENANT_STATUS, ASSET_STATUS, SEVERITY_STATUS]) {
      for (const style of Object.values(map)) {
        expect(style.label).toBeTruthy();
        expect(Boolean(style.variant || style.className)).toBe(true);
      }
    }
  });

  it("assign a Tremor color to every severity", () => {
    for (const style of Object.values(SEVERITY_STATUS)) {
      expect(style.tremorColor).toBeTruthy();
    }
  });
});

describe("agentEffectiveStatus", () => {
  it("returns offline when the agent is not online, regardless of status", () => {
    expect(agentEffectiveStatus(makeAgent({ online: false, status: "busy" }))).toBe("offline");
  });

  it("returns the reported status when online", () => {
    expect(agentEffectiveStatus(makeAgent({ status: "busy" }))).toBe("busy");
    expect(agentEffectiveStatus(makeAgent({ status: "idle" }))).toBe("idle");
  });
});
