import { describe, expect, it } from "vitest";
import type { AssetContextEvent, AssetRisk } from "@/lib/api";
import {
  ASSET_DATA_CLASSIFICATIONS,
  ASSET_ENVIRONMENTS,
  ASSET_EXPOSURE_LEVELS,
  assetRiskLabel,
  describeContextEvent,
} from "@/lib/asset-context";

function event(overrides: Partial<AssetContextEvent> = {}): AssetContextEvent {
  return {
    id: 1,
    asset_id: "a1",
    tenant_id: "default",
    occurred_at: "2026-08-19T12:00:00",
    field: "environment",
    old_value: null,
    new_value: "production",
    actor: "operator",
    source: "cmdb",
    ...overrides,
  };
}

function risk(overrides: Partial<AssetRisk> = {}): AssetRisk {
  return {
    total: 0,
    open_total: 0,
    untriaged: 0,
    unassigned: 0,
    estate_risk: null,
    by_state: {},
    by_severity_open: {},
    by_risk_level_open: {},
    by_sla: {},
    breached: 0,
    worst_breached_severity: null,
    generated_at: null,
    ...overrides,
  };
}

describe("asset context vocabularies", () => {
  it("match the closed lists the API accepts", () => {
    expect([...ASSET_ENVIRONMENTS]).toEqual([
      "production",
      "staging",
      "development",
      "lab",
      "other",
    ]);
    expect([...ASSET_DATA_CLASSIFICATIONS]).toEqual([
      "public",
      "internal",
      "confidential",
      "restricted",
    ]);
    expect([...ASSET_EXPOSURE_LEVELS]).toEqual(["internet", "partner", "internal", "unknown"]);
  });
});

describe("describeContextEvent", () => {
  it("names the field and the before/after values", () => {
    expect(describeContextEvent(event())).toBe("Environment: unset → production");
    expect(
      describeContextEvent(event({ field: "owner_email", old_value: "a@x", new_value: null })),
    ).toBe("Owner: a@x → unset");
  });
});

describe("assetRiskLabel", () => {
  it("uses the NIST label when a level is present", () => {
    expect(assetRiskLabel(risk({ estate_risk: "very_high", open_total: 2 }))).toBe("very high");
  });

  it("says none when there is no open work", () => {
    expect(assetRiskLabel(risk({ open_total: 0, estate_risk: null }))).toBe("none");
  });

  it("says unset when open findings have no NIST level yet", () => {
    expect(assetRiskLabel(risk({ open_total: 2, estate_risk: null }))).toBe("unset");
  });
});
