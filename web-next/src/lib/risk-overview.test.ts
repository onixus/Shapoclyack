import { describe, expect, it } from "vitest";
import type { VulnerabilitySummary } from "@/lib/api";
import { estateRiskColor, estateRiskLabel } from "@/lib/risk-overview";

function summary(overrides: Partial<VulnerabilitySummary>): VulnerabilitySummary {
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

describe("estateRiskColor", () => {
  it("uses rose for high and very high, emerald for the low end", () => {
    expect(estateRiskColor("very_high")).toBe("rose");
    expect(estateRiskColor("high")).toBe("rose");
    expect(estateRiskColor("moderate")).toBe("amber");
    expect(estateRiskColor("low")).toBe("emerald");
    expect(estateRiskColor("very_low")).toBe("emerald");
    expect(estateRiskColor(null)).toBe("slate");
  });
});

describe("estateRiskLabel", () => {
  it("shows the NIST label when a worst open finding exists", () => {
    expect(estateRiskLabel(summary({ open_total: 3, estate_risk: "very_high" }))).toBe("very high");
  });

  it("says none when the estate has no open work", () => {
    expect(estateRiskLabel(summary({ open_total: 0, estate_risk: null }))).toBe("none");
  });

  it("says unset when open findings have no risk_level yet", () => {
    expect(estateRiskLabel(summary({ open_total: 2, estate_risk: null }))).toBe("unset");
  });

  it("is a placeholder before the summary arrives", () => {
    expect(estateRiskLabel(undefined)).toBe("…");
  });
});
