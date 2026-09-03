import { describe, expect, it } from "vitest";
import type { UsageResource } from "@/lib/api";
import {
  barPercent,
  limitLabel,
  monthLabel,
  parseQuotaInput,
  periodLabel,
  pressure,
  quotaInputValue,
  ratioLabel,
  sortByPressure,
  usageTone,
} from "@/lib/usage-format";

function resource(overrides: Partial<UsageResource> = {}): UsageResource {
  return { used: 10, limit: 100, remaining: 90, used_ratio: 0.1, over_limit: false, ...overrides };
}

const unlimited = resource({ limit: null, remaining: null, used_ratio: null });

describe("limits", () => {
  it("spells an absent ceiling out rather than showing a number", () => {
    expect(limitLabel(null)).toBe("Unlimited");
    expect(limitLabel(2000)).toBe((2000).toLocaleString());
  });

  it("never turns an unlimited quota into a percentage", () => {
    expect(ratioLabel(null)).toBe("n/a");
    expect(ratioLabel(0)).toBe("0%");
    expect(ratioLabel(0.406)).toBe("40.6%");
  });

  it("draws no bar at all when there is no ceiling, and never overfills one", () => {
    expect(barPercent(null)).toBeNull();
    expect(barPercent(0.3)).toBe(30);
    expect(barPercent(1.4)).toBe(100);
  });
});

describe("usageTone", () => {
  it("flags the last fifth of a quota and anything past it", () => {
    expect(usageTone(resource())).toBe("ok");
    expect(usageTone(resource({ used_ratio: 0.8 }))).toBe("near");
    expect(usageTone(resource({ used_ratio: 1.2, over_limit: true }))).toBe("over");
  });

  it("treats an unlimited quota as nothing to warn about", () => {
    expect(usageTone(unlimited)).toBe("ok");
  });
});

describe("pressure ordering", () => {
  it("floats the tenant closest to a ceiling to the top and sinks unlimited ones", () => {
    const rows = [
      { tenant_id: "calm", assets: resource({ used_ratio: 0.2 }), scans: unlimited },
      { tenant_id: "free", assets: unlimited, scans: unlimited },
      { tenant_id: "over", assets: resource({ used_ratio: 1.1, over_limit: true }), scans: unlimited },
      { tenant_id: "near", assets: resource({ used_ratio: 0.9 }), scans: unlimited },
    ];
    expect(sortByPressure(rows).map((row) => row.tenant_id)).toEqual([
      "over",
      "near",
      "calm",
      "free",
    ]);
  });

  it("takes the worse of the two resources", () => {
    expect(pressure({ assets: resource({ used_ratio: 0.1 }), scans: resource({ used_ratio: 0.7 }) })).toBe(0.7);
  });

  it("leaves the caller's array alone", () => {
    const rows = [
      { tenant_id: "a", assets: resource({ used_ratio: 0.1 }), scans: unlimited },
      { tenant_id: "b", assets: resource({ used_ratio: 0.9 }), scans: unlimited },
    ];
    sortByPressure(rows);
    expect(rows.map((row) => row.tenant_id)).toEqual(["a", "b"]);
  });
});

describe("labels", () => {
  it("renders the billing period as a day range", () => {
    expect(periodLabel("2026-09-01T00:00:00", "2026-10-01T00:00:00")).toBe(
      "2026-09-01 → 2026-10-01",
    );
  });

  it("names the month on the history axis", () => {
    expect(monthLabel("2026-09")).toBe("Sep 2026");
    expect(monthLabel("nonsense")).toBe("nonsense");
  });
});

describe("quota input", () => {
  it("reads an empty box, a zero and junk all as unlimited", () => {
    expect(parseQuotaInput("")).toBeNull();
    expect(parseQuotaInput("   ")).toBeNull();
    expect(parseQuotaInput("0")).toBeNull();
    expect(parseQuotaInput("-5")).toBeNull();
    expect(parseQuotaInput("abc")).toBeNull();
  });

  it("keeps a whole positive ceiling", () => {
    expect(parseQuotaInput(" 2000 ")).toBe(2000);
    expect(parseQuotaInput("40.7")).toBe(40);
  });

  it("shows an unlimited ceiling as an empty box, not a zero", () => {
    expect(quotaInputValue(null)).toBe("");
    expect(quotaInputValue(40)).toBe("40");
  });
});
