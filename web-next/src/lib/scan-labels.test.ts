import { describe, expect, it } from "vitest";
import { scanIntentLabel, scanModeLabel, scanExecutionLabel, scanTargetLabel } from "./scan-labels";
describe("scan presentation", () => {
  it("translates all supported scan profiles and intents", () => {
    for (const v of ["inventory", "vuln", "full", "delta", "org_profile", "legacy"])
      expect(scanIntentLabel("ru", v)).not.toBe(v);
    for (const v of ["safe", "balanced", "fast", "test"])
      expect(scanModeLabel("ru", v)).not.toBe(v);
    expect(scanExecutionLabel("ru", "local")).toBe("Локально");
    expect(scanExecutionLabel("ru", "agent")).toBe("На агенте");
    expect(scanTargetLabel("ru", "domains")).toBe("Домены");
  });
  it("does not invent a translation for unrecognized backend codes", () => {
    expect(scanModeLabel("ru", "future_profile")).toBe("Другой вариант");
    expect(scanModeLabel("en", "future_profile")).toBe("future_profile");
  });
});
