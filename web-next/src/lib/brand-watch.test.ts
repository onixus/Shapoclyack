import { describe, expect, it } from "vitest";
import { punycodeDisplay, severityLabel, sinceInstant } from "@/lib/brand-watch";

describe("brand-watch formatters", () => {
  it("labels known severities and leaves unknown text alone", () => {
    expect(severityLabel("high")).toBe("High");
    expect(severityLabel("CRITICAL")).toBe("Critical");
    expect(severityLabel("informational")).toBe("Informational");
    expect(severityLabel("info")).toBe("Informational");
    expect(severityLabel("watch")).toBe("watch");
    expect(severityLabel(null)).toBe("—");
    expect(severityLabel("  ")).toBe("—");
  });

  it("shows a distinct punycode form next to the name and hides a duplicate", () => {
    expect(punycodeDisplay("пример.рф", "xn--e1afmkfd.xn--p1ai")).toBe(
      "пример.рф (xn--e1afmkfd.xn--p1ai)",
    );
    expect(punycodeDisplay("example.com", "example.com")).toBe("example.com");
    expect(punycodeDisplay("example.com", null)).toBe("example.com");
    expect(punycodeDisplay("  Example.COM  ", "example.com")).toBe("Example.COM");
  });

  it("turns a relative window into an ISO instant and leaves a blank window empty", () => {
    const now = new Date("2026-11-12T00:00:00.000Z");
    expect(sinceInstant("", now)).toBeNull();
    expect(sinceInstant("24h", now)).toBe("2026-11-11T00:00:00.000Z");
    expect(sinceInstant("7d", now)).toBe("2026-11-05T00:00:00.000Z");
  });
});
