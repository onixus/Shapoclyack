import { describe, expect, it } from "vitest";
import { absoluteTime, relativeTime } from "@/lib/i18n/datetime";

describe("relativeTime", () => {
  it("answers in the console's language", () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 3600 * 1000);
    // The defect this exists for: every call site was a bare
    // formatDistanceToNow, so a Russian console said "about 2 hours ago" in
    // the middle of a Russian table.
    expect(relativeTime(twoHoursAgo, "en")).toMatch(/hours ago/);
    expect(relativeTime(twoHoursAgo, "ru")).toMatch(/часов назад/);
  });

  it("answers the dash for the values an API legitimately sends", () => {
    // never seen, never inventoried, no last run — all null in the schema, and
    // all rendered "Invalid Date" before.
    expect(relativeTime(null, "ru")).toBe("—");
    expect(relativeTime(undefined, "ru")).toBe("—");
    expect(relativeTime("", "ru")).toBe("—");
    expect(relativeTime("not a date", "ru")).toBe("—");
  });
});

describe("absoluteTime", () => {
  it("formats the instant in the locale's own order", () => {
    const iso = "2026-09-15T16:20:18.000Z";
    // Day-first in Russian, month-first in English. Compared loosely because
    // the value is rendered in the runner's zone, not UTC.
    expect(absoluteTime(iso, "ru")).toMatch(/^\d{2}\.\d{2}\.2026, \d{2}:\d{2}:\d{2}$/);
    expect(absoluteTime(iso, "en")).toMatch(/^\d{2}\/\d{2}\/2026/);
  });

  it("does not print Invalid Date", () => {
    expect(absoluteTime(null, "en")).toBe("—");
    expect(absoluteTime("nonsense", "en")).toBe("—");
  });
});
