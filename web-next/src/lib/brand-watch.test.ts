import { describe, expect, it, vi } from "vitest";
import {
  canSetBrandWatchDisposition,
  canWriteBrandWatch,
  createBrandWatchProfile,
  linesToList,
  parseCandidate,
  punycodeDisplay,
  severityLabel,
  sinceInstant,
} from "@/lib/brand-watch";
import { api } from "@/lib/api";

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

  it("lets an operator dispose and leaves a viewer with the label only", () => {
    expect(canSetBrandWatchDisposition(["brand_watch.read", "brand_watch.disposition"])).toBe(true);
    expect(canSetBrandWatchDisposition(["brand_watch.read"])).toBe(false);
    expect(canSetBrandWatchDisposition(undefined, true)).toBe(true);
    expect(canSetBrandWatchDisposition(undefined, false)).toBe(false);
  });

  it("lets a writer create a profile and leaves a reader without the form", () => {
    expect(canWriteBrandWatch(["brand_watch.read", "brand_watch.write"])).toBe(true);
    expect(canWriteBrandWatch(["brand_watch.read", "brand_watch.disposition"])).toBe(false);
    expect(canWriteBrandWatch(undefined)).toBe(false);
    expect(canWriteBrandWatch([])).toBe(false);
  });

  it("keeps one entry per non-empty line", () => {
    expect(linesToList(" example.com \n\nacme.test\r\n")).toEqual(["example.com", "acme.test"]);
    expect(linesToList("   \n")).toEqual([]);
  });

  it("reads a candidate name from the unicode field the API returns", () => {
    expect(
      parseCandidate({
        id: "bwc_1",
        name_unicode: "examp1e.com",
        name_punycode: "examp1e.com",
        state: "registered",
        disposition: "open",
      }),
    ).toMatchObject({ id: "bwc_1", name: "examp1e.com", state: "registered", disposition: "open" });
    expect(parseCandidate({ name_unicode: "missing-id.com" })).toBeNull();
  });

  it("creates a profile as not ours and does not claim a scan starts", async () => {
    const post = vi.spyOn(api, "post").mockResolvedValue({
      data: { id: "bwp_1", name: "Acme", official_domains: ["acme.test"], approved: false, our_brand: false },
    });
    const created = await createBrandWatchProfile({
      name: "Acme",
      official_domains: ["acme.test"],
      brand_strings: ["acme"],
      our_brand: false,
    });
    expect(post).toHaveBeenCalledWith("/brand-watch/profiles", {
      name: "Acme",
      official_domains: ["acme.test"],
      brand_strings: ["acme"],
      our_brand: false,
    });
    expect(created.approved).toBe(false);
    post.mockRestore();
  });

  it("turns a relative window into an ISO instant and leaves a blank window empty", () => {
    const now = new Date("2026-11-12T00:00:00.000Z");
    expect(sinceInstant("", now)).toBeNull();
    expect(sinceInstant("24h", now)).toBe("2026-11-11T00:00:00.000Z");
    expect(sinceInstant("7d", now)).toBe("2026-11-05T00:00:00.000Z");
  });
});
