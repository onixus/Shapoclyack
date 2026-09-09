import { describe, expect, it } from "vitest";
import {
  classifyRange,
  classifyTargets,
  jobSurface,
  runSurface,
  scheduleSurface,
  splitTargetLines,
  surfaceHref,
} from "@/lib/scan-surface";

describe("classifyTargets", () => {
  it("reads private v4 space as internal", () => {
    expect(classifyTargets("10.0.0.0/24\n192.168.1.0/28\n172.16.5.1", "")).toBe("internal");
    expect(classifyRange("127.0.0.1")).toBe("internal");
    expect(classifyRange("169.254.10.1")).toBe("internal");
    expect(classifyRange("100.64.0.0/10")).toBe("internal");
  });

  it("reads public space and domains as external", () => {
    expect(classifyTargets("203.0.113.0/24", "")).toBe("external");
    expect(classifyTargets("", "api.example.com")).toBe("external");
    expect(classifyRange("8.8.8.8")).toBe("external");
  });

  it("reads IPv6 ULA and link-local as internal, global as external", () => {
    expect(classifyRange("fd12:3456::1")).toBe("internal");
    expect(classifyRange("fe80::1")).toBe("internal");
    expect(classifyRange("::1")).toBe("internal");
    expect(classifyRange("2001:db8::1")).toBe("external");
  });

  it("uses containment like the server: a prefix wider than the private block is external", () => {
    expect(classifyRange("192.168.0.0/8")).toBe("external");
    expect(classifyRange("10.0.0.0/7")).toBe("external");
    expect(classifyRange("0.0.0.0/0")).toBe("external");
    expect(classifyRange("10.1.0.0/16")).toBe("internal");
    expect(classifyRange("fd00::/7")).toBe("internal");
    expect(classifyRange("fc00::/6")).toBe("external");
    expect(classifyRange("10.0.0.0/33")).toBeNull();
  });

  it("only counts FQDN-looking entries in the domains field", () => {
    expect(classifyTargets("", "10.0.0.5")).toBeNull();
    expect(classifyTargets("", "localhost")).toBeNull();
    expect(classifyTargets("", "portal.corp.internal")).toBe("external");
  });

  it("calls a job with both kinds mixed", () => {
    expect(classifyTargets("10.0.0.0/8", "shop.example.com")).toBe("mixed");
    expect(classifyTargets("10.0.0.0/8\n1.1.1.1", "")).toBe("mixed");
  });

  it("says nothing about empty targets and ignores garbage", () => {
    expect(classifyTargets("", "")).toBeNull();
    expect(classifyTargets(null, undefined)).toBeNull();
    expect(classifyRange("not-an-ip")).toBeNull();
    expect(classifyTargets("not-an-ip\n# 10.0.0.1", "")).toBeNull();
  });

  it("splits on newlines, commas and blanks", () => {
    expect(splitTargetLines("a.example,b.example\n c.example ")).toEqual([
      "a.example",
      "b.example",
      "c.example",
    ]);
  });
});

describe("surface readers", () => {
  it("prefers the top-level mirror and falls back to the persisted option", () => {
    expect(jobSurface({ surface: "external", scan_options: { surface: "internal" } })).toBe(
      "external",
    );
    expect(jobSurface({ scan_options: { surface: "internal" } })).toBe("internal");
    expect(jobSurface({ surface: null, scan_options: { surface: "bogus" } })).toBeNull();
    expect(jobSurface({})).toBeNull();
  });

  it("never turns an absent run or schedule marker into internal", () => {
    expect(runSurface({ surface: null })).toBeNull();
    expect(runSurface({})).toBeNull();
    expect(scheduleSurface({ scan_options: {} as never })).toBeNull();
    expect(scheduleSurface({ scan_options: { surface: "mixed" } as never })).toBe("mixed");
  });

  it("routes each surface to its own operations page", () => {
    expect(surfaceHref("external")).toBe("/scans/external");
    expect(surfaceHref("internal")).toBe("/scans/internal");
    expect(surfaceHref("mixed")).toBe("/scans");
    expect(surfaceHref(null)).toBe("/scans");
  });
});
