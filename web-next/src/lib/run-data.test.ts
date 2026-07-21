import { describe, expect, it } from "vitest";
import type { PortAggregate, RunSummary, Vulnerability } from "@/lib/api";
import {
  countSeverities,
  formatLocation,
  normalizeSeverity,
  pickLatestRun,
  recentRunTrend,
  runDetailHref,
  topVulnerablePorts,
} from "@/lib/run-data";

function makeRun(overrides: Partial<RunSummary>): RunSummary {
  return {
    run_id: "run-1",
    profile: null,
    started_at: null,
    alive_hosts: null,
    open_host_port_pairs: null,
    potential_vulnerabilities: null,
    vulnerable_hosts: null,
    has_diff: false,
    has_summary: false,
    ...overrides,
  };
}

function makeVuln(severity: string | null): Vulnerability {
  return {
    host: "10.0.0.1",
    port: "80",
    cve: null,
    cvss: null,
    cvss4: null,
    cvss4_vector: null,
    cvss4_severity: null,
    severity,
    script_id: null,
    country: null,
    city: null,
    country_iso: null,
  };
}

describe("runDetailHref", () => {
  it("URL-encodes the run id into a static-export friendly query URL", () => {
    expect(runDetailHref("run/1 x")).toBe("/runs/view?runId=run%2F1%20x");
  });
});

describe("formatLocation", () => {
  it("joins city and country", () => {
    expect(formatLocation({ city: "Berlin", country: "Germany" })).toBe("Berlin, Germany");
  });

  it("falls back to the ISO code when city/country are missing", () => {
    expect(formatLocation({ country_iso: "DE" })).toBe("DE");
  });

  it("returns an empty string when nothing is known", () => {
    expect(formatLocation({})).toBe("");
  });
});

describe("normalizeSeverity", () => {
  it("lowercases known severities", () => {
    expect(normalizeSeverity("CRITICAL")).toBe("critical");
    expect(normalizeSeverity("High")).toBe("high");
  });

  it("maps null, undefined, and junk to unknown", () => {
    expect(normalizeSeverity(null)).toBe("unknown");
    expect(normalizeSeverity(undefined)).toBe("unknown");
    expect(normalizeSeverity("wat")).toBe("unknown");
  });
});

describe("pickLatestRun", () => {
  it("returns null for an empty list", () => {
    expect(pickLatestRun([])).toBeNull();
  });

  it("prefers runs with a summary even if newer runs lack one", () => {
    const runs = [
      makeRun({ run_id: "new-no-summary", started_at: "2026-07-20T00:00:00Z" }),
      makeRun({ run_id: "old-summary", started_at: "2026-07-01T00:00:00Z", has_summary: true }),
    ];
    expect(pickLatestRun(runs)?.run_id).toBe("old-summary");
  });

  it("picks the newest by started_at within the pool", () => {
    const runs = [
      makeRun({ run_id: "a", started_at: "2026-07-01T00:00:00Z", has_summary: true }),
      makeRun({ run_id: "b", started_at: "2026-07-15T00:00:00Z", has_summary: true }),
    ];
    expect(pickLatestRun(runs)?.run_id).toBe("b");
  });
});

describe("countSeverities", () => {
  it("counts normalized severities including unknown", () => {
    const counts = countSeverities([
      makeVuln("critical"),
      makeVuln("CRITICAL"),
      makeVuln("low"),
      makeVuln(null),
    ]);
    expect(counts.critical).toBe(2);
    expect(counts.low).toBe(1);
    expect(counts.unknown).toBe(1);
    expect(counts.high).toBe(0);
  });
});

describe("recentRunTrend", () => {
  it("sorts ascending by date and applies the limit from the tail", () => {
    const runs = [
      makeRun({ run_id: "c", started_at: "2026-07-03T00:00:00Z", alive_hosts: 3 }),
      makeRun({ run_id: "a", started_at: "2026-07-01T00:00:00Z", alive_hosts: 1 }),
      makeRun({ run_id: "b", started_at: "2026-07-02T00:00:00Z", alive_hosts: 2 }),
    ];
    const trend = recentRunTrend(runs, 2);
    expect(trend.map((t) => t.run_id)).toEqual(["b", "c"]);
    expect(trend[1].Hosts).toBe(3);
  });

  it("drops runs without started_at", () => {
    expect(recentRunTrend([makeRun({ started_at: null })])).toEqual([]);
  });
});

describe("topVulnerablePorts", () => {
  it("ranks by vulnerability count, falling back to host count", () => {
    const ports: PortAggregate[] = [
      { port: "80", protocol: "tcp", host_count: 5, vulnerability_count: 1, hosts: [] },
      { port: "443", protocol: "tcp", host_count: 2, vulnerability_count: 9, hosts: [] },
      { port: "53", protocol: null, host_count: 7, vulnerability_count: 0, hosts: [] },
    ];
    const top = topVulnerablePorts(ports, 2);
    expect(top.map((p) => p.name)).toEqual(["443/tcp", "53"]);
  });
});
