import { describe, expect, it } from "vitest";
import type { AliveHost, Vulnerability } from "@/lib/api";
import { aggregateGeo, hostStates, locateHost, markerRadius } from "@/lib/geo/aggregate";

function host(overrides: Partial<AliveHost> & { host: string }): AliveHost {
  return {
    hostname: null,
    names: [],
    country: null,
    city: null,
    country_iso: null,
    latitude: null,
    longitude: null,
    os_name: null,
    os_accuracy: null,
    asn: null,
    asn_org: null,
    vulnerability_count: 0,
    ...overrides,
  };
}

function vuln(overrides: Partial<Vulnerability> & { host: string }): Vulnerability {
  return {
    port: null,
    cve: null,
    cvss: null,
    cvss4: null,
    cvss4_vector: null,
    cvss4_severity: null,
    severity: null,
    script_id: null,
    country: null,
    city: null,
    country_iso: null,
    finding_class: null,
    confidence: null,
    requires_confirmation: false,
    epss: null,
    in_kev: false,
    contextual_score: null,
    cisa_decision: null,
    risk_explanation: null,
    ...overrides,
  };
}

describe("locateHost", () => {
  it("prefers the host's own coordinates", () => {
    const placed = locateHost(host({ host: "1.1.1.1", latitude: 50.11, longitude: 8.68, country_iso: "DE" }));
    expect(placed).toEqual({ latitude: 50.11, longitude: 8.68, precision: "coordinates" });
  });

  it("falls back to the country centroid, marked as such", () => {
    const placed = locateHost(host({ host: "1.1.1.1", country_iso: "de" }));
    expect(placed?.precision).toBe("country");
    // Roughly central Germany rather than "somewhere in Europe".
    expect(placed!.latitude).toBeGreaterThan(47);
    expect(placed!.latitude).toBeLessThan(55);
  });

  it("treats 0,0 as a real position rather than a missing one", () => {
    expect(locateHost(host({ host: "1.1.1.1", latitude: 0, longitude: 0 }))).toEqual({
      latitude: 0,
      longitude: 0,
      precision: "coordinates",
    });
  });

  it("returns null for a host with nothing to place it by", () => {
    // What a private address looks like: the scanner labels the country
    // "Private" and leaves the ISO code empty.
    expect(locateHost(host({ host: "10.0.0.4", country: "Private", country_iso: "" }))).toBeNull();
  });

  it("returns null for a country the map has no centroid for", () => {
    expect(locateHost(host({ host: "1.1.1.1", country_iso: "ZZ" }))).toBeNull();
  });
});

describe("hostStates", () => {
  it("keeps the worst severity per host and counts findings", () => {
    const states = hostStates([
      vuln({ host: "a", severity: "low" }),
      vuln({ host: "a", severity: "critical" }),
      vuln({ host: "a", severity: "medium" }),
      vuln({ host: "b", severity: "high" }),
    ]);
    expect(states.get("a")).toEqual({ state: "critical", count: 3 });
    expect(states.get("b")).toEqual({ state: "high", count: 1 });
  });

  it("ignores findings with no host", () => {
    expect(hostStates([vuln({ host: "" })]).size).toBe(0);
  });
});

describe("aggregateGeo", () => {
  const frankfurt = { latitude: 50.11, longitude: 8.68, country: "Germany", city: "Frankfurt", country_iso: "DE" };

  it("clusters hosts sharing a position and takes the worst state", () => {
    const result = aggregateGeo(
      [
        host({ host: "1.1.1.1", ...frankfurt }),
        host({ host: "1.1.1.2", ...frankfurt }),
        host({ host: "2.2.2.2", latitude: 1.29, longitude: 103.85, country: "Singapore", country_iso: "SG" }),
      ],
      [vuln({ host: "1.1.1.2", severity: "high" })],
    );

    expect(result.locations).toHaveLength(2);
    const [first] = result.locations;
    expect(first.label).toBe("Frankfurt, Germany");
    expect(first.hostCount).toBe(2);
    expect(first.vulnerableHostCount).toBe(1);
    expect(first.state).toBe("high");
    expect(result.countryCount).toBe(2);
    expect(result.locatedHostCount).toBe(3);
  });

  it("sorts locations worst-first, then by host count", () => {
    const result = aggregateGeo(
      [
        host({ host: "1.1.1.1", ...frankfurt }),
        host({ host: "1.1.1.2", ...frankfurt }),
        host({ host: "2.2.2.2", latitude: 1.29, longitude: 103.85, country: "Singapore", country_iso: "SG" }),
      ],
      [vuln({ host: "2.2.2.2", severity: "critical" })],
    );
    expect(result.locations.map((l) => l.label)).toEqual(["Singapore", "Frankfurt, Germany"]);
  });

  it("does not mix a country-centroid marker into a coordinate marker", () => {
    // Same country, different claims about where the host is. Merging them
    // would present a country-level guess as a located host.
    const result = aggregateGeo(
      [host({ host: "1.1.1.1", ...frankfurt }), host({ host: "1.1.1.2", country: "Germany", country_iso: "DE" })],
      [],
    );
    expect(result.locations).toHaveLength(2);
    expect(result.locations.map((l) => l.precision).sort()).toEqual(["coordinates", "country"]);
    expect(result.countryPrecisionHostCount).toBe(1);
  });

  it("lists unplaceable hosts instead of dropping them", () => {
    const result = aggregateGeo(
      [host({ host: "10.0.0.4", country: "Private", country_iso: "" }), host({ host: "1.1.1.1", ...frankfurt })],
      [],
    );
    expect(result.unlocated.map((h) => h.host)).toEqual(["10.0.0.4"]);
    expect(result.hostCount).toBe(2);
    expect(result.locatedHostCount).toBe(1);
  });

  it("reads a host with no findings as clean, not unknown", () => {
    const result = aggregateGeo([host({ host: "1.1.1.1", ...frankfurt })], []);
    expect(result.locations[0].state).toBe("clean");
    expect(result.vulnerableHostCount).toBe(0);
  });

  it("falls back to the host's own finding count when findings were not fetched", () => {
    // The findings endpoint is capped, so a large run can return hosts whose
    // findings are not in the page. Reporting them as clean would be wrong.
    const result = aggregateGeo([host({ host: "1.1.1.1", ...frankfurt, vulnerability_count: 4 })], []);
    expect(result.locations[0].state).toBe("unknown");
    expect(result.locations[0].findingCount).toBe(4);
    expect(result.vulnerableHostCount).toBe(1);
  });

  it("orders a location's hosts worst-first", () => {
    const result = aggregateGeo(
      [
        host({ host: "1.1.1.1", ...frankfurt }),
        host({ host: "1.1.1.2", ...frankfurt }),
        host({ host: "1.1.1.3", ...frankfurt }),
      ],
      [vuln({ host: "1.1.1.3", severity: "critical" }), vuln({ host: "1.1.1.2", severity: "low" })],
    );
    expect(result.locations[0].hosts.map((h) => h.host)).toEqual(["1.1.1.3", "1.1.1.2", "1.1.1.1"]);
  });
});

describe("markerRadius", () => {
  it("scales by area, so one busy location does not swallow the map", () => {
    const one = markerRadius(1, 100);
    const hundred = markerRadius(100, 100);
    const twentyFive = markerRadius(25, 100);
    expect(hundred).toBeGreaterThan(twentyFive);
    expect(twentyFive).toBeGreaterThan(one);
    // Radius grows with √count, not count: 25 of a 100-host maximum is
    // (5-1)/(10-1) ≈ 44 % of the way from floor to cap, not 25 %.
    expect((twentyFive - one) / (hundred - one)).toBeCloseTo(4 / 9, 2);
  });

  it("puts a single host at the floor and the busiest location at the cap", () => {
    // The property that matters on a small run: with three hosts at the
    // busiest location, a lone host must still look like a lone host.
    expect(markerRadius(1, 3)).toBe(markerRadius(1, 5000));
    expect(markerRadius(3, 3)).toBe(markerRadius(5000, 5000));
    expect(markerRadius(3, 3)).toBeGreaterThan(markerRadius(1, 3));
  });

  it("never returns a zero-radius marker", () => {
    expect(markerRadius(0, 10)).toBeGreaterThan(0);
    expect(markerRadius(1, 0)).toBeGreaterThan(0);
    expect(markerRadius(5, 1)).toBeGreaterThan(0);
  });
});
