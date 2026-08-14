import type { AliveHost, Vulnerability } from "@/lib/api";
import { normalizeSeverity, type Severity } from "@/lib/run-data";
import { COUNTRY_CENTROIDS } from "@/lib/geo/world-map";

/**
 * How a marker's position was obtained. Kept on every point and shown in the
 * UI, because the two are not the same claim: `coordinates` is what the GeoIP
 * database recorded for the network (typically a city centre), `country` is
 * this app placing a host at its country's centroid because the database gave
 * a country and nothing more.
 */
export type GeoPrecision = "coordinates" | "country";

/** A host's state on the map: its worst finding, or `clean` when it has none. */
export type HostState = Severity | "clean";

/** Worst-first. Also the order the legend and the location table sort by. */
export const HOST_STATES: readonly HostState[] = [
  "critical",
  "high",
  "medium",
  "low",
  "unknown",
  "clean",
];

const STATE_RANK: Record<HostState, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
  clean: 5,
};

export type GeoHost = {
  host: string;
  hostname: string | null;
  state: HostState;
  findingCount: number;
  asnOrg: string | null;
};

export type GeoLocation = {
  /** Stable across renders and re-fetches; used as the React key and selection id. */
  key: string;
  label: string;
  countryIso: string | null;
  longitude: number;
  latitude: number;
  precision: GeoPrecision;
  hosts: GeoHost[];
  hostCount: number;
  vulnerableHostCount: number;
  findingCount: number;
  /** Worst host state at this location — what colours the marker. */
  state: HostState;
};

export type GeoAggregation = {
  locations: GeoLocation[];
  /** Hosts with neither coordinates nor a mappable country. Never plotted. */
  unlocated: GeoHost[];
  hostCount: number;
  locatedHostCount: number;
  countryCount: number;
  vulnerableHostCount: number;
  /** Located hosts placed only at a country centroid, i.e. the coarse ones. */
  countryPrecisionHostCount: number;
};

function worse(a: HostState, b: HostState): HostState {
  return STATE_RANK[a] <= STATE_RANK[b] ? a : b;
}

/** host → worst finding severity and finding count, from a run's findings. */
export function hostStates(vulns: Vulnerability[]): Map<string, { state: HostState; count: number }> {
  const out = new Map<string, { state: HostState; count: number }>();
  for (const vuln of vulns) {
    const host = vuln.host;
    if (!host) continue;
    const severity = normalizeSeverity(vuln.severity);
    const current = out.get(host);
    if (current) {
      current.count += 1;
      current.state = worse(current.state, severity);
    } else {
      out.set(host, { state: severity, count: 1 });
    }
  }
  return out;
}

/**
 * Where a host is plotted, or null when it cannot be placed honestly.
 *
 * Real coordinates win. A host with only a country is placed at that country's
 * centroid and *labelled* as country-level — the alternative, dropping it, would
 * quietly under-report the estate on a Country-edition GeoIP database.
 * `country_iso` is empty for private addresses (the scanner labels those
 * `Private`), which is why they end up unlocated rather than somewhere plausible.
 */
export function locateHost(
  host: AliveHost,
): { longitude: number; latitude: number; precision: GeoPrecision } | null {
  if (typeof host.latitude === "number" && typeof host.longitude === "number") {
    return { longitude: host.longitude, latitude: host.latitude, precision: "coordinates" };
  }
  const iso = (host.country_iso || "").trim().toUpperCase();
  const centroid = iso ? COUNTRY_CENTROIDS[iso] : undefined;
  if (centroid) {
    return { longitude: centroid[0], latitude: centroid[1], precision: "country" };
  }
  return null;
}

function locationLabel(host: AliveHost, precision: GeoPrecision): string {
  const country = host.country?.trim();
  const city = host.city?.trim();
  const iso = host.country_iso?.trim();
  if (precision === "country") return country || iso || "Unknown country";
  const parts = [city, country].filter(Boolean);
  if (parts.length) return parts.join(", ");
  return iso || "Unknown location";
}

/**
 * Group a run's hosts into map markers.
 *
 * Hosts are clustered by *position*, not by city name: two GeoIP records for
 * one city carry the same coordinates, and clustering by name would split them
 * whenever a database spells the city differently. Coordinates are rounded to
 * two decimals (~1 km) so floating-point noise cannot produce two markers a
 * pixel apart.
 */
export function aggregateGeo(hosts: AliveHost[], vulns: Vulnerability[]): GeoAggregation {
  const states = hostStates(vulns);
  const byKey = new Map<string, GeoLocation>();
  const unlocated: GeoHost[] = [];
  const countries = new Set<string>();
  let vulnerableHostCount = 0;
  let countryPrecisionHostCount = 0;

  for (const host of hosts) {
    const found = states.get(host.host);
    // The larger of the two counts, not the one from `vulns`: the findings
    // endpoint is capped, so a host can have more findings than the page
    // carries, and `vulnerability_count` is counted server-side over the whole
    // run. Taking the truncated number would under-report exactly the busiest
    // hosts.
    const findingCount = Math.max(found?.count ?? 0, host.vulnerability_count ?? 0);
    // A host with no findings is `clean` rather than `unknown`: the run looked
    // at it and found nothing. `unknown` is reserved for a finding whose own
    // severity is unrated — or for one this page never received.
    const state: HostState = found?.state ?? (findingCount > 0 ? "unknown" : "clean");
    const entry: GeoHost = {
      host: host.host,
      hostname: host.hostname ?? null,
      state,
      findingCount,
      asnOrg: host.asn_org ?? null,
    };
    if (findingCount > 0) vulnerableHostCount += 1;

    const placed = locateHost(host);
    if (!placed) {
      unlocated.push(entry);
      continue;
    }
    if (placed.precision === "country") countryPrecisionHostCount += 1;
    const iso = (host.country_iso || "").trim().toUpperCase() || null;
    if (iso) countries.add(iso);

    const longitude = Number(placed.longitude.toFixed(2));
    const latitude = Number(placed.latitude.toFixed(2));
    const key = `${placed.precision}:${latitude},${longitude}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.hosts.push(entry);
      existing.hostCount += 1;
      existing.findingCount += findingCount;
      if (findingCount > 0) existing.vulnerableHostCount += 1;
      existing.state = worse(existing.state, state);
    } else {
      byKey.set(key, {
        key,
        label: locationLabel(host, placed.precision),
        countryIso: iso,
        longitude,
        latitude,
        precision: placed.precision,
        hosts: [entry],
        hostCount: 1,
        vulnerableHostCount: findingCount > 0 ? 1 : 0,
        findingCount,
        state,
      });
    }
  }

  // Array.from rather than a spread: the build targets a tsconfig without
  // downlevelIteration, where spreading a Map iterator does not compile.
  const locations: GeoLocation[] = Array.from(byKey.values()).map((location) => ({
    ...location,
    hosts: [...location.hosts].sort(
      (a, b) => STATE_RANK[a.state] - STATE_RANK[b.state] || a.host.localeCompare(b.host),
    ),
  }));
  // Worst first, then busiest: the marker an operator should click is the one
  // at the top of the list beside the map.
  locations.sort(
    (a, b) =>
      STATE_RANK[a.state] - STATE_RANK[b.state] ||
      b.hostCount - a.hostCount ||
      a.label.localeCompare(b.label),
  );

  const locatedHostCount = locations.reduce((total, location) => total + location.hostCount, 0);
  return {
    locations,
    unlocated: unlocated.sort(
      (a, b) => STATE_RANK[a.state] - STATE_RANK[b.state] || a.host.localeCompare(b.host),
    ),
    hostCount: hosts.length,
    locatedHostCount,
    countryCount: countries.size,
    vulnerableHostCount,
    countryPrecisionHostCount,
  };
}

const MIN_RADIUS = 3.5;
const MAX_RADIUS = 16;

/**
 * Marker radius for a host count, in viewBox units.
 *
 * Area-proportional (radius ∝ √count), so a marker for 100 hosts reads as ten
 * times one host rather than a hundred times — a linear radius lets one busy
 * location swallow the map. Anchored so a single host is always the floor and
 * the busiest location is always the cap: scaling √count against √max alone
 * made a lone host two-thirds of full size whenever the busiest location had
 * only a handful.
 */
export function markerRadius(hostCount: number, maxHostCount: number): number {
  if (hostCount <= 1) return MIN_RADIUS;
  const ceiling = Math.max(maxHostCount, 2);
  const scale = (Math.sqrt(hostCount) - 1) / (Math.sqrt(ceiling) - 1);
  const clamped = Math.min(Math.max(scale, 0), 1);
  return Number((MIN_RADIUS + (MAX_RADIUS - MIN_RADIUS) * clamped).toFixed(2));
}
