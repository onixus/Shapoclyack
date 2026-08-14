/**
 * Regenerates `src/lib/geo/world-map.ts` — the land outline and the per-country
 * fallback centroids the Geo Map draws.
 *
 *     node scripts/generate-world-map.mjs
 *
 * Run by hand, not by the build: the output is committed, so `npm ci` and the
 * Docker image build stay offline, and the map cannot change under a release
 * without the diff being reviewable. The Attack Surface graph made the same
 * call — dependency-free SVG rather than a charting library.
 *
 * Sources, both fetched only here:
 *   - world-atlas land-110m / countries-110m (Natural Earth, public domain)
 *   - lukes/ISO-3166-Countries-with-Regional-Codes, for numeric → alpha-2,
 *     since Natural Earth identifies countries by ISO numeric code and GeoIP
 *     reports alpha-2.
 *
 * TopoJSON is decoded inline (~40 lines below) rather than by adding
 * topojson-client as a dependency for one script.
 */

import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const LAND_URL = "https://unpkg.com/world-atlas@2.0.2/land-110m.json";
const COUNTRIES_URL = "https://unpkg.com/world-atlas@2.0.2/countries-110m.json";
const ISO_URL =
  "https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/all/all.json";
// Natural Earth 110m drops countries too small to draw — Singapore, Hong Kong,
// Malta, Luxembourg — which are exactly the ones a cloud estate lives in. Their
// centroids come from this dataset instead, so no host is unplaceable because
// its country is small.
const SMALL_STATES_URL =
  "https://raw.githubusercontent.com/mledoze/countries/master/countries.json";

// Projection viewBox. Equirectangular: x is linear in longitude, y in latitude,
// which is why the projection can live in four lines of arithmetic in the
// component instead of in a projection library.
const WIDTH = 1000;
const HEIGHT = 500;
// One unit is 0.36° of longitude, so one decimal place is ~4 km — far finer
// than a 110m-resolution outline resolves, and it halves the file.
const PRECISION = 1;

async function getJson(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`GET ${url} → ${response.status}`);
  return response.json();
}

/** TopoJSON arc decoding: delta-encoded integers → absolute [lon, lat]. */
function decodeArcs(topology) {
  const { scale, translate } = topology.transform;
  return topology.arcs.map((arc) => {
    let x = 0;
    let y = 0;
    return arc.map(([dx, dy]) => {
      x += dx;
      y += dy;
      return [x * scale[0] + translate[0], y * scale[1] + translate[1]];
    });
  });
}

/** A topology arc index is ~n for a reversed arc, which is why this is not a lookup. */
function arcPoints(arcs, index) {
  if (index < 0) return arcs[~index].slice().reverse();
  return arcs[index];
}

function ringPoints(arcs, ring) {
  const points = [];
  for (const index of ring) {
    const segment = arcPoints(arcs, index);
    // Consecutive arcs share their join point.
    points.push(...(points.length ? segment.slice(1) : segment));
  }
  return points;
}

function* geometryRings(arcs, geometry) {
  if (geometry.type === "Polygon") {
    for (const ring of geometry.arcs) yield ringPoints(arcs, ring);
  } else if (geometry.type === "MultiPolygon") {
    for (const polygon of geometry.arcs) {
      for (const ring of polygon) yield ringPoints(arcs, ring);
    }
  }
}

const projectX = (lon) => ((lon + 180) / 360) * WIDTH;
const projectY = (lat) => ((90 - lat) / 180) * HEIGHT;
const round = (value) => Number(value.toFixed(PRECISION));

function ringToPath(points) {
  const parts = [];
  let previous = null;
  for (const [lon, lat] of points) {
    const x = round(projectX(lon));
    const y = round(projectY(lat));
    // Drop points that collapse onto their predecessor at this precision —
    // most of the size of a projected 110m outline is repeated coordinates.
    if (previous && previous[0] === x && previous[1] === y) continue;
    parts.push(`${parts.length === 0 ? "M" : "L"}${x} ${y}`);
    previous = [x, y];
  }
  return parts.length > 2 ? `${parts.join("")}Z` : "";
}

const wrap = (lon) => ((((lon + 180) % 360) + 360) % 360) - 180;

/** Circular mean longitude — the reference a ring is rotated onto below. */
function meanLongitude(points) {
  let x = 0;
  let y = 0;
  for (const [lon] of points) {
    const radians = (lon * Math.PI) / 180;
    x += Math.cos(radians);
    y += Math.sin(radians);
  }
  return (Math.atan2(y, x) * 180) / Math.PI;
}

/**
 * Signed-area centroid of a ring, in degrees.
 *
 * Computed in a frame rotated onto the ring's mean longitude, then rotated
 * back. Countries clipped at the antimeridian (Russia, Fiji) are stored as
 * rings spanning -180…180, and a planar centroid over those coordinates lands
 * in the wrong hemisphere — Russia came out at 202°E, i.e. the Bering Sea.
 */
function ringCentroid(points) {
  const reference = meanLongitude(points);
  let area = 0;
  let cx = 0;
  let cy = 0;
  for (let i = 0; i < points.length - 1; i += 1) {
    const x0 = wrap(points[i][0] - reference);
    const y0 = points[i][1];
    const x1 = wrap(points[i + 1][0] - reference);
    const y1 = points[i + 1][1];
    const cross = x0 * y1 - x1 * y0;
    area += cross;
    cx += (x0 + x1) * cross;
    cy += (y0 + y1) * cross;
  }
  if (area === 0) return null;
  return {
    lon: wrap(cx / (3 * area) + reference),
    lat: cy / (3 * area),
    weight: Math.abs(area / 2),
  };
}

async function main() {
  const [land, countries, isoCodes, smallStates] = await Promise.all([
    getJson(LAND_URL),
    getJson(COUNTRIES_URL),
    getJson(ISO_URL),
    getJson(SMALL_STATES_URL),
  ]);

  const landArcs = decodeArcs(land);
  const landPaths = [];
  for (const geometry of land.objects.land.geometries) {
    for (const ring of geometryRings(landArcs, geometry)) {
      const path = ringToPath(ring);
      if (path) landPaths.push(path);
    }
  }

  const numericToAlpha2 = new Map(
    isoCodes.map((entry) => [String(Number(entry["country-code"])), entry["alpha-2"]]),
  );

  const countryArcs = decodeArcs(countries);
  const centroids = {};
  for (const geometry of countries.objects.countries.geometries) {
    const alpha2 = numericToAlpha2.get(String(Number(geometry.id)));
    if (!alpha2) continue;
    // Largest ring wins rather than the average of all of them: an average
    // over overseas territories puts France in the Atlantic.
    let best = null;
    for (const ring of geometryRings(countryArcs, geometry)) {
      const centroid = ringCentroid(ring);
      if (centroid && (!best || centroid.weight > best.weight)) best = centroid;
    }
    if (best) centroids[alpha2] = [Number(best.lon.toFixed(2)), Number(best.lat.toFixed(2))];
  }

  // Gap-fill only: a drawn country keeps its geometric centroid, which sits on
  // its landmass, while this dataset's point is a nominal country centre.
  let filled = 0;
  for (const entry of smallStates) {
    const alpha2 = entry.cca2;
    const latlng = entry.latlng;
    if (!alpha2 || centroids[alpha2] || !Array.isArray(latlng) || latlng.length !== 2) continue;
    centroids[alpha2] = [Number(Number(latlng[1]).toFixed(2)), Number(Number(latlng[0]).toFixed(2))];
    filled += 1;
  }

  const target = resolve(dirname(fileURLToPath(import.meta.url)), "../src/lib/geo/world-map.ts");
  const body = `// GENERATED FILE — do not edit by hand.
// Regenerate with: node scripts/generate-world-map.mjs
//
// Land outline from Natural Earth 110m via world-atlas (public domain),
// projected equirectangular into a ${WIDTH}x${HEIGHT} viewBox, and per-country
// fallback centroids for hosts whose GeoIP record carries a country but no
// coordinates.

/** Projection viewBox the paths below are drawn in. */
export const MAP_WIDTH = ${WIDTH};
export const MAP_HEIGHT = ${HEIGHT};

/** Equirectangular projection — the one the paths were generated with. */
export function projectLongitude(longitude: number): number {
  return ((longitude + 180) / 360) * MAP_WIDTH;
}

export function projectLatitude(latitude: number): number {
  return ((90 - latitude) / 180) * MAP_HEIGHT;
}

/** Closed land rings, coarse by design: a backdrop for the markers, not a basemap. */
export const LAND_PATHS: readonly string[] = [
${landPaths.map((path) => `  ${JSON.stringify(path)},`).join("\n")}
];

/**
 * ISO 3166-1 alpha-2 → [longitude, latitude] of the country's largest landmass.
 *
 * Used only when a host has a country but no coordinates of its own — a
 * Country-edition GeoIP database, or a run scanned before the scanner recorded
 * them. Such markers are labelled country-level, because that is what they are.
 */
export const COUNTRY_CENTROIDS: Readonly<Record<string, readonly [number, number]>> = {
${Object.keys(centroids)
  .sort()
  .map((iso) => `  ${iso}: [${centroids[iso][0]}, ${centroids[iso][1]}],`)
  .join("\n")}
};
`;
  writeFileSync(target, body, "utf8");
  console.log(
    `wrote ${target}: ${landPaths.length} land rings, ${Object.keys(centroids).length} centroids ` +
      `(${filled} gap-filled for countries too small to draw at 110m)`,
  );
}

await main();
