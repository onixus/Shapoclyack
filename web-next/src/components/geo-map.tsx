"use client";

import { useMemo, useState } from "react";
import {
  HOST_STATES,
  markerRadius,
  type GeoLocation,
  type HostState,
} from "@/lib/geo/aggregate";
import {
  LAND_PATHS,
  MAP_HEIGHT,
  MAP_WIDTH,
  projectLatitude,
  projectLongitude,
} from "@/lib/geo/world-map";
import { cn } from "@/lib/utils";

/**
 * World map of a run's external hosts, by GeoIP position and worst finding.
 *
 * A dependency-free SVG, like the Attack Surface graph: the projection is
 * equirectangular, which is four lines of arithmetic, and the land outline is
 * a generated constant (`scripts/generate-world-map.mjs`). That keeps the
 * published image offline-installable and adds no runtime dependency for one
 * page.
 *
 * The map is a *view of GeoIP data*, so it deliberately shows how each marker
 * was placed rather than presenting every dot as equally precise — see
 * `GeoPrecision` in `lib/geo/aggregate.ts`.
 */

/** Marker fill per state. Same palette as SEVERITY_STATUS, as solid colours —
 * a translucent badge class does not read as a dot against the land. */
const STATE_FILL: Record<HostState, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#f59e0b",
  low: "#38bdf8",
  unknown: "#94a3b8",
  clean: "#34d399",
};

const STATE_LABEL: Record<HostState, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  unknown: "unrated",
  clean: "no findings",
};

type GeoMapProps = {
  locations: GeoLocation[];
  selectedKey: string | null;
  onSelect: (key: string | null) => void;
};

export function GeoMap({ locations, selectedKey, onSelect }: GeoMapProps) {
  const [hovered, setHovered] = useState<GeoLocation | null>(null);

  const maxHostCount = useMemo(
    () => locations.reduce((max, location) => Math.max(max, location.hostCount), 1),
    [locations],
  );

  // Biggest first, so a small critical marker is drawn on top of the large
  // clean one it would otherwise hide.
  const ordered = useMemo(
    () => [...locations].sort((a, b) => b.hostCount - a.hostCount),
    [locations],
  );

  const active = hovered ?? locations.find((location) => location.key === selectedKey) ?? null;
  const statesPresent = HOST_STATES.filter((state) =>
    locations.some((location) => location.state === state),
  );

  return (
    <div className="space-y-3">
      <div className="relative overflow-hidden rounded-xl border border-slate-800/80 bg-slate-950/60">
        <svg
          viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`}
          className="h-auto w-full"
          role="img"
          aria-label={`World map of ${locations.length} host locations`}
        >
          <rect width={MAP_WIDTH} height={MAP_HEIGHT} fill="#020617" />
          {/* Graticule every 30°: without it an equirectangular map gives no
              sense of scale, and the poles look like the tropics. */}
          <g stroke="#1e293b" strokeWidth={0.5} fill="none">
            {[-150, -120, -90, -60, -30, 0, 30, 60, 90, 120, 150].map((lon) => (
              <line
                key={`lon-${lon}`}
                x1={projectLongitude(lon)}
                y1={0}
                x2={projectLongitude(lon)}
                y2={MAP_HEIGHT}
              />
            ))}
            {[-60, -30, 0, 30, 60].map((lat) => (
              <line
                key={`lat-${lat}`}
                x1={0}
                y1={projectLatitude(lat)}
                x2={MAP_WIDTH}
                y2={projectLatitude(lat)}
              />
            ))}
          </g>
          <g fill="#1e293b" stroke="#334155" strokeWidth={0.4}>
            {LAND_PATHS.map((path, index) => (
              <path key={index} d={path} />
            ))}
          </g>

          <g>
            {ordered.map((location) => {
              const radius = markerRadius(location.hostCount, maxHostCount);
              const x = projectLongitude(location.longitude);
              const y = projectLatitude(location.latitude);
              const isSelected = location.key === selectedKey;
              return (
                <g
                  key={location.key}
                  className="cursor-pointer"
                  onMouseEnter={() => setHovered(location)}
                  onMouseLeave={() => setHovered(null)}
                  onClick={() => onSelect(isSelected ? null : location.key)}
                >
                  <circle
                    cx={x}
                    cy={y}
                    r={radius}
                    fill={STATE_FILL[location.state]}
                    fillOpacity={isSelected ? 0.85 : 0.55}
                    stroke={STATE_FILL[location.state]}
                    strokeWidth={isSelected ? 2 : 1}
                    // Dashed ring = placed at a country centroid, not at
                    // coordinates of its own. The distinction is on the marker
                    // itself so it survives being screenshotted out of context.
                    strokeDasharray={location.precision === "country" ? "3 2" : undefined}
                  />
                  <title>
                    {`${location.label} — ${location.hostCount} host${
                      location.hostCount === 1 ? "" : "s"
                    }, ${STATE_LABEL[location.state]}${
                      location.precision === "country" ? " (country-level position)" : ""
                    }`}
                  </title>
                </g>
              );
            })}
          </g>
        </svg>

        {active ? (
          <div className="pointer-events-none absolute bottom-3 left-3 max-w-xs rounded-lg border border-slate-700 bg-slate-900/95 p-3 text-xs shadow-xl">
            <p className="font-semibold text-slate-100">{active.label}</p>
            <p className="mt-1 text-slate-400">
              {active.hostCount} host{active.hostCount === 1 ? "" : "s"} ·{" "}
              {active.vulnerableHostCount} with findings · {active.findingCount} finding
              {active.findingCount === 1 ? "" : "s"}
            </p>
            <p className="mt-1 text-slate-500">
              worst: {STATE_LABEL[active.state]} ·{" "}
              {active.precision === "country"
                ? "country-level position"
                : `${active.latitude.toFixed(2)}, ${active.longitude.toFixed(2)}`}
            </p>
          </div>
        ) : null}
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-slate-400">
        {statesPresent.map((state) => (
          <span key={state} className="flex items-center gap-1.5">
            <span
              className="inline-block h-2.5 w-2.5 rounded-full"
              style={{ backgroundColor: STATE_FILL[state] }}
            />
            {STATE_LABEL[state]}
          </span>
        ))}
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full border border-dashed border-slate-400" />
          country-level position
        </span>
        <span className={cn("text-slate-500")}>marker area ∝ hosts</span>
      </div>
    </div>
  );
}

export { STATE_FILL, STATE_LABEL };
