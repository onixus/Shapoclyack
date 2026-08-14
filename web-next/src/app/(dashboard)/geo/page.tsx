"use client";

import { useMemo, useState } from "react";
import { Globe2 } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { GeoMap, STATE_FILL, STATE_LABEL } from "@/components/geo-map";
import { KpiCard } from "@/components/kpi-card";
import { useRunHosts, useRuns, useRunVulns } from "@/hooks/use-runs";
import { aggregateGeo } from "@/lib/geo/aggregate";
import { pickLatestRun } from "@/lib/run-data";
import { cn } from "@/lib/utils";

const RUN_PICKER_LIMIT = 50;

export default function GeoPage() {
  const runsQuery = useRuns(undefined, { limit: RUN_PICKER_LIMIT });
  const [selectedRun, setSelectedRun] = useState<string>("");
  const [selectedLocation, setSelectedLocation] = useState<string | null>(null);

  const runs = useMemo(() => runsQuery.data?.items ?? [], [runsQuery.data]);
  const latest = useMemo(() => pickLatestRun(runs), [runs]);
  const runId = selectedRun || latest?.run_id || "";

  const hostsQuery = useRunHosts(runId);
  const vulnsQuery = useRunVulns(runId);

  const geo = useMemo(
    () => aggregateGeo(hostsQuery.data || [], vulnsQuery.data || []),
    [hostsQuery.data, vulnsQuery.data],
  );

  const selected = geo.locations.find((location) => location.key === selectedLocation) ?? null;
  const isLoading =
    runsQuery.isLoading || (Boolean(runId) && (hostsQuery.isLoading || vulnsQuery.isLoading));
  const error = runsQuery.error || hostsQuery.error || vulnsQuery.error;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-emerald-500/20 bg-emerald-500/10 text-emerald-400 shadow-md">
            <Globe2 className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">Geo Map</h1>
            <p className="text-xs text-slate-400">
              External hosts by GeoIP position, coloured by their worst finding in this run.
            </p>
          </div>
        </div>

        <Select
          value={runId}
          onValueChange={(value) => {
            setSelectedRun(value);
            setSelectedLocation(null);
          }}
        >
          <SelectTrigger className="w-72 border-slate-800 bg-slate-900 text-slate-200">
            <SelectValue placeholder="Select a scan run" />
          </SelectTrigger>
          <SelectContent className="border-slate-800 bg-slate-900 text-slate-200">
            {runs.map((run) => (
              <SelectItem key={run.run_id} value={run.run_id} className="font-mono text-xs">
                {run.run_id}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {error ? (
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
          <AlertDescription>{(error as Error).message}</AlertDescription>
        </Alert>
      ) : null}

      {!runId && !isLoading ? (
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-8 text-center backdrop-blur">
          <p className="text-sm font-semibold text-slate-300">No scan runs available</p>
          <p className="mt-1 text-xs text-slate-400">
            Start a scan job to place its hosts on the map.
          </p>
        </div>
      ) : isLoading ? (
        <div className="flex items-center justify-center gap-2 py-16 text-slate-400">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-emerald-400 border-t-transparent" />
          <span className="text-sm">Resolving host locations…</span>
        </div>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <KpiCard label="Countries" value={geo.countryCount} decorationColor="sky" />
            <KpiCard
              label="Located hosts"
              value={geo.locatedHostCount}
              hint={`of ${geo.hostCount} alive`}
              decorationColor="emerald"
            />
            <KpiCard
              label="Hosts with findings"
              value={geo.vulnerableHostCount}
              decorationColor="rose"
            />
            <KpiCard
              label="Unlocated"
              value={geo.unlocated.length}
              hint="no GeoIP position"
              decorationColor="slate"
            />
          </div>

          {geo.countryPrecisionHostCount > 0 ? (
            <Alert className="border-slate-700 bg-slate-900/60 text-slate-300">
              <AlertDescription className="text-xs">
                {geo.countryPrecisionHostCount} host
                {geo.countryPrecisionHostCount === 1 ? " is" : "s are"} plotted at a country
                centroid because the GeoIP database gave a country but no coordinates — those
                markers are dashed. GeoIP positions are the *registered* location of a network,
                usually a city or country centre, never the machine.
              </AlertDescription>
            </Alert>
          ) : null}

          <div className="grid gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
            <GeoMap
              locations={geo.locations}
              selectedKey={selectedLocation}
              onSelect={setSelectedLocation}
            />

            <div className="space-y-3">
              <div className="rounded-xl border border-slate-800/80 bg-slate-900/60">
                <div className="border-b border-slate-800/80 px-4 py-3">
                  <h2 className="text-sm font-semibold text-slate-200">Locations</h2>
                  <p className="text-xs text-slate-500">Worst state first. Select one to list its hosts.</p>
                </div>
                <ul className="max-h-72 overflow-y-auto">
                  {geo.locations.length === 0 ? (
                    <li className="px-4 py-6 text-center text-xs text-slate-500">
                      No host in this run carries a GeoIP position.
                    </li>
                  ) : (
                    geo.locations.map((location) => (
                      <li key={location.key}>
                        <button
                          type="button"
                          onClick={() =>
                            setSelectedLocation(
                              location.key === selectedLocation ? null : location.key,
                            )
                          }
                          className={cn(
                            "flex w-full items-center justify-between gap-3 px-4 py-2 text-left text-xs transition-colors hover:bg-slate-800/60",
                            location.key === selectedLocation && "bg-slate-800/80",
                          )}
                        >
                          <span className="flex min-w-0 items-center gap-2">
                            <span
                              className="h-2.5 w-2.5 shrink-0 rounded-full"
                              style={{ backgroundColor: STATE_FILL[location.state] }}
                            />
                            <span className="truncate text-slate-200">{location.label}</span>
                            {location.precision === "country" ? (
                              <span className="shrink-0 text-[10px] uppercase tracking-wide text-slate-500">
                                country
                              </span>
                            ) : null}
                          </span>
                          <span className="shrink-0 font-mono text-slate-400">
                            {location.hostCount}
                          </span>
                        </button>
                      </li>
                    ))
                  )}
                </ul>
              </div>

              <div className="rounded-xl border border-slate-800/80 bg-slate-900/60">
                <div className="border-b border-slate-800/80 px-4 py-3">
                  <h2 className="text-sm font-semibold text-slate-200">
                    {selected ? selected.label : "Hosts"}
                  </h2>
                  <p className="text-xs text-slate-500">
                    {selected
                      ? `${selected.hostCount} host${selected.hostCount === 1 ? "" : "s"} · ${selected.findingCount} finding${selected.findingCount === 1 ? "" : "s"}`
                      : "Select a location on the map."}
                  </p>
                </div>
                <ul className="max-h-72 overflow-y-auto">
                  {(selected?.hosts ?? []).map((host) => (
                    <li
                      key={host.host}
                      className="flex items-center justify-between gap-3 px-4 py-2 text-xs"
                    >
                      <span className="min-w-0">
                        <span className="block truncate font-mono text-slate-200">{host.host}</span>
                        {host.hostname ? (
                          <span className="block truncate text-slate-500">{host.hostname}</span>
                        ) : null}
                      </span>
                      <Badge
                        variant="outline"
                        className="shrink-0 border-slate-700 text-[10px] text-slate-300"
                      >
                        {STATE_LABEL[host.state]}
                        {host.findingCount > 0 ? ` · ${host.findingCount}` : ""}
                      </Badge>
                    </li>
                  ))}
                  {selected && selected.hosts.length === 0 ? (
                    <li className="px-4 py-6 text-center text-xs text-slate-500">No hosts.</li>
                  ) : null}
                </ul>
              </div>
            </div>
          </div>

          {geo.unlocated.length > 0 ? (
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/60">
              <div className="border-b border-slate-800/80 px-4 py-3">
                <h2 className="text-sm font-semibold text-slate-200">
                  Unlocated hosts ({geo.unlocated.length})
                </h2>
                <p className="text-xs text-slate-500">
                  No GeoIP record and no country to fall back on — private addresses, or an
                  installation with no GeoIP database configured. Listed rather than dropped, so
                  the map never reads as the whole estate.
                </p>
              </div>
              <ul className="flex max-h-40 flex-wrap gap-2 overflow-y-auto p-4">
                {geo.unlocated.map((host) => (
                  <li
                    key={host.host}
                    className="rounded border border-slate-800 bg-slate-950/60 px-2 py-1 font-mono text-[11px] text-slate-300"
                  >
                    {host.host}
                    {host.findingCount > 0 ? (
                      <span className="ml-1.5 text-rose-400">{host.findingCount}</span>
                    ) : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}
