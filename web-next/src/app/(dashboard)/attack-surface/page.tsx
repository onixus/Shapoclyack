"use client";

import { useMemo, useState } from "react";
import { Network } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { AttackSurfaceGraph } from "@/components/attack-surface-graph";
import { useRunHosts, useRunPorts, useRuns } from "@/hooks/use-runs";
import { uniqueOwnershipGroups, type GraphGroupBy } from "@/lib/attack-surface";
import { pickLatestRun } from "@/lib/run-data";

const RUN_PICKER_LIMIT = 50;

export default function AttackSurfacePage() {
  // Run picker only needs the newest runs, so one page is enough (P3.3).
  const runsQuery = useRuns(undefined, { limit: RUN_PICKER_LIMIT });
  const [selected, setSelected] = useState<string>("");
  const [groupBy, setGroupBy] = useState<GraphGroupBy>("topology");
  const [ownerKey, setOwnerKey] = useState<string>("all");

  const runs = useMemo(() => runsQuery.data?.items ?? [], [runsQuery.data]);
  const latest = useMemo(() => pickLatestRun(runs), [runs]);
  const runId = selected || latest?.run_id || "";

  const hostsQuery = useRunHosts(runId);
  const portsQuery = useRunPorts(runId);

  const isLoading = runsQuery.isLoading || (Boolean(runId) && (hostsQuery.isLoading || portsQuery.isLoading));
  const error = runsQuery.error || hostsQuery.error || portsQuery.error;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-md">
            <Network className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">Attack Surface Graph</h1>
            <p className="text-xs text-slate-400">
              {groupBy === "owner"
                ? "What this owner exposes in one scan — operator-set unit/owner, else registrable domain. Not an attack path."
                : "One scan's hostname → IP → port → service graph — not an attack path and not an internet-exposure map."}
              {runsQuery.isFetching ? " · Refreshing stream…" : ""}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Select
            value={groupBy}
            onValueChange={(value) => {
              setGroupBy(value as GraphGroupBy);
              setOwnerKey("all");
            }}
          >
            <SelectTrigger className="w-40 bg-slate-900 border-slate-800 text-slate-200">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
              <SelectItem value="topology">Topology</SelectItem>
              <SelectItem value="owner">Ownership</SelectItem>
            </SelectContent>
          </Select>
          {groupBy === "owner" ? (
            <Select value={ownerKey} onValueChange={setOwnerKey}>
              <SelectTrigger className="w-56 bg-slate-900 border-slate-800 text-slate-200">
                <SelectValue placeholder="All owners" />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                <SelectItem value="all">All owners</SelectItem>
                {uniqueOwnershipGroups(hostsQuery.data || []).map((group) => (
                  <SelectItem key={group.key} value={group.key}>
                    {group.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : null}
          <Select value={runId} onValueChange={setSelected}>
            <SelectTrigger className="w-72 bg-slate-900 border-slate-800 text-slate-200">
              <SelectValue placeholder="Select a scan run" />
            </SelectTrigger>
            <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
              {runs.map((run) => (
                <SelectItem key={run.run_id} value={run.run_id} className="font-mono text-xs">
                  {run.run_id}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {error ? (
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
          <AlertDescription>{(error as Error).message}</AlertDescription>
        </Alert>
      ) : null}

      {!runId && !isLoading ? (
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-8 text-center backdrop-blur">
          <p className="text-sm font-semibold text-slate-300">No scan runs telemetry available</p>
          <p className="mt-1 text-xs text-slate-400">Start a scan job to render the network topology map.</p>
        </div>
      ) : isLoading ? (
        <div className="flex items-center justify-center py-16 text-slate-400 gap-2">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
          <span className="text-sm">Building attack surface graph topology…</span>
        </div>
      ) : (
        <AttackSurfaceGraph
          hosts={hostsQuery.data || []}
          ports={portsQuery.data || []}
          groupBy={groupBy}
          ownerKey={ownerKey}
        />
      )}
    </div>
  );
}

