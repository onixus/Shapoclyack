"use client";

import { useMemo, useState } from "react";
import { Share2 } from "lucide-react";
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
import { pickLatestRun } from "@/lib/run-data";

export default function AttackSurfacePage() {
  const runsQuery = useRuns();
  const [selected, setSelected] = useState<string>("");

  const latest = useMemo(() => pickLatestRun(runsQuery.data || []), [runsQuery.data]);
  const runId = selected || latest?.run_id || "";

  const hostsQuery = useRunHosts(runId);
  const portsQuery = useRunPorts(runId);

  const isLoading = runsQuery.isLoading || (Boolean(runId) && (hostsQuery.isLoading || portsQuery.isLoading));
  const error = runsQuery.error || hostsQuery.error || portsQuery.error;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex items-center gap-3">
          <Share2 className="h-6 w-6 text-slate-500" />
          <div>
            <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Attack surface</h1>
            <p className="text-sm text-muted-foreground">
              Hostnames → IPs → ports for a scan run, clustered by GeoIP country.
              {runsQuery.isFetching ? " · refreshing…" : ""}
            </p>
          </div>
        </div>
        <Select value={runId} onValueChange={setSelected}>
          <SelectTrigger className="w-72">
            <SelectValue placeholder="Select a run" />
          </SelectTrigger>
          <SelectContent>
            {(runsQuery.data || []).map((run) => (
              <SelectItem key={run.run_id} value={run.run_id}>
                {run.run_id}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{(error as Error).message}</AlertDescription>
        </Alert>
      ) : null}

      {!runId && !isLoading ? (
        <p className="rounded-md border bg-white px-3 py-6 text-center text-sm text-muted-foreground">
          No scan runs yet. Start a job, then return here to explore the attack surface.
        </p>
      ) : isLoading ? (
        <p className="text-sm text-muted-foreground">Loading attack surface…</p>
      ) : (
        <AttackSurfaceGraph hosts={hostsQuery.data || []} ports={portsQuery.data || []} />
      )}
    </div>
  );
}
