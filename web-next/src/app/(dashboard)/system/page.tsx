"use client";

import { Card, Title } from "@tremor/react";
import { formatDistanceToNow } from "date-fns";
import { Settings, Cpu, Database, Layers, Activity } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { ConfigEditor } from "@/components/config-editor";
import { KpiCard } from "@/components/kpi-card";
import { useSystemStatus } from "@/hooks/use-system";
import { useAuthStore } from "@/lib/auth-store";
import type { EnrichmentDb } from "@/lib/api";

const STALE_AFTER_DAYS = 30;

function EnabledBadge({ on }: { on: boolean }) {
  return (
    <Badge variant={on ? "default" : "outline"} className={on ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30 font-semibold" : "border-slate-800 bg-slate-950 text-slate-500 font-normal"}>
      {on ? "ENABLED" : "DISABLED"}
    </Badge>
  );
}

function freshness(db: EnrichmentDb): { label: string; className: string } {
  if (!db.present) return { label: "missing", className: "bg-rose-500/20 text-rose-300 border-rose-500/30" };
  if (db.age_days != null && db.age_days > STALE_AFTER_DAYS) return { label: "stale", className: "bg-amber-500/20 text-amber-300 border-amber-500/30" };
  return { label: "fresh", className: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30" };
}

function formatBytes(bytes: number | null): string {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function SystemPage() {
  const { data, isLoading, error, isFetching } = useSystemStatus();
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-md">
            <Settings className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">System Telemetry & Config</h1>
            <p className="text-xs text-slate-400">
              Tool versions, enrichment databases, execution flags, and live YAML configuration tuner.
              {isFetching ? " · Refreshing system state…" : ""}
            </p>
          </div>
        </div>
      </div>

      {error ? (
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
          <AlertDescription>{(error as Error).message}</AlertDescription>
        </Alert>
      ) : null}

      {isLoading || !data ? (
        <div className="flex items-center justify-center py-16 text-slate-400 gap-2">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
          <span className="text-sm">Retrieving system diagnostics telemetry…</span>
        </div>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <KpiCard label="App Version" value={data.app_version} decorationColor="sky" />
            <KpiCard label="Active Tenants" value={data.inventory.tenants ?? "—"} decorationColor="indigo" />
            <KpiCard
              label="Fleet Agents Online"
              value={
                data.inventory.agents_total == null
                  ? "—"
                  : `${data.inventory.agents_online ?? 0} / ${data.inventory.agents_total}`
              }
              decorationColor="emerald"
            />
            <KpiCard label="Scan Execution" value={data.runtime.allow_scan_start ? "active" : "disabled"} decorationColor="amber" />
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
              <Title className="text-sm font-bold uppercase tracking-wider text-slate-200">Scanner Toolchain & Binaries</Title>
              <table className="mt-4 w-full text-left text-xs">
                <tbody className="divide-y divide-slate-800/60">
                  {data.tools.map((tool) => (
                    <tr key={tool.name} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-2.5 px-2 font-mono font-bold text-slate-200">{tool.name}</td>
                      <td className="py-2.5 px-2 text-right">
                        {tool.version ? (
                          <code className="rounded bg-slate-950 px-2 py-0.5 font-mono text-[11px] text-sky-400 border border-slate-800">{tool.version}</code>
                        ) : (
                          <Badge variant="destructive" className="bg-rose-500/20 text-rose-300 border-rose-500/30">{tool.error || "unavailable"}</Badge>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>

            <Card className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
              <Title className="text-sm font-bold uppercase tracking-wider text-slate-200">Enrichment Databases</Title>
              <table className="mt-4 w-full text-left text-xs">
                <tbody className="divide-y divide-slate-800/60">
                  {data.enrichment.map((db) => {
                    const badge = freshness(db);
                    return (
                      <tr key={db.name} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-2.5 px-2">
                          <p className="font-mono font-bold uppercase text-slate-200">{db.name}</p>
                          <p className="font-mono text-[10px] text-slate-400">{db.path}</p>
                        </td>
                        <td className="py-2.5 px-2 text-right text-[11px] text-slate-400">
                          {formatBytes(db.size_bytes)}
                          {db.modified_at
                            ? ` · ${formatDistanceToNow(new Date(db.modified_at), { addSuffix: true })}`
                            : ""}
                        </td>
                        <td className="py-2.5 px-2 text-right">
                          <span className={`inline-block rounded px-2 py-0.5 text-[10px] font-bold uppercase border ${badge.className}`}>
                            {badge.label}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </Card>

            <Card className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
              <Title className="text-sm font-bold uppercase tracking-wider text-slate-200">Pipeline Stages & Profiles</Title>
              <div className="mt-4 grid grid-cols-2 gap-y-3 gap-x-4 text-xs">
                {Object.entries(data.scan_config.stages).map(([stage, on]) => (
                  <div key={stage} className="flex items-center justify-between rounded-lg bg-slate-950/60 p-2 border border-slate-800/60">
                    <span className="font-medium text-slate-300">{stage}</span>
                    <EnabledBadge on={on} />
                  </div>
                ))}
              </div>
              <div className="mt-5 space-y-3 pt-3 border-t border-slate-800 text-xs">
                <div>
                  <p className="text-slate-400 font-semibold mb-1">Configured Scan Profiles</p>
                  <div className="flex flex-wrap gap-1.5">
                    {data.scan_config.profiles.map((p) => (
                      <Badge key={p} variant="secondary" className="bg-slate-800 text-sky-300 font-mono text-[11px]">{p}</Badge>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-slate-400 font-semibold mb-1">NSE Script Profiles</p>
                  <div className="flex flex-wrap gap-1.5">
                    {data.scan_config.nse_profiles.map((p) => (
                      <Badge key={p} variant="outline" className="border-slate-700 text-slate-300 font-mono text-[11px]">{p}</Badge>
                    ))}
                  </div>
                </div>
              </div>
            </Card>

            <Card className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
              <Title className="text-sm font-bold uppercase tracking-wider text-slate-200">Runtime Services & Integration</Title>
              <div className="mt-4 space-y-2.5 text-xs">
                <div className="flex items-center justify-between rounded-lg bg-slate-950/60 p-2.5 border border-slate-800/60">
                  <span className="font-semibold text-slate-300">Job Execution Mode</span>
                  <Badge variant="secondary" className="bg-sky-500/20 text-sky-300 border-sky-500/30 uppercase font-bold text-[10px]">{data.runtime.job_execution_mode}</Badge>
                </div>
                <div className="flex items-center justify-between rounded-lg bg-slate-950/60 p-2.5 border border-slate-800/60">
                  <span className="font-semibold text-slate-300">Postgres (Primary Datastore)</span>
                  <EnabledBadge on={data.runtime.postgres_enabled} />
                </div>
                <div className="flex items-center justify-between rounded-lg bg-slate-950/60 p-2.5 border border-slate-800/60">
                  <span className="font-semibold text-slate-300">ClickHouse (Telemetry Data Lake)</span>
                  <EnabledBadge on={data.runtime.clickhouse_enabled} />
                </div>
                <div className="flex items-center justify-between rounded-lg bg-slate-950/60 p-2.5 border border-slate-800/60">
                  <span className="font-semibold text-slate-300">NATS Message Broker</span>
                  <EnabledBadge on={data.runtime.nats_enabled} />
                </div>
                <div className="flex items-center justify-between rounded-lg bg-slate-950/60 p-2.5 border border-slate-800/60">
                  <span className="font-semibold text-slate-300">ClickHouse Ingest Worker</span>
                  <EnabledBadge on={data.runtime.ch_ingest_enabled} />
                </div>
                <div className="flex items-center justify-between rounded-lg bg-slate-950/60 p-2.5 border border-slate-800/60">
                  <span className="font-semibold text-slate-300">Asset Stale Threshold</span>
                  <span className="font-mono font-bold text-sky-400">{data.runtime.asset_stale_days} days</span>
                </div>
              </div>
            </Card>
          </div>

          <ConfigEditor canEdit={isAdmin} />
        </>
      )}
    </div>
  );
}

