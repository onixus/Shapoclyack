"use client";

import { Card, Title } from "@tremor/react";
import { formatDistanceToNow } from "date-fns";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { KpiCard } from "@/components/kpi-card";
import { useSystemStatus } from "@/hooks/use-system";
import type { EnrichmentDb } from "@/lib/api";

const STALE_AFTER_DAYS = 30;

function EnabledBadge({ on }: { on: boolean }) {
  return <Badge variant={on ? "default" : "outline"}>{on ? "on" : "off"}</Badge>;
}

function freshness(db: EnrichmentDb): { label: string; variant: "default" | "secondary" | "destructive" | "outline" } {
  if (!db.present) return { label: "missing", variant: "destructive" };
  if (db.age_days != null && db.age_days > STALE_AFTER_DAYS) return { label: "stale", variant: "destructive" };
  return { label: "fresh", variant: "secondary" };
}

function formatBytes(bytes: number | null): string {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function SystemPage() {
  const { data, isLoading, error, isFetching } = useSystemStatus();

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">System</h1>
          <p className="text-sm text-muted-foreground">
            Read-only installation status from <code className="text-xs">GET /api/system</code> —
            tool versions, enrichment data freshness, enabled stages, runtime.
            {isFetching ? " · refreshing…" : ""}
          </p>
        </div>
      </div>

      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{(error as Error).message}</AlertDescription>
        </Alert>
      ) : null}

      {isLoading || !data ? (
        <p className="text-sm text-muted-foreground">Loading system status…</p>
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-4">
            <KpiCard label="App version" value={data.app_version} decorationColor="blue" />
            <KpiCard label="Tenants" value={data.inventory.tenants ?? "—"} />
            <KpiCard
              label="Agents online"
              value={
                data.inventory.agents_total == null
                  ? "—"
                  : `${data.inventory.agents_online ?? 0} / ${data.inventory.agents_total}`
              }
            />
            <KpiCard label="Scan start" value={data.runtime.allow_scan_start ? "enabled" : "disabled"} />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <Title>Scanner toolchain</Title>
              <table className="mt-4 w-full text-sm">
                <tbody>
                  {data.tools.map((tool) => (
                    <tr key={tool.name} className="border-b border-slate-100 last:border-0">
                      <td className="py-2 font-medium text-slate-800">{tool.name}</td>
                      <td className="py-2 text-right">
                        {tool.version ? (
                          <code className="text-xs">{tool.version}</code>
                        ) : (
                          <Badge variant="destructive">{tool.error || "unavailable"}</Badge>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>

            <Card>
              <Title>Enrichment databases</Title>
              <table className="mt-4 w-full text-sm">
                <tbody>
                  {data.enrichment.map((db) => {
                    const badge = freshness(db);
                    return (
                      <tr key={db.name} className="border-b border-slate-100 last:border-0">
                        <td className="py-2">
                          <p className="font-medium uppercase text-slate-800">{db.name}</p>
                          <p className="font-mono text-[11px] text-muted-foreground">{db.path}</p>
                        </td>
                        <td className="py-2 text-right text-xs text-muted-foreground">
                          {formatBytes(db.size_bytes)}
                          {db.modified_at
                            ? ` · ${formatDistanceToNow(new Date(db.modified_at), { addSuffix: true })}`
                            : ""}
                        </td>
                        <td className="py-2 pl-3 text-right">
                          <Badge variant={badge.variant}>{badge.label}</Badge>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </Card>

            <Card>
              <Title>Pipeline stages</Title>
              <div className="mt-4 grid grid-cols-2 gap-y-3 text-sm">
                {Object.entries(data.scan_config.stages).map(([stage, on]) => (
                  <div key={stage} className="flex items-center justify-between pr-4">
                    <span className="text-slate-700">{stage}</span>
                    <EnabledBadge on={on} />
                  </div>
                ))}
              </div>
              <div className="mt-6 space-y-2 text-sm">
                <div>
                  <p className="text-xs text-muted-foreground">Scan profiles</p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {data.scan_config.profiles.map((p) => (
                      <Badge key={p} variant="secondary">{p}</Badge>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">NSE profiles</p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {data.scan_config.nse_profiles.map((p) => (
                      <Badge key={p} variant="outline">{p}</Badge>
                    ))}
                  </div>
                </div>
              </div>
            </Card>

            <Card>
              <Title>Runtime</Title>
              <div className="mt-4 space-y-3 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-slate-700">Job execution mode</span>
                  <Badge variant="secondary">{data.runtime.job_execution_mode}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-700">Postgres (tenant store)</span>
                  <EnabledBadge on={data.runtime.postgres_enabled} />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-700">ClickHouse (analytics)</span>
                  <EnabledBadge on={data.runtime.clickhouse_enabled} />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-700">NATS (broker)</span>
                  <EnabledBadge on={data.runtime.nats_enabled} />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-700">ClickHouse ingest worker</span>
                  <EnabledBadge on={data.runtime.ch_ingest_enabled} />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-700">Asset stale threshold</span>
                  <span className="tabular-nums text-slate-600">{data.runtime.asset_stale_days} days</span>
                </div>
              </div>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
