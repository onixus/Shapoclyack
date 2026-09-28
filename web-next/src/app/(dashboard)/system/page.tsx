"use client";

import { Card, Title } from "@tremor/react";
import { Settings } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { ConfigEditor } from "@/components/config-editor";
import { KpiCard } from "@/components/kpi-card";
import { useAgentSummary } from "@/hooks/use-agents";
import { useRetroMatchStatus } from "@/hooks/use-retro-match";
import { useSystemStatus } from "@/hooks/use-system";
import { holdsPermission, useAuthStore } from "@/lib/auth-store";
import type { EnrichmentDb } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { useRelativeTime } from "@/lib/i18n/datetime";

const STALE_AFTER_DAYS = 30;

function EnabledBadge({ on }: { on: boolean }) {
  const t = useT();
  return (
    <Badge variant={on ? "default" : "outline"} className={on ? "bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 font-semibold" : "border-border bg-muted text-muted-foreground font-normal"}>
      {on ? t.label("enabled").toUpperCase() : t.label("disabled").toUpperCase()}
    </Badge>
  );
}

// Age and size describe a seed and a real corpus identically — the seed's mtime
// is the build's — so `present && !stale` used to render a fresh-built
// eight-advisory placeholder as a green `fresh`. `usable` is the one field that
// separates them: the build's own verdict against the dataset's floor. `null`
// is not `false`: it means no manifest was found, which is a statement about
// the image, not about the data.
function freshness(db: EnrichmentDb): { label: string; className: string } {
  if (!db.present) return { label: "missing", className: "bg-rose-500/20 text-rose-600 dark:text-rose-300 border-rose-500/30" };
  const stale = db.stale ?? (db.age_days != null && db.age_days > STALE_AFTER_DAYS);
  if (stale) return { label: "stale", className: "bg-amber-500/20 text-amber-600 dark:text-amber-300 border-amber-500/30" };
  if (db.usable === false) return { label: "stub", className: "bg-amber-500/20 text-amber-600 dark:text-amber-300 border-amber-500/30" };
  return { label: "fresh", className: "bg-emerald-500/20 text-emerald-600 dark:text-emerald-300 border-emerald-500/30" };
}

function formatBytes(bytes: number | null): string {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function SystemPage() {
  const ago = useRelativeTime();
  const t = useT();
  const { data, isLoading, error, isFetching } = useSystemStatus();
  const retroDataset = useRetroMatchStatus().data?.dataset ?? null;
  // "active" only says scan start is allowed. In agent mode a started scan
  // also needs a sensor to take it, and with none the tile used to read
  // "active" over a queue that would never move (#338).
  const fleet = useAgentSummary().data;
  const noSensor =
    data?.runtime.job_execution_mode === "agent" && fleet?.scan_ready_agents === 0;
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  // GET /api/config needs `config.read` since #318, which a viewer does not
  // hold: rendering the panel for one would show an error where there used to
  // be a read-only view. The fallback keeps the panel for anyone above viewer
  // on an API that predates the permission list.
  const canReadConfig = useAuthStore((s) =>
    holdsPermission(s.user, "config.read", s.user?.role !== "viewer"),
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20 shadow-md">
            <Settings className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-foreground">{t("page.system.title")}</h1>
            <p className="text-xs text-muted-foreground">
              {t("page.system.subtitle")}
              {isFetching ? t("common.refreshing") : ""}
            </p>
          </div>
        </div>
      </div>

      {error ? (
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-50 dark:bg-rose-950/40 text-rose-800 dark:text-rose-200">
          <AlertDescription>{(error as Error).message}</AlertDescription>
        </Alert>
      ) : null}

      {isLoading || !data ? (
        <div className="flex items-center justify-center py-16 text-muted-foreground gap-2">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
          <span className="text-sm">{t("loading.system")}</span>
        </div>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <KpiCard label={t("kpi.appVersion")} value={data.app_version} decorationColor="sky" />
            <KpiCard label={t("kpi.activeTenants")} value={data.inventory.tenants ?? "—"} decorationColor="indigo" />
            <KpiCard
              label={t("kpi.fleetOnline")}
              value={
                data.inventory.agents_total == null
                  ? "—"
                  : `${data.inventory.agents_online ?? 0} / ${data.inventory.agents_total}`
              }
              decorationColor="emerald"
            />
            <KpiCard
              label={t("kpi.scanExecution")}
              value={
                !data.runtime.allow_scan_start
                  ? "disabled"
                  : noSensor
                    ? t("kpi.scanExecutionNoSensor")
                    : "active"
              }
              hint={noSensor ? t("kpi.scanExecutionNoSensorHint") : undefined}
              href={noSensor ? "/agents" : undefined}
              decorationColor={noSensor ? "rose" : "amber"}
            />
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="rounded-xl border border-border bg-card p-5 shadow-lg backdrop-blur">
              <Title className="text-sm font-bold uppercase tracking-wider text-foreground">Scanner Toolchain & Binaries</Title>
              <table className="mt-4 w-full text-left text-xs">
                <tbody className="divide-y divide-border">
                  {data.tools.map((tool) => (
                    <tr key={tool.name} className="hover:bg-muted transition-colors">
                      <td className="py-2.5 px-2 font-mono font-bold text-foreground">
                        {tool.name}
                        {tool.optional ? (
                          <span className="ml-1.5 text-[10px] font-semibold uppercase text-muted-foreground">optional</span>
                        ) : null}
                      </td>
                      <td className="py-2.5 px-2 text-right">
                        {tool.version ? (
                          <code className="rounded bg-muted px-2 py-0.5 font-mono text-[11px] text-sky-600 dark:text-sky-400 border border-border">{tool.version}</code>
                        ) : tool.optional ? (
                          <Badge variant="secondary" className="bg-muted text-muted-foreground border-border">
                            {tool.error || "not installed"}
                          </Badge>
                        ) : (
                          <Badge variant="destructive" className="bg-rose-500/20 text-rose-600 dark:text-rose-300 border-rose-500/30">{tool.error || "unavailable"}</Badge>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>

            <Card className="rounded-xl border border-border bg-card p-5 shadow-lg backdrop-blur">
              <Title className="text-sm font-bold uppercase tracking-wider text-foreground">{t("ui.enrichmentDatabases")}</Title>
              <table className="mt-4 w-full text-left text-xs">
                <tbody className="divide-y divide-border">
                  {data.enrichment.map((db) => {
                    const badge = freshness(db);
                    return (
                      <tr key={db.name} className="hover:bg-muted transition-colors">
                        <td className="py-2.5 px-2">
                          <p className="font-mono font-bold uppercase text-foreground">{db.name}</p>
                          <p className="font-mono text-[10px] text-muted-foreground">{db.path}</p>
                          {/* The file's age says when it was written; what the
                              retro matcher actually loaded from it — or why it
                              could not — is the retro status's answer. */}
                          {db.name === "nvd_cpe" && retroDataset ? (
                            <p className="text-[10px] text-muted-foreground" data-testid="nvd-cpe-detail">
                              {!retroDataset.present ? (
                                t("retro.noDataset")
                              ) : retroDataset.error ? (
                                <span className="text-rose-600 dark:text-rose-400">{retroDataset.error}</span>
                              ) : (
                                <>
                                  {t("page.system.nvdCpe.summary", {
                                    products: retroDataset.products.toLocaleString(),
                                    statements: retroDataset.statements.toLocaleString(),
                                  })}
                                  {retroDataset.updated
                                    ? ` · ${t("page.system.nvdCpe.updated", { date: retroDataset.updated })}`
                                    : ""}
                                </>
                              )}
                            </p>
                          ) : null}
                        </td>
                        <td className="py-2.5 px-2 text-right text-[11px] text-muted-foreground">
                          {formatBytes(db.size_bytes)}
                          {db.modified_at
                            ? ` · ${ago(db.modified_at)}`
                            : ""}
                        </td>
                        <td className="py-2.5 px-2 text-right">
                          <span
                            data-testid="enrichment-freshness"
                            title={db.usable === false ? t("page.system.enrichment.stub") : undefined}
                            className={`inline-block rounded px-2 py-0.5 text-[10px] font-bold uppercase border ${badge.className}`}
                          >
                            {t.label(badge.label)}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </Card>

            <Card className="rounded-xl border border-border bg-card p-5 shadow-lg backdrop-blur">
              <Title className="text-sm font-bold uppercase tracking-wider text-foreground">Pipeline Stages & Profiles</Title>
              <div className="mt-4 grid grid-cols-2 gap-y-3 gap-x-4 text-xs">
                {Object.entries(data.scan_config.stages).map(([stage, on]) => (
                  <div key={stage} className="flex items-center justify-between rounded-lg bg-muted p-2 border border-border">
                    <span className="font-medium text-foreground">{stage}</span>
                    <EnabledBadge on={on} />
                  </div>
                ))}
              </div>
              <div className="mt-5 space-y-3 pt-3 border-t border-border text-xs">
                {data.scan_config.service_backend ? (
                  <div className="flex items-center justify-between rounded-lg bg-muted p-2 border border-border">
                    <span className="font-medium text-foreground">{t("ui.serviceProbeBackend")}</span>
                    <Badge variant="secondary" className="bg-sky-500/20 text-sky-600 dark:text-sky-300 border-sky-500/30 font-mono text-[11px]">
                      {data.scan_config.service_backend}
                    </Badge>
                  </div>
                ) : null}
                <div>
                  <p className="text-muted-foreground font-semibold mb-1">{t("ui.speedProfiles")}</p>
                  <div className="flex flex-wrap gap-1.5">
                    {data.scan_config.profiles.map((p) => (
                      <Badge key={p} variant="secondary" className="bg-muted text-sky-600 dark:text-sky-300 font-mono text-[11px]">{p}</Badge>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-muted-foreground font-semibold mb-1">{t("ui.legacyNmapNseProfiles")}</p>
                  <p className="text-[10px] text-muted-foreground mb-1.5">{t("ui.usedOnlyWhenBackendIsNmap")}</p>
                  <div className="flex flex-wrap gap-1.5">
                    {data.scan_config.nse_profiles.map((p) => (
                      <Badge key={p} variant="outline" className="border-border text-foreground font-mono text-[11px]">{p}</Badge>
                    ))}
                  </div>
                </div>
              </div>
            </Card>

            <Card className="rounded-xl border border-border bg-card p-5 shadow-lg backdrop-blur">
              <Title className="text-sm font-bold uppercase tracking-wider text-foreground">Runtime Services & Integration</Title>
              <div className="mt-4 space-y-2.5 text-xs">
                <div className="flex items-center justify-between rounded-lg bg-muted p-2.5 border border-border">
                  <span className="font-semibold text-foreground">{t("ui.jobExecutionMode")}</span>
                  <Badge variant="secondary" className="bg-sky-500/20 text-sky-600 dark:text-sky-300 border-sky-500/30 uppercase font-bold text-[10px]">{data.runtime.job_execution_mode}</Badge>
                </div>
                <div className="flex items-center justify-between rounded-lg bg-muted p-2.5 border border-border">
                  <span className="font-semibold text-foreground">{t("ui.postgresPrimary")}</span>
                  <EnabledBadge on={data.runtime.postgres_enabled} />
                </div>
                <div className="flex items-center justify-between rounded-lg bg-muted p-2.5 border border-border">
                  <span className="font-semibold text-foreground">{t("ui.clickhouseLake")}</span>
                  <EnabledBadge on={data.runtime.clickhouse_enabled} />
                </div>
                <div className="flex items-center justify-between rounded-lg bg-muted p-2.5 border border-border">
                  <span className="font-semibold text-foreground">NATS Message Broker</span>
                  <EnabledBadge on={data.runtime.nats_enabled} />
                </div>
                <div className="flex items-center justify-between rounded-lg bg-muted p-2.5 border border-border">
                  <span className="font-semibold text-foreground">{t("ui.clickhouseIngestWorker")}</span>
                  <EnabledBadge on={data.runtime.ch_ingest_enabled} />
                </div>
                <div className="flex items-center justify-between rounded-lg bg-muted p-2.5 border border-border">
                  <span className="font-semibold text-foreground">{t("ui.assetStaleThreshold")}</span>
                  <span className="font-mono font-bold text-sky-600 dark:text-sky-400">{data.runtime.asset_stale_days} days</span>
                </div>
              </div>
            </Card>

            <Card className="rounded-xl border border-border bg-card p-5 shadow-lg backdrop-blur">
              <Title className="text-sm font-bold uppercase tracking-wider text-foreground">Endpoint Inventory & Retention</Title>
              <div className="mt-4 space-y-2.5 text-xs">
                <div className="flex items-center justify-between rounded-lg bg-muted p-2.5 border border-border">
                  <span className="font-semibold text-foreground">{t("ui.endpointIngestion")}</span>
                  <EnabledBadge on={data.endpoint_inventory.enabled} />
                </div>
                <div className="flex items-center justify-between rounded-lg bg-muted p-2.5 border border-border">
                  <span className="font-semibold text-foreground">{t("ui.endpointsStaleTotal")}</span>
                  <span className="font-mono font-bold text-sky-600 dark:text-sky-400">
                    {data.endpoint_inventory.devices_stale ?? "—"} / {data.endpoint_inventory.devices_total ?? "—"}
                  </span>
                </div>
                <div className="flex items-center justify-between rounded-lg bg-muted p-2.5 border border-border">
                  <span className="font-semibold text-foreground">{t("ui.endpointStaleThreshold")}</span>
                  <span className="font-mono font-bold text-sky-600 dark:text-sky-400">{data.endpoint_inventory.stale_hours} hours</span>
                </div>
                <div className="flex items-center justify-between rounded-lg bg-muted p-2.5 border border-border">
                  <span className="font-semibold text-foreground">{t("ui.retentionJob")}</span>
                  <EnabledBadge on={data.endpoint_inventory.retention_enabled} />
                </div>
                <div className="flex items-center justify-between rounded-lg bg-muted p-2.5 border border-border">
                  <span className="font-semibold text-foreground">{t("ui.softwareRowsChangeEvents")}</span>
                  <span className="font-mono font-bold text-sky-600 dark:text-sky-400">
                    {data.endpoint_inventory.snapshot_retention_days}d / {data.endpoint_inventory.change_retention_days}d
                  </span>
                </div>
                <div className="flex items-center justify-between rounded-lg bg-muted p-2.5 border border-border">
                  <span className="font-semibold text-foreground">{t("ui.lastRetentionSweep")}</span>
                  <span className="font-mono font-bold text-sky-600 dark:text-sky-400">
                    {data.endpoint_inventory.retention_last_run_at
                      ? ago(data.endpoint_inventory.retention_last_run_at)
                      : "not yet run"}
                  </span>
                </div>
              </div>
            </Card>
          </div>

          {canReadConfig ? <ConfigEditor canEdit={isAdmin} /> : null}
        </>
      )}
    </div>
  );
}

