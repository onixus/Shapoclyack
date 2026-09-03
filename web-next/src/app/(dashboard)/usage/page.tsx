"use client";

import { useMemo, useState } from "react";
import { BarChart, Card, Title } from "@tremor/react";
import { CircleGauge } from "lucide-react";
import { KpiCard } from "@/components/kpi-card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useFleetUsage, useUpdateTenantQuota, useUsage } from "@/hooks/use-usage";
import { useAuthStore } from "@/lib/auth-store";
import type { TenantUsageRow, UsageResource } from "@/lib/api";
import { useT, type Translate } from "@/lib/i18n";
import {
  barPercent,
  limitLabel,
  monthLabel,
  parseQuotaInput,
  periodLabel,
  quotaInputValue,
  ratioLabel,
  sortByPressure,
  usageTone,
  type UsageTone,
} from "@/lib/usage-format";

const HISTORY_MONTHS = 12;

const TONE_BAR: Record<UsageTone, string> = {
  ok: "bg-emerald-500",
  near: "bg-amber-500",
  over: "bg-rose-500",
};

const TONE_TEXT: Record<UsageTone, string> = {
  ok: "text-foreground",
  near: "text-amber-500",
  over: "text-rose-500",
};

function ToneBadge({ tone, t }: { tone: UsageTone; t: Translate }) {
  if (tone === "over") {
    return (
      <Badge variant="outline" className="border-rose-500/30 text-rose-400">
        {t("page.usage.overLimit")}
      </Badge>
    );
  }
  if (tone === "near") {
    return (
      <Badge variant="outline" className="border-amber-500/30 text-amber-400">
        {t("page.usage.nearLimit")}
      </Badge>
    );
  }
  return null;
}

/** An unlimited resource gets no track at all: a bar has to be some fraction
 * full, and every fraction would be a claim the API did not make. */
function UsageBar({ label, resource, t }: { label: string; resource: UsageResource; t: Translate }) {
  const tone = usageTone(resource);
  const width = barPercent(resource.used_ratio);
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2 text-sm">
        <span className="text-muted-foreground">{label}</span>
        <span className="flex items-center gap-2">
          <ToneBadge tone={tone} t={t} />
          <span className={`font-mono ${TONE_TEXT[tone]}`}>
            {t("page.usage.usedOf", {
              used: resource.used.toLocaleString(),
              limit: limitLabel(resource.limit),
            })}
          </span>
        </span>
      </div>
      {width === null ? (
        <p className="text-xs text-muted-foreground">{t("page.usage.noCeiling")}</p>
      ) : (
        <>
          <div
            role="progressbar"
            aria-label={label}
            aria-valuenow={width}
            aria-valuemin={0}
            aria-valuemax={100}
            className="h-2 w-full overflow-hidden rounded-full bg-muted"
          >
            <div className={`h-full rounded-full ${TONE_BAR[tone]}`} style={{ width: `${width}%` }} />
          </div>
          <p className="text-xs text-muted-foreground">
            {ratioLabel(resource.used_ratio)} ·{" "}
            {t("page.usage.remaining", { count: (resource.remaining ?? 0).toLocaleString() })}
          </p>
        </>
      )}
    </div>
  );
}

function ResourceCell({ resource, t }: { resource: UsageResource; t: Translate }) {
  const tone = usageTone(resource);
  return (
    <div className="space-y-1">
      <span className={`font-mono text-xs ${TONE_TEXT[tone]}`}>
        {t("page.usage.usedOf", {
          used: resource.used.toLocaleString(),
          limit: limitLabel(resource.limit),
        })}
      </span>
      <div className="flex items-center gap-2">
        <span className="text-[11px] text-muted-foreground">{ratioLabel(resource.used_ratio)}</span>
        <ToneBadge tone={tone} t={t} />
      </div>
    </div>
  );
}

/** Prefilled from the ceilings currently in force; an empty box is how both
 * this form and the API spell "unlimited". */
function QuotaEditor({ row, t }: { row: TenantUsageRow; t: Translate }) {
  const [maxAssets, setMaxAssets] = useState(quotaInputValue(row.assets.limit));
  const [maxScans, setMaxScans] = useState(quotaInputValue(row.scans.limit));
  const [note, setNote] = useState("");
  const mutation = useUpdateTenantQuota();
  const pending = mutation.isPending && mutation.variables?.tenantId === row.tenant_id;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Input
        className="h-8 w-24 text-xs"
        inputMode="numeric"
        aria-label={`${t("page.usage.maxAssets")} — ${row.tenant_id}`}
        placeholder={t("page.usage.unlimitedPlaceholder")}
        value={maxAssets}
        onChange={(event) => setMaxAssets(event.target.value)}
      />
      <Input
        className="h-8 w-24 text-xs"
        inputMode="numeric"
        aria-label={`${t("page.usage.maxScans")} — ${row.tenant_id}`}
        placeholder={t("page.usage.unlimitedPlaceholder")}
        value={maxScans}
        onChange={(event) => setMaxScans(event.target.value)}
      />
      <Input
        className="h-8 w-36 text-xs"
        aria-label={`${t("page.usage.note")} — ${row.tenant_id}`}
        placeholder={t("page.usage.note")}
        value={note}
        onChange={(event) => setNote(event.target.value)}
      />
      <Button
        type="button"
        size="sm"
        variant="outline"
        className="h-8 text-xs"
        disabled={pending}
        onClick={() =>
          mutation.mutate({
            tenantId: row.tenant_id,
            quota: {
              max_assets: parseQuotaInput(maxAssets),
              max_scans_per_month: parseQuotaInput(maxScans),
              ...(note.trim() ? { note: note.trim() } : {}),
            },
          })
        }
      >
        {pending ? t("page.usage.saving") : t("page.usage.save")}
      </Button>
    </div>
  );
}

export default function UsagePage() {
  const t = useT();
  const user = useAuthStore((state) => state.user);
  const isPlatformAdmin = Boolean(user?.is_platform_admin);
  const { data, isLoading, error } = useUsage(HISTORY_MONTHS);
  const fleet = useFleetUsage(isPlatformAdmin);

  const history = useMemo(
    () =>
      (data?.scan_history ?? []).map((point) => ({
        month: monthLabel(point.month),
        Scans: point.scans,
      })),
    [data],
  );
  const fleetRows = useMemo(() => sortByPressure(fleet.data?.tenants ?? []), [fleet.data]);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-sky-500/20 bg-sky-500/10 text-sky-500 shadow-md">
          <CircleGauge className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">
            {t("page.usage.title")}
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            {t("page.usage.subtitle")}
          </p>
        </div>
      </div>

      {error ? (
        <p className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-400">
          {(error as Error).message}
        </p>
      ) : null}

      {isLoading || !data ? (
        <p className="text-sm text-muted-foreground">{t("page.usage.loading")}</p>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <KpiCard
              label={t("page.usage.assets")}
              value={data.assets.used}
              hint={t("page.usage.usedOf", {
                used: data.assets.used.toLocaleString(),
                limit: limitLabel(data.assets.limit),
              })}
              href="/assets"
              decorationColor={
                usageTone(data.assets) === "over"
                  ? "rose"
                  : usageTone(data.assets) === "near"
                    ? "amber"
                    : "blue"
              }
            />
            <KpiCard
              label={t("page.usage.scans")}
              value={data.scans.used}
              hint={t("page.usage.usedOf", {
                used: data.scans.used.toLocaleString(),
                limit: limitLabel(data.scans.limit),
              })}
              href="/runs"
              decorationColor={
                usageTone(data.scans) === "over"
                  ? "rose"
                  : usageTone(data.scans) === "near"
                    ? "amber"
                    : "sky"
              }
            />
            <KpiCard
              label={t("page.usage.period")}
              value={periodLabel(data.period_start, data.period_end)}
              hint={data.enforced ? t("page.usage.enforcedOn") : t("page.usage.enforcedOff")}
              decorationColor={data.enforced ? "emerald" : "slate"}
            />
            <KpiCard
              label={t("page.usage.quotaSource")}
              value={
                data.quota_source === "tenant"
                  ? t("page.usage.source.tenant")
                  : t("page.usage.source.default")
              }
              hint={
                data.updated_at
                  ? t("page.usage.updatedBy", {
                      at: data.updated_at.slice(0, 10),
                      by: data.updated_by ?? "—",
                    })
                  : undefined
              }
              decorationColor={data.quota_source === "tenant" ? "sky" : "slate"}
            />
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <section className="space-y-5 rounded-xl border border-border bg-card p-5">
              <h2 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                {t("page.usage.period")} · {periodLabel(data.period_start, data.period_end)}
              </h2>
              <UsageBar label={t("page.usage.assets")} resource={data.assets} t={t} />
              <UsageBar label={t("page.usage.scans")} resource={data.scans} t={t} />
              <dl className="space-y-1.5 border-t border-border/60 pt-3 text-sm">
                <div className="flex justify-between gap-3">
                  <dt className="text-muted-foreground">{t("page.usage.enforcement")}</dt>
                  <dd className="text-right text-foreground">
                    {data.enforced ? t("page.usage.enforcedOn") : t("page.usage.enforcedOff")}
                  </dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-muted-foreground">{t("page.usage.quotaSource")}</dt>
                  <dd className="text-right text-foreground">
                    {data.quota_source === "tenant"
                      ? t("page.usage.source.tenant")
                      : t("page.usage.source.default")}
                  </dd>
                </div>
                {data.note ? (
                  <div className="flex justify-between gap-3">
                    <dt className="text-muted-foreground">{t("page.usage.note")}</dt>
                    <dd className="text-right text-foreground">{data.note}</dd>
                  </div>
                ) : null}
              </dl>
            </section>

            <Card className="rounded-xl border border-border bg-card p-5 shadow-sm lg:col-span-2">
              <Title className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                {t("page.usage.history")}
              </Title>
              {history.length === 0 ? (
                <p className="mt-3 text-sm text-muted-foreground">
                  {t("page.usage.historyEmpty")}
                </p>
              ) : (
                <BarChart
                  className="mt-4 h-64"
                  data={history}
                  index="month"
                  categories={["Scans"]}
                  colors={["cyan"]}
                  showLegend={false}
                  showAnimation={false}
                  yAxisWidth={40}
                />
              )}
              <p className="mt-3 text-xs text-muted-foreground">{t("page.usage.historyHint")}</p>
            </Card>
          </div>
        </>
      )}

      {isPlatformAdmin ? (
        <section className="space-y-2 rounded-xl border border-border bg-card p-5">
          <h2 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
            {t("page.usage.fleet")}
          </h2>
          <p className="text-xs text-muted-foreground">{t("page.usage.fleetHint")}</p>
          {fleet.error ? (
            <p className="text-sm text-rose-400">{(fleet.error as Error).message}</p>
          ) : fleet.isLoading ? (
            <p className="text-sm text-muted-foreground">{t("page.usage.loading")}</p>
          ) : fleetRows.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("page.usage.fleetEmpty")}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-xs uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="py-1.5 font-semibold">{t("page.usage.col.tenant")}</th>
                    <th className="py-1.5 font-semibold">{t("page.usage.col.assets")}</th>
                    <th className="py-1.5 font-semibold">{t("page.usage.col.scans")}</th>
                    <th className="py-1.5 font-semibold">{t("page.usage.col.quota")}</th>
                  </tr>
                </thead>
                <tbody>
                  {fleetRows.map((row) => (
                    <tr
                      key={row.tenant_id}
                      className={
                        row.assets.over_limit || row.scans.over_limit
                          ? "border-t border-border/60 bg-rose-500/5"
                          : "border-t border-border/60"
                      }
                    >
                      <td className="py-2 pr-3 align-top">
                        <p className="font-semibold text-foreground">{row.name}</p>
                        <p className="font-mono text-[10px] text-muted-foreground">
                          {row.tenant_id} ·{" "}
                          {row.quota_source === "tenant"
                            ? t("page.usage.source.tenant")
                            : t("page.usage.source.default")}
                        </p>
                      </td>
                      <td className="py-2 pr-3 align-top">
                        <ResourceCell resource={row.assets} t={t} />
                      </td>
                      <td className="py-2 pr-3 align-top">
                        <ResourceCell resource={row.scans} t={t} />
                      </td>
                      <td className="py-2 align-top">
                        <QuotaEditor row={row} t={t} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      ) : null}
    </div>
  );
}
