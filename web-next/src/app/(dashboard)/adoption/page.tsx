"use client";

import { useState } from "react";
import { useT } from "@/lib/i18n";
import { KpiCard } from "@/components/kpi-card";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAdoption } from "@/hooks/use-adoption";
import type { AdoptionMetrics, AdoptionNoiseSource } from "@/lib/api";
import { hours, scanHistoryReason, scopeReason, share } from "@/lib/adoption-format";

const WINDOWS = [30, 90, 180, 365] as const;

function NoiseTable({
  rows,
  threshold,
  caption,
}: {
  rows: AdoptionNoiseSource[];
  threshold: number;
  caption: string;
}) {
  const t = useT();
  if (rows.length === 0) {
    return <p className="text-sm text-muted-foreground">{caption}</p>;
  }
  return (
    <table className="w-full text-sm">
      <thead className="text-left text-xs uppercase tracking-wider text-muted-foreground">
        <tr>
          <th className="py-1.5 font-semibold">{t("ui.source")}</th>
          <th className="py-1.5 text-right font-semibold">{t("ui.closed")}</th>
          <th className="py-1.5 text-right font-semibold">{t("ui.falsePositives")}</th>
          <th className="py-1.5 text-right font-semibold">{t("ui.rate")}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.source} className="border-t border-border/60">
            <td className="py-1.5 font-mono text-foreground">{row.source}</td>
            <td className="py-1.5 text-right text-foreground">{row.closed}</td>
            <td className="py-1.5 text-right text-foreground">{row.false_positive}</td>
            <td
              className="py-1.5 text-right font-mono text-foreground"
              title={
                row.false_positive_share === null
                  ? `Fewer than ${threshold} closures: the counts are the honest answer, a rate computed from them is not.`
                  : undefined
              }
            >
              {share(row.false_positive_share)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SeverityRow({ label, value }: { label: string; value: number | null }) {
  return (
    <li className="flex items-center justify-between border-b border-border/60 py-1.5 text-sm last:border-0">
      <span className="capitalize text-muted-foreground">{label}</span>
      <span className="font-mono text-foreground">{hours(value)}</span>
    </li>
  );
}

function Analysts({ rows }: { rows: AdoptionMetrics["analysts"] }) {
  const t = useT();
  if (rows.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        {t("prose.noFindingsWereClosedIn")}
      </p>
    );
  }
  return (
    <table className="w-full text-sm">
      <thead className="text-left text-xs uppercase tracking-wider text-muted-foreground">
        <tr>
          <th className="py-1.5 font-semibold">{t("ui.analyst")}</th>
          <th className="py-1.5 text-right font-semibold">{t("ui.closed")}</th>
          <th className="py-1.5 text-right font-semibold">{t("ui.verifiedByScan")}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.analyst} className="border-t border-border/60">
            <td className="py-1.5 font-mono text-foreground">{row.analyst}</td>
            <td className="py-1.5 text-right text-foreground">{row.closed}</td>
            <td className="py-1.5 text-right text-foreground">{row.machine_verified}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function AdoptionPage() {
  const t = useT();
  const [windowDays, setWindowDays] = useState<number>(90);
  const { data, isLoading, error } = useAdoption(windowDays);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">{t("ui.adoption")}</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            {t("prose.whetherThePlatformIsProducing")}
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          {t("ui.window")}
          <Select value={String(windowDays)} onValueChange={(value) => setWindowDays(Number(value))}>
            <SelectTrigger className="w-28" aria-label={t("adoption.windowDays")}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {WINDOWS.map((days) => (
                <SelectItem key={days} value={String(days)}>
                  {days} days
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </label>
      </div>

      {error ? (
        <p className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-600 dark:text-rose-400">
          {(error as Error).message}
        </p>
      ) : null}
      {isLoading || !data ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (
        <>
          <section>
            <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
              Outcomes, last {data.window_days} days
            </h2>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <KpiCard
                label={t("adoption.closed")}
                value={data.findings.closed_in_window}
                hint={t("hint.stillOpen", {
            open: data.findings.open,
            accepted: data.findings.accepted_open,
            noise: data.findings.false_positive_in_window,
          })}
                href="/vulnerabilities"
                decorationColor="blue"
              />
              <KpiCard
                label={t("adoption.confirmedByScan")}
                value={share(data.findings.machine_verified_share)}
                hint={t("hint.verifiedMechanically", {
            verified: data.findings.machine_verified_closed,
            closed: data.findings.closed_in_window,
          })}
                decorationColor={
                  data.findings.machine_verified_share === null
                    ? "slate"
                    : data.findings.machine_verified_share >= 50
                      ? "emerald"
                      : "amber"
                }
              />
              <KpiCard
                label={t("adoption.closedWithinSla")}
                value={share(data.findings.closed_within_sla_share)}
                hint={t("hint.ofClosuresWithDeadline")}
                decorationColor="emerald"
              />
              <KpiCard
                label={t("adoption.medianTimeToFix")}
                value={hours(data.findings.mttr_hours)}
                hint={t("hint.fromSlaStart")}
                decorationColor="orange"
              />
            </div>
          </section>

          {data.false_positives ? (
            <section>
              <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                Noise, last {data.window_days} days
              </h2>
              <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <KpiCard
                  label={t("adoption.closedAsNoise")}
                  value={data.false_positives.in_window}
                  hint={`Of everything closed in the window, ${share(
                    data.false_positives.share_of_closures,
                  )} was never a real finding`}
                  decorationColor="amber"
                />
                <KpiCard
                  label={t("adoption.suppressions")}
                  value={data.false_positives.suppressions_active}
                  hint={t("hint.suppressionsLapsed", { count: data.false_positives.suppressions_lapsed })}
                  decorationColor={
                    data.false_positives.suppressions_lapsed > 0 ? "amber" : "slate"
                  }
                />
                <KpiCard
                  label={t("adoption.brokenByEvidence")}
                  value={data.false_positives.overridden_in_window}
                  hint={t("hint.overriddenVerdicts")}
                  decorationColor={
                    data.false_positives.overridden_in_window > 0 ? "rose" : "slate"
                  }
                />
                <KpiCard
                  label={t("adoption.medianTimeToVerdict")}
                  value={hours(data.false_positives.median_hours_to_verdict)}
                  hint={t("hint.noiseQueueTime")}
                  decorationColor="sky"
                />
              </div>
              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <div className="rounded-xl border border-border bg-card p-5">
                  <h3 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                    {t("prose.noisiestDetectors")}
                  </h3>
                  <NoiseTable
                    rows={data.false_positives.by_source}
                    threshold={data.false_positives.source_threshold}
                    caption="Nothing was closed as noise in this window."
                  />
                  <p className="mt-3 text-xs text-muted-foreground">
                    A rate needs at least {data.false_positives.source_threshold} closures behind
                    it; below that the counts are shown and the rate is not, because one verdict
                    out of one closure is not a 100% error rate. Findings matched from an advisory
                    have no detector and are counted as <span className="font-mono">unknown</span>
                    {" "}rather than blamed on a script.
                  </p>
                </div>
                <div className="rounded-xl border border-border bg-card p-5">
                  <h3 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                    By observer
                  </h3>
                  <NoiseTable
                    rows={data.false_positives.by_origin}
                    threshold={data.false_positives.source_threshold}
                    caption="Nothing was closed in this window."
                  />
                  <p className="mt-3 text-xs text-muted-foreground">
                    {t("prose.theNetworkScannerAgainstThe")}
                  </p>
                </div>
              </div>
            </section>
          ) : null}

          {data.coverage ? (
            <section>
              <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                Coverage
              </h2>
              <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <KpiCard
                  label={`Scanned in ${data.coverage.coverage_days} days`}
                  value={share(data.coverage.scanned_share)}
                  hint={
                    scanHistoryReason(data.coverage.scan_history_reason) ??
                    `${data.coverage.assets_with_scan_history} active assets have been reached by a scan at some point`
                  }
                  decorationColor={data.coverage.scanned_share === null ? "slate" : "blue"}
                />
                <KpiCard
                  label={`Assessed for vulnerabilities in ${data.coverage.coverage_days} days`}
                  value={share(data.coverage.vuln_scanned_share)}
                  hint={
                    scanHistoryReason(data.coverage.scan_history_reason) ??
                    "A discovery sweep covers an asset for inventory and says nothing about its vulnerabilities; only a run whose manifest shows a vulnerability stage that actually ran counts here"
                  }
                  decorationColor={data.coverage.vuln_scanned_share === null ? "slate" : "sky"}
                />
                <KpiCard
                  label={t("adoption.rangesReached")}
                  value={share(data.coverage.scope_covered_share)}
                  hint={
                    scopeReason(data.coverage.scope_unbounded_reason) ??
                    `${data.coverage.scope_covered_entries} of ${data.coverage.measurable_entries} approved ranges contain an asset a scan reached in the last ${data.coverage.coverage_days} days`
                  }
                  decorationColor={data.coverage.scope_covered_share === null ? "slate" : "emerald"}
                />
                <KpiCard
                  label={t("adoption.approvedEntries")}
                  value={data.coverage.approved_entries}
                  hint={`Allow rows in this tenant's scan scope${
                    data.coverage.denied_entries > 0
                      ? `, beside ${data.coverage.denied_entries} deny rows that are not counted`
                      : ""
                  }. The denominator comes from the approval, not from what was discovered — which is how a subnet nobody ever pointed the scanner at shows up`}
                  decorationColor="slate"
                />
              </div>
              {data.coverage.scope_uncovered_entries.length > 0 ? (
                <p className="mt-3 max-w-3xl text-xs text-muted-foreground">
                  Approved and never reached:{" "}
                  {data.coverage.scope_uncovered_entries.map((entry) => (
                    <span key={entry} className="mr-2 font-mono text-foreground">
                      {entry}
                    </span>
                  ))}
                </p>
              ) : null}
              {data.coverage.unmeasurable_entries.length > 0 ? (
                <p className="mt-2 max-w-3xl text-xs text-muted-foreground">
                  Not measurable, and left out of the share rather than counted as missed:{" "}
                  {data.coverage.unmeasurable_entries.map((entry) => (
                    <span key={entry} className="mr-2 font-mono text-foreground">
                      {entry}
                    </span>
                  ))}
                  — a wildcard or a domain suffix says nothing about which addresses are behind it.
                </p>
              ) : null}
              <p className="mt-3 max-w-3xl text-xs text-muted-foreground">
                Read from a column only the scan-ingest path writes, never from{" "}
                <span className="font-mono">last_seen</span>, which an endpoint agent checking in
                also moves. There is no backfill, so an installation that has not scanned since
                upgrading reads <span className="font-mono">n/a</span> — no coverage data, which
                is not the same as no coverage. Scope is counted in approved ranges rather than in
                addresses: a fully scanned /22 with thirty live hosts is 100% of one approval and
                2.9% of an address space, and only the first is about this estate.
              </p>
            </section>
          ) : null}

          <section>
            <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
              Estate
            </h2>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <KpiCard
                label={t("adoption.assetsWithOwner")}
                value={share(data.assets.with_owner_share)}
                hint={t("hint.unownedAssets", { unowned: data.assets.unowned, active: data.assets.active })}
                href="/assets"
                decorationColor={data.assets.unowned > 0 ? "amber" : "emerald"}
              />
              <KpiCard
                label={t("adoption.assetsWithContext")}
                value={share(data.assets.with_context_share)}
                hint={t("hint.contextSet")}
                decorationColor="sky"
              />
              <KpiCard
                label={`Scanned in ${data.assets.coverage_days} days`}
                value={share(data.assets.scanned_recently_share)}
                hint={t("hint.coverageShare")}
                decorationColor="blue"
              />
              <KpiCard
                label={t("adoption.networkAndAgent")}
                value={share(data.assets.dual_source_share)}
                hint={t("hint.dualSource")}
                href="/endpoints"
                decorationColor="sky"
              />
            </div>
          </section>

          <div className="grid gap-4 lg:grid-cols-3">
            <section className="rounded-xl border border-border bg-card p-5">
              <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                {t("prose.closedAndVerifiedPerAnalyst")}
              </h2>
              <Analysts rows={data.analysts} />
              <p className="mt-3 text-xs text-muted-foreground">
                {t("prose.theQuarterlyControlQuestionDid")}
              </p>
            </section>

            <section className="rounded-xl border border-border bg-card p-5">
              <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                {t("prose.medianTimeToFixBy")}
              </h2>
              <ul>
                {Object.entries(data.findings.mttr_hours_by_severity).map(([severity, value]) => (
                  <SeverityRow key={severity} label={severity} value={value} />
                ))}
              </ul>
              <p className="mt-3 text-xs text-muted-foreground">
                Reopened after closure: {share(data.findings.reopened_share)} of all tracked
                findings. Open findings per asset: {data.findings.open_per_asset ?? "n/a"}.
              </p>
            </section>

            <section className="space-y-4">
              <div className="rounded-xl border border-border bg-card p-5">
                <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  {t("prose.timeToFirstValue")}
                </h2>
                <dl className="space-y-1.5 text-sm">
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">{t("ui.tenantCreated")}</dt>
                    <dd className="font-mono text-foreground">
                      {data.onboarding.tenant_created_at?.slice(0, 10) ?? "n/a"}
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">{t("ui.toFirstSuccessfulScan")}</dt>
                    <dd className="font-mono text-foreground">
                      {hours(data.onboarding.hours_to_first_scan)}
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">{t("ui.toFirstTrackedFinding")}</dt>
                    <dd className="font-mono text-foreground">
                      {hours(data.onboarding.hours_to_first_finding)}
                    </dd>
                  </div>
                </dl>
              </div>
              <div className="rounded-xl border border-border bg-card p-5">
                <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  {t("prose.enrichmentOverlays")}
                </h2>
                <ul className="space-y-1.5 text-sm">
                  {data.enrichment.map((dataset) => (
                    <li key={dataset.name} className="flex items-center justify-between">
                      <span className="font-mono text-foreground">{dataset.name}</span>
                      {!dataset.present ? (
                        <Badge variant="outline" className="border-slate-500/30 text-muted-foreground">
                          missing
                        </Badge>
                      ) : dataset.stale ? (
                        <Badge variant="outline" className="border-amber-500/30 text-amber-600 dark:text-amber-400">
                          {dataset.age_days} d, stale
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="border-emerald-500/30 text-emerald-600 dark:text-emerald-400">
                          {dataset.age_days} d
                        </Badge>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            </section>
          </div>
        </>
      )}
    </div>
  );
}
