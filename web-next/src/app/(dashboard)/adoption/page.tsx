"use client";

import { useState } from "react";
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
import { hours, scopeReason, share } from "@/lib/adoption-format";

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
  if (rows.length === 0) {
    return <p className="text-sm text-muted-foreground">{caption}</p>;
  }
  return (
    <table className="w-full text-sm">
      <thead className="text-left text-xs uppercase tracking-wider text-muted-foreground">
        <tr>
          <th className="py-1.5 font-semibold">Source</th>
          <th className="py-1.5 text-right font-semibold">Closed</th>
          <th className="py-1.5 text-right font-semibold">False</th>
          <th className="py-1.5 text-right font-semibold">Rate</th>
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
  if (rows.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No findings were closed in this window, so there is nobody to attribute a closure to.
      </p>
    );
  }
  return (
    <table className="w-full text-sm">
      <thead className="text-left text-xs uppercase tracking-wider text-muted-foreground">
        <tr>
          <th className="py-1.5 font-semibold">Analyst</th>
          <th className="py-1.5 text-right font-semibold">Closed</th>
          <th className="py-1.5 text-right font-semibold">Verified by scan</th>
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
  const [windowDays, setWindowDays] = useState<number>(90);
  const { data, isLoading, error } = useAdoption(windowDays);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">Adoption</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Whether the platform is producing outcomes rather than data: what got fixed, how
            fast, how much of it a scan confirmed, and how much of the estate has an owner. All of
            it is computed here, from this tenant&apos;s own tables; nothing is sent anywhere.
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          Window
          <Select value={String(windowDays)} onValueChange={(value) => setWindowDays(Number(value))}>
            <SelectTrigger className="w-28" aria-label="Window in days">
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
        <p className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-400">
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
                label="Closed"
                value={data.findings.closed_in_window}
                hint={`${data.findings.open} still open (${data.findings.accepted_open} risk-accepted). Remediation only — ${data.findings.false_positive_in_window} closed as noise are counted under Noise, not here`}
                href="/vulnerabilities"
                decorationColor="blue"
              />
              <KpiCard
                label="Confirmed by a scan"
                value={share(data.findings.machine_verified_share)}
                hint={`${data.findings.machine_verified_closed} of ${data.findings.closed_in_window} closures were verified mechanically`}
                decorationColor={
                  data.findings.machine_verified_share === null
                    ? "slate"
                    : data.findings.machine_verified_share >= 50
                      ? "emerald"
                      : "amber"
                }
              />
              <KpiCard
                label="Closed within SLA"
                value={share(data.findings.closed_within_sla_share)}
                hint="Of closures that had a deadline"
                decorationColor="emerald"
              />
              <KpiCard
                label="Median time to fix"
                value={hours(data.findings.mttr_hours)}
                hint="From SLA start to closure"
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
                  label="Closed as noise"
                  value={data.false_positives.in_window}
                  hint={`Of everything closed in the window, ${share(
                    data.false_positives.share_of_closures,
                  )} was never a real finding`}
                  decorationColor="amber"
                />
                <KpiCard
                  label="Suppressions in force"
                  value={data.false_positives.suppressions_active}
                  hint={`${data.false_positives.suppressions_lapsed} have expired and are waiting for a second look`}
                  decorationColor={
                    data.false_positives.suppressions_lapsed > 0 ? "amber" : "slate"
                  }
                />
                <KpiCard
                  label="Broken by evidence"
                  value={data.false_positives.overridden_in_window}
                  hint="Verdicts the scanner overrode because the assessment got worse — the number that says whether one was hiding something"
                  decorationColor={
                    data.false_positives.overridden_in_window > 0 ? "rose" : "slate"
                  }
                />
                <KpiCard
                  label="Median time to a verdict"
                  value={hours(data.false_positives.median_hours_to_verdict)}
                  hint="How long noise sat in the queue before someone ruled on it. Triage speed, not fix speed — it is deliberately not part of MTTR"
                  decorationColor="sky"
                />
              </div>
              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <div className="rounded-xl border border-border bg-card p-5">
                  <h3 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                    Noisiest detectors
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
                    The network scanner against the endpoint software matcher. The two are wrong
                    for unrelated reasons and are tuned in unrelated places, so the quiet one is
                    listed as well — it is what makes the other number mean something.
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
                  hint={`${data.coverage.assets_with_scan_history} active assets have ever been reached by a scan since the column existed`}
                  decorationColor={data.coverage.scanned_share === null ? "slate" : "blue"}
                />
                <KpiCard
                  label="Assessed for vulnerabilities"
                  value={share(data.coverage.vuln_scanned_share)}
                  hint="A discovery sweep covers an asset for inventory and says nothing about its vulnerabilities; only a run that produced findings counts here"
                  decorationColor={data.coverage.vuln_scanned_share === null ? "slate" : "sky"}
                />
                <KpiCard
                  label="Approved scope covered"
                  value={share(data.coverage.scope_covered_share)}
                  hint={
                    scopeReason(data.coverage.scope_unbounded_reason) ??
                    `${data.coverage.assets_in_scope} known addresses inside ${data.coverage.approved_addresses} approved ones`
                  }
                  decorationColor={data.coverage.scope_covered_share === null ? "slate" : "emerald"}
                />
                <KpiCard
                  label="Approved entries"
                  value={data.coverage.approved_entries}
                  hint="Rows in this tenant's scan scope. The denominator comes from the approval, not from what was discovered — which is how a subnet nobody ever pointed the scanner at shows up"
                  decorationColor="slate"
                />
              </div>
              <p className="mt-3 max-w-3xl text-xs text-muted-foreground">
                Read from a column only the scan-ingest path writes, never from{" "}
                <span className="font-mono">last_seen</span>, which an endpoint agent checking in
                also moves. There is no backfill, so an installation that has not scanned since
                upgrading reads <span className="font-mono">n/a</span> — no coverage data, which
                is not the same as no coverage.
              </p>
            </section>
          ) : null}

          <section>
            <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
              Estate
            </h2>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <KpiCard
                label="Assets with an owner"
                value={share(data.assets.with_owner_share)}
                hint={`${data.assets.unowned} of ${data.assets.active} active assets have nobody to hand a finding to`}
                href="/assets"
                decorationColor={data.assets.unowned > 0 ? "amber" : "emerald"}
              />
              <KpiCard
                label="Assets with business context"
                value={share(data.assets.with_context_share)}
                hint="Service, environment or classification set"
                decorationColor="sky"
              />
              <KpiCard
                label={`Scanned in ${data.assets.coverage_days} days`}
                value={share(data.assets.scanned_recently_share)}
                hint="Coverage: share of active assets seen by a recent run"
                decorationColor="blue"
              />
              <KpiCard
                label="Network + agent"
                value={share(data.assets.dual_source_share)}
                hint="Assets also reporting an endpoint inventory"
                href="/endpoints"
                decorationColor="sky"
              />
            </div>
          </section>

          <div className="grid gap-4 lg:grid-cols-3">
            <section className="rounded-xl border border-border bg-card p-5">
              <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                Closed and verified, per analyst
              </h2>
              <Analysts rows={data.analysts} />
              <p className="mt-3 text-xs text-muted-foreground">
                The quarterly control question: did this go up? If it did not, the new
                functionality produced data rather than outcomes.
              </p>
            </section>

            <section className="rounded-xl border border-border bg-card p-5">
              <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                Median time to fix, by severity
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
                  Time to first value
                </h2>
                <dl className="space-y-1.5 text-sm">
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">Tenant created</dt>
                    <dd className="font-mono text-foreground">
                      {data.onboarding.tenant_created_at?.slice(0, 10) ?? "n/a"}
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">To first successful scan</dt>
                    <dd className="font-mono text-foreground">
                      {hours(data.onboarding.hours_to_first_scan)}
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">To first tracked finding</dt>
                    <dd className="font-mono text-foreground">
                      {hours(data.onboarding.hours_to_first_finding)}
                    </dd>
                  </div>
                </dl>
              </div>
              <div className="rounded-xl border border-border bg-card p-5">
                <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  Enrichment overlays
                </h2>
                <ul className="space-y-1.5 text-sm">
                  {data.enrichment.map((dataset) => (
                    <li key={dataset.name} className="flex items-center justify-between">
                      <span className="font-mono text-foreground">{dataset.name}</span>
                      {!dataset.present ? (
                        <Badge variant="outline" className="border-slate-500/30 text-slate-400">
                          missing
                        </Badge>
                      ) : dataset.stale ? (
                        <Badge variant="outline" className="border-amber-500/30 text-amber-400">
                          {dataset.age_days} d, stale
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="border-emerald-500/30 text-emerald-400">
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
