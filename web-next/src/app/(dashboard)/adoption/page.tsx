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
import type { AdoptionMetrics } from "@/lib/api";

const WINDOWS = [30, 90, 180, 365] as const;

/** A share renders as a percentage, and as "n/a" when the API had nothing to
 * divide by — 0% and 100% are both claims, and neither is true of an empty
 * denominator. */
export function share(value: number | null): string {
  return value === null ? "n/a" : `${value}%`;
}

export function hours(value: number | null): string {
  if (value === null) return "n/a";
  if (value < 48) return `${value} h`;
  return `${Math.round((value / 24) * 10) / 10} d`;
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
                hint={`${data.findings.open} still open (${data.findings.accepted_open} risk-accepted)`}
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
