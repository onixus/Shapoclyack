"use client";

import Link from "next/link";
import { Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowUpRight, Info } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ControlsMatrix } from "@/components/run/controls-matrix";
import { RelatedDomainsPanel } from "@/components/run/related-domains";
import { useRuns } from "@/hooks/use-runs";
import { pickLatestRun, runDetailHref } from "@/lib/run-data";
import { orgProfileHref } from "@/components/org-profile/posture-tile";
import { useT } from "@/lib/i18n";

/**
 * Organization profile (EPIC #182): owner, related domains and the control
 * matrix for one run.
 *
 * The org profile is a property of a run, not of a tenant — the attribution is
 * only as fresh as the scan that produced it — so the page picks the newest run
 * by default and lets the operator pin an older one via `?runId=`.
 */
export default function OrgProfilePage() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center py-16 gap-2 text-slate-400">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
          <span className="text-sm">Loading organization profile…</span>
        </div>
      }
    >
      <OrgProfileInner />
    </Suspense>
  );
}

function OrgProfileInner() {
  const t = useT();
  const router = useRouter();
  const searchParams = useSearchParams();
  const pinnedRunId = (searchParams.get("runId") || "").trim();
  const { data, isLoading } = useRuns();
  const runs = data?.items ?? [];
  const latest = pickLatestRun(runs);
  const runId = pinnedRunId || latest?.run_id || "";

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">
            {t("page.orgProfile.title")}
          </h1>
          <p className="mt-1 text-xs text-slate-400">{t("page.orgProfile.subtitle")}</p>
        </div>

        {runs.length > 0 ? (
          <div className="flex items-end gap-3">
            <label className="text-xs text-slate-400">
              <span className="mb-1 block font-semibold uppercase tracking-wider">
                {t("page.orgProfile.runPicker")}
              </span>
              <select
                className="rounded-md border border-slate-800 bg-slate-900 px-2 py-1.5 font-mono text-xs text-slate-200"
                value={runId}
                // The run stays in the URL, so the view is shareable and
                // survives a reload.
                onChange={(event) => router.push(orgProfileHref(event.target.value))}
              >
                {runs.map((run) => (
                  <option key={run.run_id} value={run.run_id}>
                    {run.run_id}
                  </option>
                ))}
              </select>
            </label>
            {runId ? (
              <Link
                href={runDetailHref(runId)}
                className="inline-flex items-center gap-1 pb-2 font-mono text-xs text-sky-400 hover:underline"
              >
                open run
                <ArrowUpRight className="h-3 w-3" />
              </Link>
            ) : null}
          </div>
        ) : null}
      </div>

      {!isLoading && !runId ? (
        <Alert className="border-slate-800 bg-slate-900/60 text-slate-300">
          <AlertDescription>{t("page.orgProfile.noRuns")}</AlertDescription>
        </Alert>
      ) : null}

      {runId ? (
        <>
          <p className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            {t("page.orgProfile.disclaimer")}
          </p>
          <ControlsMatrix runId={runId} />
          <RelatedDomainsPanel runId={runId} />
        </>
      ) : null}
    </div>
  );
}
