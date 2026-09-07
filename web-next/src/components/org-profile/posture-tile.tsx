"use client";

import { useQuery } from "@tanstack/react-query";
import { KpiCard } from "@/components/kpi-card";
import { fetchRunControls, type ControlStatus, type OrgProfileControlsSummary } from "@/lib/api";
import { useT } from "@/lib/i18n";

/** Link to the org-profile page for one run. */
export function orgProfileHref(runId: string): string {
  return `/org-profile?runId=${encodeURIComponent(runId)}`;
}

const VERDICT_COLOR: Record<string, string> = {
  ok: "emerald",
  weak: "amber",
  fail: "rose",
  error: "rose",
  not_checked: "slate",
};

/** Module invariant (EPIC #182): absence of data never reads as `ok`, so an
 * unreachable or unevaluated controls matrix falls back to `not_checked` — the
 * "requires a check" cell of the matrix — and never to a reassuring verdict. */
export function postureVerdict(
  data: OrgProfileControlsSummary | undefined,
): ControlStatus {
  return data?.overall_verdict ?? "not_checked";
}

/** Controls whose status is an actual failure, and the assessed total. */
export function postureCounts(data: OrgProfileControlsSummary | undefined): {
  failing: number;
  total: number;
  notChecked: number;
} {
  const controls = data?.controls ?? [];
  return {
    failing: controls.filter((c) => c.status === "fail" || c.status === "error").length,
    total: controls.length,
    notChecked: controls.filter((c) => c.status === "not_checked").length,
  };
}

/**
 * Dashboard tile with the organization-wide control verdict of the newest run.
 *
 * Shares the `run-controls` query key with the run-level matrix, so opening the
 * run afterwards reuses the cached response instead of refetching it.
 */
export function OrgPostureTile({ runId }: { runId: string }) {
  const t = useT();
  const { data, isLoading } = useQuery<OrgProfileControlsSummary>({
    queryKey: ["run-controls", runId],
    queryFn: () => fetchRunControls(runId),
    enabled: Boolean(runId),
    // A run without the org_profile stage answers 404: that is a configuration
    // state, not an outage, so do not retry it.
    retry: false,
  });

  const verdict = postureVerdict(data);
  const { failing, total, notChecked } = postureCounts(data);
  const value = isLoading && runId ? "…" : t.label(verdict.replace("_", " "));
  const hint = !runId
    ? t("page.risk.kpiPostureNoRun")
    : total === 0
      ? t("page.risk.kpiPostureNoData")
      : t("page.risk.kpiPostureHint", { failing, total, notChecked });

  return (
    <KpiCard
      label={t("page.risk.kpiPosture")}
      value={value}
      hint={hint}
      href={runId ? orgProfileHref(runId) : "/org-profile"}
      decorationColor={VERDICT_COLOR[verdict] || "slate"}
    />
  );
}
