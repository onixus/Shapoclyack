"use client";

import Link from "next/link";
import { Activity, Server } from "lucide-react";
import { useAgentSummary } from "@/hooks/use-agents";
import { useJobCounts } from "@/hooks/use-jobs";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

/**
 * Header strip with the two numbers an operator glances at all day: jobs in
 * flight and agents online. Replaces the decorative "Live System" pill, which
 * was green whether or not anything was alive. Operators only: the job list
 * is operator-gated on the API (a viewer would get a 403 toast every poll),
 * and the agent count means little to someone who cannot launch anything.
 */
export function OpsPulse({ className }: { className?: string }) {
  const t = useT();
  const { canOperate } = useAuthStore();
  const jobs = useJobCounts(canOperate);
  const agents = useAgentSummary();
  if (!canOperate) return null;

  const { running, queued } = jobs;
  const online = agents.data?.online_agents ?? null;
  const total = agents.data?.total_agents ?? null;

  return (
    <div
      className={cn("hidden items-center gap-1.5 md:flex", className)}
      title={t("header.pulse.title")}
    >
      <Link
        href="/scans"
        className={cn(
          "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold transition-colors",
          running > 0
            ? "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300"
            : "border-border bg-muted text-muted-foreground hover:text-foreground",
        )}
        data-testid="pulse-jobs"
      >
        <Activity className={cn("h-3 w-3", running > 0 ? "animate-pulse" : "")} />
        {t("header.pulse.running", { count: jobs.isLoading ? "…" : running })}
        {queued > 0 ? (
          <span className="opacity-70">· {t("header.pulse.queued", { count: queued })}</span>
        ) : null}
      </Link>
      {total !== null && total > 0 ? (
        <Link
          href="/agents"
          className={cn(
            "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold transition-colors",
            online === 0
              ? "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300"
              : "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
          )}
          data-testid="pulse-agents"
        >
          <Server className="h-3 w-3" />
          {t("header.pulse.agents", { online: online ?? 0, total })}
        </Link>
      ) : null}
    </div>
  );
}
