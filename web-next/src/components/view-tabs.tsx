"use client";

import Link from "next/link";
import { useT } from "@/lib/i18n";
import type { MsgKey } from "@/lib/i18n/messages";
import { cn } from "@/lib/utils";

type Tab = { id: string; href: string; labelKey: MsgKey };

/**
 * Sibling views of one question. The menu keeps the question; these are the
 * old pages, still at their own addresses so a bookmark does not move.
 */
function ViewTabs({ tabs, current }: { tabs: readonly Tab[]; current: string }) {
  const t = useT();
  return (
    <nav aria-label={t("viewTabs.label")} className="mt-3 flex flex-wrap gap-1">
      {tabs.map((tab) => {
        const active = tab.id === current;
        return (
          <Link
            key={tab.id}
            href={tab.href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "rounded-md px-3 py-1.5 text-sm font-medium",
              active
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:bg-muted hover:text-foreground",
            )}
          >
            {t(tab.labelKey)}
          </Link>
        );
      })}
    </nav>
  );
}

const FINDING_TABS: readonly Tab[] = [
  { id: "list", href: "/vulnerabilities", labelKey: "view.findings.list" },
  { id: "board", href: "/remediation", labelKey: "view.findings.board" },
  { id: "campaigns", href: "/campaigns", labelKey: "view.findings.campaigns" },
  { id: "kev", href: "/threats", labelKey: "view.findings.kev" },
];

export function FindingViews({ current }: { current: "list" | "board" | "campaigns" | "kev" }) {
  return <ViewTabs tabs={FINDING_TABS} current={current} />;
}

const ASSET_TABS: readonly Tab[] = [
  { id: "list", href: "/assets", labelKey: "view.assets.list" },
  { id: "declared", href: "/exposure", labelKey: "view.assets.declared" },
];

export function AssetViews({ current }: { current: "list" | "declared" }) {
  return <ViewTabs tabs={ASSET_TABS} current={current} />;
}

/** Graph, profile and map describe one run. No id means the page opens the newest. */
export function runViewHref(runId: string, view: "result" | "graph" | "profile" | "map"): string {
  const id = runId.trim();
  const query = id ? `?runId=${encodeURIComponent(id)}` : "";
  if (view === "result") return id ? `/runs/view?runId=${encodeURIComponent(id)}` : "/runs";
  if (view === "graph") return `/attack-surface${query}`;
  if (view === "profile") return `/org-profile${query}`;
  return `/geo${query}`;
}

export function RunViews({
  runId,
  current,
}: {
  runId: string;
  current: "result" | "graph" | "profile" | "map";
}) {
  const tabs: readonly Tab[] = [
    { id: "result", href: runViewHref(runId, "result"), labelKey: "view.run.result" },
    { id: "graph", href: runViewHref(runId, "graph"), labelKey: "view.run.graph" },
    { id: "profile", href: runViewHref(runId, "profile"), labelKey: "view.run.profile" },
    { id: "map", href: runViewHref(runId, "map"), labelKey: "view.run.map" },
  ];
  return <ViewTabs tabs={tabs} current={current} />;
}
