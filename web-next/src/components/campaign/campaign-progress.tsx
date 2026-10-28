"use client";

import { CAMPAIGN_CATEGORIES, type CampaignCategory, type CampaignProgress } from "@/lib/campaigns";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

/** One colour per category. They are deliberately not grouped into
 * "done / not done": the point of the view is that they are different claims. */
export const CATEGORY_COLOR: Record<CampaignCategory, string> = {
  open: "bg-muted-foreground",
  fixing: "bg-orange-500",
  awaiting_verification: "bg-violet-500",
  verified: "bg-emerald-500",
  accepted_risk: "bg-amber-500",
  false_positive: "bg-zinc-400 dark:bg-zinc-500",
  closed_unverified: "bg-yellow-400",
  unavailable: "bg-rose-500",
};

export function CategoryBadge({ category }: { category: CampaignCategory }) {
  const t = useT();
  return (
    <span
      className="inline-flex items-center gap-1.5 text-xs"
      title={t(`campaign.cat.hint.${category}` as never)}
    >
      <span className={cn("h-2 w-2 rounded-full", CATEGORY_COLOR[category])} aria-hidden />
      {t(`campaign.cat.${category}` as never)}
    </span>
  );
}

/** A stacked bar of the categories, with the numbers spelled out for anyone who
 * cannot tell the colours apart. */
export function ProgressBar({ progress }: { progress: CampaignProgress }) {
  const t = useT();
  const total = progress.total;
  const label = CAMPAIGN_CATEGORIES.map(
    (c) => `${t(`campaign.cat.${c}` as never)}: ${progress.categories[c]}`,
  ).join(", ");
  return (
    <div
      role="img"
      aria-label={`${total} — ${label}`}
      className="flex h-2 w-full min-w-24 overflow-hidden rounded-full bg-muted"
    >
      {total
        ? CAMPAIGN_CATEGORIES.map((c) =>
            progress.categories[c] ? (
              <span
                key={c}
                className={CATEGORY_COLOR[c]}
                style={{ width: `${(progress.categories[c] / total) * 100}%` }}
              />
            ) : null,
          )
        : null}
    </div>
  );
}

export function CategoryCards({
  progress,
  active,
  onSelect,
}: {
  progress: CampaignProgress;
  active: CampaignCategory | "";
  onSelect: (category: CampaignCategory | "") => void;
}) {
  const t = useT();
  return (
    <div className="space-y-3">
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        {CAMPAIGN_CATEGORIES.map((category) => (
          <button
            key={category}
            type="button"
            aria-pressed={active === category}
            onClick={() => onSelect(active === category ? "" : category)}
            className={cn(
              "rounded-md border border-border bg-card p-3 text-left transition-colors hover:bg-muted",
              active === category && "ring-2 ring-sky-500",
            )}
          >
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span className={cn("h-2 w-2 rounded-full", CATEGORY_COLOR[category])} aria-hidden />
              {t(`campaign.cat.${category}` as never)}
            </div>
            <p className="mt-1 text-2xl font-bold tabular-nums" data-testid={`cat-${category}`}>
              {progress.categories[category]}
            </p>
            <p className="text-xs text-muted-foreground">
              {t(`campaign.cat.hint.${category}` as never)}
            </p>
          </button>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        {t("campaign.progress.unresolved", { count: progress.unresolved })}
        {progress.recurred ? ` · ${t("campaign.progress.recurred", { count: progress.recurred })}` : ""}
        {progress.vanished ? ` · ${t("campaign.progress.vanished", { count: progress.vanished })}` : ""}
        {" · "}
        {t("campaign.progress.note")}
      </p>
    </div>
  );
}
