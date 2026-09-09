import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * One header for every page: icon tile, title, one-line purpose, and the
 * page's primary actions on the right. Keeps the eleven hand-rolled headers
 * from drifting apart and gives a reader the same place to look for "what is
 * this screen for" on each one.
 */
export function PageHeader({
  icon: Icon,
  title,
  subtitle,
  badge,
  actions,
  tone = "sky",
  className,
  children,
}: {
  icon?: LucideIcon;
  title: ReactNode;
  subtitle?: ReactNode;
  /** Small pill next to the title (e.g. "External", "Admin"). */
  badge?: ReactNode;
  actions?: ReactNode;
  tone?: "sky" | "violet" | "amber" | "emerald" | "rose" | "slate";
  className?: string;
  /** Optional second row — tabs, filters, banners. */
  children?: ReactNode;
}) {
  const tile: Record<NonNullable<typeof tone>, string> = {
    sky: "bg-sky-500/10 text-sky-600 border-sky-500/20 dark:text-sky-400",
    violet: "bg-violet-500/10 text-violet-600 border-violet-500/20 dark:text-violet-400",
    amber: "bg-amber-500/10 text-amber-600 border-amber-500/20 dark:text-amber-400",
    emerald: "bg-emerald-500/10 text-emerald-600 border-emerald-500/20 dark:text-emerald-400",
    rose: "bg-rose-500/10 text-rose-600 border-rose-500/20 dark:text-rose-400",
    slate: "bg-muted text-muted-foreground border-border",
  };
  return (
    <header className={cn("space-y-4 border-b border-border/80 pb-4", className)}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 items-start gap-3">
          {Icon ? (
            <div
              className={cn(
                "mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border shadow-sm",
                tile[tone],
              )}
            >
              <Icon className="h-5 w-5" />
            </div>
          ) : null}
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-2xl font-extrabold tracking-tight text-foreground">{title}</h1>
              {badge}
            </div>
            {subtitle ? (
              <p className="mt-1 max-w-3xl text-xs text-muted-foreground">{subtitle}</p>
            ) : null}
          </div>
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {children}
    </header>
  );
}
