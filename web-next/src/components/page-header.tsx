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
    sky: "bg-accent-subtle text-primary border-primary",
    violet: "bg-info-subtle text-info border-info/20",
    amber: "bg-warning-subtle text-warning border-warning/20",
    emerald: "bg-success-subtle text-success border-success/20",
    rose: "bg-danger-subtle text-danger border-danger/20",
    slate: "bg-muted text-muted-foreground border-border",
  };
  return (
    <header className={cn("space-y-4 border-b border-border/80 pb-4", className)}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 items-start gap-3">
          {Icon ? (
            <div
              className={cn(
                "mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border",
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
