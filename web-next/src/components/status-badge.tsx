"use client";

import { AlertTriangle, CheckCircle2, CircleMinus, Info, XCircle, type LucideIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { StatusStyle, StatusTone } from "@/lib/config/statuses";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

// APEX: a status is an icon plus a word; colour only repeats the meaning, so
// the badge still reads in greyscale and for colour-blind operators.
const TONE_ICON: Partial<Record<StatusTone, LucideIcon>> = {
  success: CheckCircle2,
  warning: AlertTriangle,
  danger: XCircle,
  info: Info,
  muted: CircleMinus,
};

export function StatusBadge({
  value,
  map,
  fallback,
  showPulse = false,
}: {
  value: string;
  map: Record<string, StatusStyle>;
  fallback?: StatusStyle;
  showPulse?: boolean;
}) {
  const t = useT();
  const style: StatusStyle = map[value] ?? fallback ?? { label: value, variant: "secondary", tone: "muted" };
  const isRunning = value === "running" || value === "active" || showPulse;
  const Icon = style.tone ? TONE_ICON[style.tone] : undefined;

  return (
    <Badge
      // A coloured style brings its own plate; the outline variant adds no
      // fill or hover of its own that could repaint the status in the accent.
      variant={style.className ? "outline" : (style.variant ?? "default")}
      data-tone={style.tone}
      className={cn(
        "inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium transition-colors",
        style.className,
      )}
    >
      {isRunning ? (
        <span className="relative flex h-1.5 w-1.5" aria-hidden>
          <span className="absolute inline-flex h-full w-full rounded-full bg-current opacity-75 motion-safe:animate-ping" />
          <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-current" />
        </span>
      ) : Icon ? (
        <Icon className="h-3.5 w-3.5 shrink-0" strokeWidth={1.75} aria-hidden />
      ) : null}
      <span className={cn(style.tone === "severity" && "capitalize")}>{t.label(style.label)}</span>
    </Badge>
  );
}
