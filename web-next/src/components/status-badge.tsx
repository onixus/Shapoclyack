import { Badge } from "@/components/ui/badge";
import type { StatusStyle } from "@/lib/config/statuses";
import { cn } from "@/lib/utils";

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
  const style = map[value] ?? fallback ?? { label: value, variant: "secondary" as const };
  const isRunning = value === "running" || value === "active" || showPulse;

  return (
    <Badge 
      variant={style.variant ?? "default"} 
      className={cn("inline-flex items-center gap-1.5 px-2.5 py-0.5 font-medium text-xs rounded-full border shadow-sm transition-colors", style.className)}
    >
      {isRunning && (
        <span className="relative flex h-1.5 w-1.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-current opacity-75" />
          <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-current" />
        </span>
      )}
      <span>{style.label}</span>
    </Badge>
  );
}

