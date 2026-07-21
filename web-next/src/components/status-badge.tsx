import { Badge } from "@/components/ui/badge";
import type { StatusStyle } from "@/lib/config/statuses";

export function StatusBadge({
  value,
  map,
  fallback,
}: {
  value: string;
  map: Record<string, StatusStyle>;
  fallback?: StatusStyle;
}) {
  const style = map[value] ?? fallback ?? { label: value, variant: "secondary" as const };
  return (
    <Badge variant={style.variant ?? "default"} className={style.className}>
      {style.label}
    </Badge>
  );
}
