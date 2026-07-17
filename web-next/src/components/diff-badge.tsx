import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

type DiffBadgeProps = {
  kind: "port" | "cve";
  label: string;
  className?: string;
};

export function DiffBadge({ kind, label, className }: DiffBadgeProps) {
  const isCve = kind === "cve";
  return (
    <Badge
      variant="outline"
      className={cn(
        "font-medium",
        isCve
          ? "border-red-200 bg-red-50 text-red-700"
          : "border-emerald-200 bg-emerald-50 text-emerald-700",
        className,
      )}
    >
      {label}
    </Badge>
  );
}
