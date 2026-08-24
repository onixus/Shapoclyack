import Link from "next/link";
import { cn } from "@/lib/utils";

export function KpiCard({
  label,
  value,
  hint,
  href,
  decorationColor = "sky",
}: {
  label: string;
  value: string | number;
  hint?: string;
  href?: string;
  decorationColor?: string;
}) {
  const gradientMap: Record<string, string> = {
    rose: "from-rose-500 to-amber-500",
    amber: "from-amber-500 to-orange-500",
    emerald: "from-emerald-500 to-teal-500",
    blue: "from-sky-500 to-indigo-500",
    sky: "from-sky-500 to-indigo-500",
    orange: "from-orange-500 to-amber-500",
    slate: "from-slate-400 to-slate-600",
  };

  const gradient = gradientMap[decorationColor] || gradientMap.sky;

  const card = (
    <div
      className={cn(
        "relative overflow-hidden rounded-xl border border-border bg-card text-card-foreground p-5 shadow-sm transition-all duration-200 hover:border-border/80 hover:shadow-md",
        href && "cursor-pointer",
      )}
    >
      <div className={cn("absolute top-0 left-0 right-0 h-1 bg-gradient-to-r", gradient)} />
      <p className="text-xs font-bold uppercase tracking-wider text-muted-foreground">{label}</p>
      <p className="mt-2 text-3xl font-extrabold tracking-tight text-foreground">
        {typeof value === "number" ? value.toLocaleString() : value}
      </p>
      {hint ? <p className="mt-1.5 text-xs text-muted-foreground font-medium">{hint}</p> : null}
    </div>
  );

  if (href) {
    return (
      <Link href={href} className="block rounded-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">
        {card}
      </Link>
    );
  }
  return card;
}
