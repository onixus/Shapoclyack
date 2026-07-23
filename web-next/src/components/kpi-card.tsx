import { Card, Metric, Text } from "@tremor/react";
import { cn } from "@/lib/utils";

export function KpiCard({
  label,
  value,
  hint,
  decorationColor = "sky",
}: {
  label: string;
  value: string | number;
  hint?: string;
  decorationColor?: string;
}) {
  const accentBorder: Record<string, string> = {
    blue: "border-sky-500/40 text-sky-400 shadow-sky-950/40",
    sky: "border-sky-400/40 text-sky-300 shadow-sky-950/40",
    amber: "border-amber-500/40 text-amber-400 shadow-amber-950/40",
    rose: "border-rose-500/40 text-rose-400 shadow-rose-950/40",
    orange: "border-orange-500/40 text-orange-400 shadow-orange-950/40",
    emerald: "border-emerald-500/40 text-emerald-400 shadow-emerald-950/40",
    slate: "border-slate-700 text-slate-300 shadow-slate-950/40",
  };

  const borderClass = accentBorder[decorationColor] || accentBorder.sky;

  return (
    <Card className={cn(
      "relative overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur transition-all duration-200 hover:border-slate-700 hover:bg-slate-900/90",
    )}>
      <div className={cn("absolute top-0 left-0 right-0 h-1 bg-gradient-to-r", 
        decorationColor === "rose" ? "from-rose-500 to-amber-500" :
        decorationColor === "amber" ? "from-amber-500 to-orange-500" :
        decorationColor === "emerald" ? "from-emerald-500 to-teal-500" :
        "from-sky-500 to-indigo-500"
      )} />
      <Text className="text-xs font-semibold uppercase tracking-wider text-slate-400">{label}</Text>
      <Metric className={cn("mt-2 text-3xl font-extrabold tracking-tight text-slate-100", borderClass.split(" ")[1])}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </Metric>
      {hint ? <Text className="mt-1.5 text-xs text-slate-400 font-medium">{hint}</Text> : null}
    </Card>
  );
}

