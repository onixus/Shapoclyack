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

  // A word, not a count. "requires a check" in a slot sized for "32" wraps to
  // two or three lines and towers over its neighbours, which is what made a
  // row of these cards look like six different components. Long text steps
  // down a size or two instead; the numbers keep the size they had.
  const text = typeof value === "number" ? value.toLocaleString() : String(value);
  const valueSize =
    typeof value === "number" || text.length <= 6
      ? "text-3xl"
      : text.length <= 14
        ? "text-2xl"
        : "text-xl";

  const card = (
    <div
      className={cn(
        // h-full, and a column that pushes the hint to the bottom: a grid
        // stretches its items, but the card inside the Link did not fill
        // them, so every card was as tall as its own text and the row looked
        // ragged. min-h keeps a card with no hint from collapsing next to one
        // that has two lines of it.
        "relative flex h-full min-h-[7.5rem] flex-col overflow-hidden rounded-xl border border-border bg-card p-5 text-card-foreground shadow-sm transition-all duration-200 hover:border-border/80 hover:shadow-md",
        href && "cursor-pointer",
      )}
    >
      <div className={cn("absolute top-0 left-0 right-0 h-1 bg-gradient-to-r", gradient)} />
      <p className="text-xs font-bold uppercase tracking-wider text-muted-foreground">{label}</p>
      <p className={cn("mt-2 font-extrabold tracking-tight text-foreground", valueSize)}>{text}</p>
      {hint ? (
        <p className="mt-auto pt-1.5 text-xs font-medium text-muted-foreground">{hint}</p>
      ) : null}
    </div>
  );

  if (href) {
    return (
      <Link
        href={href}
        className="block h-full rounded-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
      >
        {card}
      </Link>
    );
  }
  return card;
}
