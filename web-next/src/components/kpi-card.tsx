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
  // APEX keeps colour for meaning: a tone that says "bad", "watch" or "fine"
  // tints the value; brand-ish tones (sky, blue, indigo, slate) stay neutral,
  // and so do a zero and the loading ellipsis — "0 failed deliveries" is not an alarm.
  const valueTone =
    value === 0 || value === "…"
      ? "text-foreground"
      : decorationColor === "rose"
      ? "text-danger"
      : decorationColor === "amber" || decorationColor === "orange"
        ? "text-warning"
        : decorationColor === "emerald"
          ? "text-success"
          : "text-foreground";

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
        "relative flex h-full min-h-[7.5rem] flex-col overflow-hidden rounded-xl border border-border bg-card p-5 text-card-foreground transition-colors duration-150 hover:border-border-strong",
        href && "cursor-pointer",
      )}
    >
      <p className="text-caption text-muted-foreground">{label}</p>
      <p className={cn("mt-2 font-semibold tabular-nums tracking-tight", valueTone, valueSize)}>{text}</p>
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
