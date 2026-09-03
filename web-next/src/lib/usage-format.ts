import type { UsageResource } from "@/lib/api";

/** An absent ceiling is unlimited, not a very large number — so there is no bar
 * to fill and no percentage to quote. Everything below keeps that distinction
 * instead of collapsing it into 0% or 100%, the same rule the adoption page
 * follows for an absent denominator. */
export const UNLIMITED = "Unlimited";
export const NOT_APPLICABLE = "n/a";

export function limitLabel(limit: number | null): string {
  return limit === null ? UNLIMITED : limit.toLocaleString();
}

/** `used_ratio` arrives as a fraction 0..1; render it as a percentage, or as
 * "n/a" when the quota is unlimited. */
export function ratioLabel(ratio: number | null): string {
  if (ratio === null) return NOT_APPLICABLE;
  return `${Math.round(ratio * 1000) / 10}%`;
}

/** How wide the filled part of a usage bar should be, or null when there is no
 * bar to draw. Clamped: an over-limit tenant fills the track, never overflows
 * it. */
export function barPercent(ratio: number | null): number | null {
  if (ratio === null) return null;
  return Math.min(100, Math.max(0, Math.round(ratio * 1000) / 10));
}

export type UsageTone = "ok" | "near" | "over";

/** Over the ceiling, or within the last fifth of it — the two states an
 * operator has to act on. Unlimited is always "ok". */
export function usageTone(resource: Pick<UsageResource, "over_limit" | "used_ratio">): UsageTone {
  if (resource.over_limit) return "over";
  if (resource.used_ratio !== null && resource.used_ratio >= 0.8) return "near";
  return "ok";
}

/** Sort key for the fleet table: the worst of the two resources, so whoever is
 * closest to a ceiling floats to the top. Unlimited sorts last (-1). */
export function pressure(row: { assets: UsageResource; scans: UsageResource }): number {
  const ratios = [row.assets, row.scans].map((r) =>
    r.over_limit ? Math.max(r.used_ratio ?? 1, 1) : (r.used_ratio ?? -1),
  );
  return Math.max(...ratios);
}

export function sortByPressure<T extends { assets: UsageResource; scans: UsageResource }>(
  rows: readonly T[],
): T[] {
  return [...rows].sort((a, b) => pressure(b) - pressure(a));
}

/** The billing period as a plain day range; the API sends naive ISO stamps. */
export function periodLabel(start: string, end: string): string {
  return `${start.slice(0, 10)} → ${end.slice(0, 10)}`;
}

/** "2026-09" → "Sep 2026", for the history chart's axis. */
export function monthLabel(month: string): string {
  const [year, index] = month.split("-");
  const names = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ];
  const name = names[Number(index) - 1];
  return name ? `${name} ${year}` : month;
}

/** An empty input means unlimited, which is how the API spells it too. So does
 * a zero, and so does anything that is not a positive number. */
export function parseQuotaInput(value: string): number | null {
  const trimmed = value.trim();
  if (trimmed === "") return null;
  const parsed = Number(trimmed);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return Math.floor(parsed);
}

/** The inverse: an unlimited ceiling shows as an empty box, not as "0". */
export function quotaInputValue(limit: number | null): string {
  return limit === null ? "" : String(limit);
}
