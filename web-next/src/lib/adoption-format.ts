/** A share renders as a percentage, and as "n/a" when the API had nothing to
 * divide by — 0% and 100% are both claims, and neither is true of an empty
 * denominator. */
export function share(value: number | null): string {
  return value === null ? "n/a" : `${value}%`;
}

export function hours(value: number | null): string {
  if (value === null) return "n/a";
  if (value < 48) return `${value} h`;
  return `${Math.round((value / 24) * 10) / 10} d`;
}
