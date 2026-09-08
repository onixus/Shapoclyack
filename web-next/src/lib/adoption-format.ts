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

/** Why coverage has no share to report, in words rather than as a dash.
 *
 * A `null` share and a `0%` share look identical if the page prints "n/a" and
 * stops there, and they mean opposite things: one says the estate is not
 * covered, the other says the approval has no size to be covered *of*. The
 * reason is the only thing that separates them for the reader. */
export function scopeReason(reason: string | null): string | null {
  switch (reason) {
    case "wildcard":
      return "The approved scope is a wildcard, so there is no address space to be a share of.";
    case "domain":
      return "A domain approval says nothing about how many hosts are behind it.";
    case "no_scope":
      return "Nothing has been approved for scanning yet.";
    case "too_large":
      return "The approval is larger than a target list; a share of it would read as zero.";
    default:
      return null;
  }
}
