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
 * covered, the other says there was nothing to be covered *of*. The reason is
 * the only thing that separates them for the reader. */
export function scopeReason(reason: string | null): string | null {
  switch (reason) {
    case "no_scope":
      return "Nothing has been approved for scanning yet.";
    case "no_measurable_scope":
      return "Every approval is a wildcard or a domain suffix, and neither is an address space that can be reached or missed.";
    case "no_scan_history":
    case "partial_scan_history":
      return scanHistoryReason(reason);
    default:
      return null;
  }
}

/** Why the two scan shares are withheld.
 *
 * Migration 0035 has no backfill, so the columns fill one run at a time after
 * an upgrade. A share taken before enough of them have is a statement about the
 * rollout, not about the estate — and "1%" reads exactly like scanning having
 * collapsed. */
export function scanHistoryReason(reason: string | null): string | null {
  switch (reason) {
    case "no_scan_history":
      return "No scan has been ingested since the coverage columns were added — no coverage data, which is not the same as no coverage.";
    case "partial_scan_history":
      return "Too few assets have any scan history yet for a share of the estate to mean anything; it would read as collapsed scanning rather than as an upgrade still filling in.";
    default:
      return null;
  }
}
