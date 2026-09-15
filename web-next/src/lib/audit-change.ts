/** Summarising one audit event's before/after for a table cell.
 *
 * The audit page renders the whole document the API recorded. That is the
 * right thing to keep — it is the answer the page exists for, and it is
 * already redacted server-side — but `JSON.stringify({before, after})` in a
 * narrow column with `break-all` is that answer rendered unreadable: one row
 * grew to a quarter of the screen and squeezed every other column, the
 * timestamp included, into a wrapping sliver.
 *
 * So the cell shows what actually changed and keeps the document one click
 * away. This module is the "what actually changed" part, kept out of the page
 * so it can be tested without rendering one.
 */

/** One value, short enough to sit in a table cell.
 *
 * Nested structures are counted rather than spelled out: a cell is not where
 * anybody reads a list of forty scope entries, and the expander below it is.
 */
export function brief(value: unknown): string {
  if (value === null || value === undefined) return "∅";
  if (Array.isArray(value)) return `[${value.length}]`;
  if (typeof value === "object") return "{…}";
  const text = String(value);
  return text.length > 28 ? `${text.slice(0, 27)}…` : text;
}

export type ChangedField = { key: string; from: string; to: string };

/** The fields that differ between the two documents, sorted by name.
 *
 * Compared as JSON rather than with `===`: these are decoded documents, so two
 * equal arrays are two different objects and every list-valued field would
 * read as having changed on every event.
 */
export function changedFields(
  before: Record<string, unknown> | null,
  after: Record<string, unknown> | null,
): ChangedField[] {
  const keys = new Set([...Object.keys(before ?? {}), ...Object.keys(after ?? {})]);
  const rows: ChangedField[] = [];
  for (const key of Array.from(keys).sort()) {
    const from = before ? before[key] : undefined;
    const to = after ? after[key] : undefined;
    if (JSON.stringify(from) === JSON.stringify(to)) continue;
    rows.push({ key, from: brief(from), to: brief(to) });
  }
  return rows;
}

/** Whether this event created or removed the thing it is about, or neither.
 *
 * A creation has no `before` and a deletion no `after`; saying so is more use
 * than listing every field of the document as "changed".
 */
export function changeShape(
  before: Record<string, unknown> | null,
  after: Record<string, unknown> | null,
): "created" | "removed" | null {
  if (before === null && after !== null) return "created";
  if (after === null && before !== null) return "removed";
  return null;
}
