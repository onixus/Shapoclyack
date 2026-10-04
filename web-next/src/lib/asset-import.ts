import type { AssetImportBody, AssetImportReport, AssetImportRow } from "@/lib/api";

/**
 * Reading a CMDB/AD export in the browser before it goes to
 * `POST /api/assets/import` (#350).
 *
 * The API takes the file's *text*, so the charset is decided here. A CMDB
 * export is UTF-8 when it comes from an integration and Windows-1251 when
 * somebody saved it from Excel in a Russian locale, and the two cannot be told
 * apart by the extension. So: strict UTF-8 first — it rejects any byte
 * sequence that is not valid UTF-8, which a 1251 file with Cyrillic in it never
 * is — and 1251 when that fails. Decoding 1251 bytes as lenient UTF-8 would
 * hand the API U+FFFD for every Cyrillic letter, which it refuses outright
 * rather than storing "Ð˜Ð²Ð°Ð½Ð¾Ð²" as an owner.
 */
export function decodeImportFile(bytes: ArrayBuffer | Uint8Array): {
  text: string;
  encoding: "utf-8" | "windows-1251";
} {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  try {
    // `ignoreBOM: false` (the default) drops a UTF-8 BOM; the API strips one
    // too, so either side is enough.
    return { text: new TextDecoder("utf-8", { fatal: true }).decode(view), encoding: "utf-8" };
  } catch {
    return { text: new TextDecoder("windows-1251").decode(view), encoding: "windows-1251" };
  }
}

/** `json` for a `.json` file, `csv` for anything else (`.csv`, `.txt`, none). */
export function importFormatFor(fileName: string): AssetImportBody["format"] {
  return fileName.toLowerCase().endsWith(".json") ? "json" : "csv";
}

/** The order the preview lists rows in: what needs the operator's attention
 * first, what will change next, and the rows that change nothing last. */
const STATUS_ORDER: Record<AssetImportRow["status"], number> = {
  conflict: 0,
  invalid: 1,
  create: 2,
  update: 3,
  unchanged: 4,
};

export function previewRows(report: AssetImportReport): AssetImportRow[] {
  return [...report.rows].sort(
    (left, right) => STATUS_ORDER[left.status] - STATUS_ORDER[right.status] || left.row - right.row,
  );
}

/** Whether applying this preview would change anything at all. */
export function importWouldChange(report: AssetImportReport): boolean {
  return report.counts.create + report.counts.update > 0;
}
