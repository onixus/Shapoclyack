import { describe, expect, it } from "vitest";
import type { AssetImportReport, AssetImportRow } from "@/lib/api";
import {
  decodeImportFile,
  importFormatFor,
  importWouldChange,
  previewRows,
} from "@/lib/asset-import";

/** "Бухгалтерия" as Excel in a Russian locale saves it: one byte a letter. */
const CP1251_ACCOUNTING = new Uint8Array([
  0xc1, 0xf3, 0xf5, 0xe3, 0xe0, 0xeb, 0xf2, 0xe5, 0xf0, 0xe8, 0xff,
]);

function row(number: number, status: AssetImportRow["status"]): AssetImportRow {
  return {
    row: number,
    status,
    key: `10.0.0.${number}`,
    code: null,
    message: null,
    asset_id: null,
    changes: {},
    identifiers_added: [],
    conflicting_fields: [],
  };
}

function report(rows: AssetImportRow[]): AssetImportReport {
  const counts = { create: 0, update: 0, unchanged: 0, conflict: 0, invalid: 0 };
  for (const item of rows) counts[item.status] += 1;
  return {
    dry_run: true,
    format: "csv",
    sha256: "x",
    context_source: "cmdb",
    overwrite_operator_edits: false,
    link_new_identifiers: false,
    total: rows.length,
    counts,
    codes: {},
    ignored_columns: [],
    rows,
    replayed: false,
  };
}

describe("decodeImportFile", () => {
  it("reads UTF-8 and drops the BOM Excel writes in front of it", () => {
    const bytes = new TextEncoder().encode("﻿ip,team\n10.0.0.1,Бухгалтерия\n");
    const decoded = decodeImportFile(bytes);
    expect(decoded.encoding).toBe("utf-8");
    expect(decoded.text).toBe("ip,team\n10.0.0.1,Бухгалтерия\n");
  });

  it("falls back to Windows-1251 instead of producing replacement characters", () => {
    const decoded = decodeImportFile(CP1251_ACCOUNTING);
    expect(decoded.encoding).toBe("windows-1251");
    expect(decoded.text).toBe("Бухгалтерия");
    expect(decoded.text).not.toContain("�");
  });
});

describe("importFormatFor", () => {
  it("is json only for a .json file", () => {
    expect(importFormatFor("cmdb-export.JSON")).toBe("json");
    expect(importFormatFor("cmdb-export.csv")).toBe("csv");
    expect(importFormatFor("hosts.txt")).toBe("csv");
  });
});

describe("previewRows", () => {
  it("lists conflicts and invalid rows before the rows that change nothing", () => {
    const sorted = previewRows(
      report([row(1, "unchanged"), row(2, "create"), row(3, "invalid"), row(4, "conflict")]),
    );
    expect(sorted.map((item) => item.row)).toEqual([4, 3, 2, 1]);
  });

  it("offers no apply for a file that would change nothing", () => {
    expect(importWouldChange(report([row(1, "unchanged"), row(2, "conflict")]))).toBe(false);
    expect(importWouldChange(report([row(1, "update")]))).toBe(true);
  });
});
