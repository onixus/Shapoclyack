"use client";

import { useState } from "react";
import { Upload } from "lucide-react";
import { useT, type MsgKey } from "@/lib/i18n";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAssetImportApply, useAssetImportPreview } from "@/hooks/use-assets";
import { useAuthStore } from "@/lib/auth-store";
import { can } from "@/lib/authz";
import {
  decodeImportFile,
  importFormatFor,
  importWouldChange,
  previewRows,
} from "@/lib/asset-import";
import type {
  AssetImportBody,
  AssetImportReport,
  AssetImportSource,
  AssetImportStatus,
} from "@/lib/api";

/**
 * Import a CMDB/AD export into the asset registry (#350): pick a file, see the
 * dry run row by row, then apply exactly that.
 *
 * The door is `asset.import` **in the active tenant** — the tenant admin's —
 * asked through `can(...)`, not the account's global role: an account that is
 * globally a viewer and `admin` in this tenant may import here, and a global
 * operator may not. The API enforces the same on the request.
 *
 * Apply is offered only after a preview of the same file and options, and is
 * disabled when the preview says nothing would change. The server re-plans on
 * apply, so a registry that moved in between is reported as it is then.
 */
const SOURCES: readonly AssetImportSource[] = ["cmdb", "ad", "other"];

/** Rows shown in the preview table; the counts above it cover all of them. */
const PREVIEW_LIMIT = 200;

const STATUS_CLASS: Record<AssetImportStatus, string> = {
  create: "text-emerald-600 dark:text-emerald-400",
  update: "text-sky-600 dark:text-sky-400",
  unchanged: "text-muted-foreground",
  conflict: "text-amber-600 dark:text-amber-400",
  invalid: "text-red-600 dark:text-red-400",
};

const STATUS_LABEL: Record<AssetImportStatus, MsgKey> = {
  create: "assetImport.status.create",
  update: "assetImport.status.update",
  unchanged: "assetImport.status.unchanged",
  conflict: "assetImport.status.conflict",
  invalid: "assetImport.status.invalid",
};

const STATUSES = Object.keys(STATUS_LABEL) as AssetImportStatus[];

export function AssetImportButton() {
  const t = useT();
  const allowed = useAuthStore((state) => can(state.user, { permission: "asset.import" }));
  const [open, setOpen] = useState(false);
  if (!allowed) return null;
  return (
    <>
      <Button variant="outline" size="sm" className="h-8 gap-1.5 text-xs" onClick={() => setOpen(true)}>
        <Upload className="h-3.5 w-3.5" />
        {t("assetImport.button")}
      </Button>
      {open ? <AssetImportDialog open={open} onOpenChange={setOpen} /> : null}
    </>
  );
}

export function AssetImportDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const t = useT();
  const preview = useAssetImportPreview();
  const apply = useAssetImportApply();
  const [fileName, setFileName] = useState("");
  const [file, setFile] = useState<{ format: AssetImportBody["format"]; content: string } | null>(
    null,
  );
  const [encoding, setEncoding] = useState<string | null>(null);
  const [source, setSource] = useState<AssetImportSource>("cmdb");
  const [overwrite, setOverwrite] = useState(false);
  const [report, setReport] = useState<AssetImportReport | null>(null);
  const [applied, setApplied] = useState<AssetImportReport | null>(null);

  const body = (): Omit<AssetImportBody, "dry_run"> | null =>
    file
      ? {
          format: file.format,
          content: file.content,
          context_source: source,
          overwrite_operator_edits: overwrite,
        }
      : null;

  // Any change to what would be sent invalidates the preview: Apply must only
  // ever send the request the operator has just seen the answer to.
  const resetPreview = () => {
    setReport(null);
    setApplied(null);
    preview.reset();
  };

  const onFile = async (picked: File | undefined) => {
    resetPreview();
    if (!picked) {
      setFile(null);
      setFileName("");
      return;
    }
    const decoded = decodeImportFile(await picked.arrayBuffer());
    setFileName(picked.name);
    setEncoding(decoded.encoding);
    setFile({ format: importFormatFor(picked.name), content: decoded.text });
  };

  const runPreview = () => {
    const next = body();
    if (!next) return;
    preview.mutate(next, { onSuccess: (result) => setReport(result) });
  };

  const runApply = () => {
    const next = body();
    if (!next) return;
    apply.mutate(next, { onSuccess: (result) => setApplied(result) });
  };

  const shown = report ? previewRows(report).slice(0, PREVIEW_LIMIT) : [];
  const summary = applied ?? report;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl bg-card border-border text-foreground">
        <DialogHeader>
          <DialogTitle className="text-foreground">{t("assetImport.title")}</DialogTitle>
          <DialogDescription className="text-xs text-muted-foreground">
            {t("assetImport.description")}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="asset-import-file" className="text-xs text-foreground">
              {t("assetImport.file")}
            </Label>
            <input
              id="asset-import-file"
              type="file"
              accept=".csv,.json,.txt,text/csv,application/json"
              className="block w-full text-xs text-foreground file:mr-3 file:rounded file:border file:border-border file:bg-muted file:px-2 file:py-1 file:text-xs"
              onChange={(event) => void onFile(event.target.files?.[0])}
            />
            {file ? (
              <p className="text-[11px] text-muted-foreground">
                {t("assetImport.fileInfo", {
                  name: fileName,
                  format: file.format.toUpperCase(),
                  encoding: encoding ?? "",
                })}
              </p>
            ) : null}
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <div className="space-y-1.5">
              <span className="text-xs text-foreground">{t("assetImport.source")}</span>
              <Select
                value={source}
                onValueChange={(value) => {
                  setSource(value as AssetImportSource);
                  resetPreview();
                }}
              >
                <SelectTrigger className="w-40" aria-label={t("assetImport.source")}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SOURCES.map((item) => (
                    <SelectItem key={item} value={item}>
                      {item}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <label className="flex items-center gap-2 pt-5 text-xs text-foreground">
              <Checkbox
                checked={overwrite}
                onCheckedChange={(value) => {
                  setOverwrite(value === true);
                  resetPreview();
                }}
              />
              {t("assetImport.overwrite")}
            </label>
          </div>

          {preview.error ? (
            <p className="text-xs text-red-600 dark:text-red-400">
              {(preview.error as Error).message}
            </p>
          ) : null}

          {summary ? (
            <div className="space-y-2" data-testid="asset-import-report">
              <p className="text-xs font-semibold text-foreground">
                {applied ? t("assetImport.appliedHeading") : t("assetImport.previewHeading")}
              </p>
              <div className="flex flex-wrap gap-3 text-xs">
                {STATUSES.map((status) => (
                  <span key={status} className={STATUS_CLASS[status]}>
                    {t(STATUS_LABEL[status])}: {summary.counts[status]}
                  </span>
                ))}
              </div>
              {summary.ignored_columns.length > 0 ? (
                <p className="text-[11px] text-muted-foreground">
                  {t("assetImport.ignored", { columns: summary.ignored_columns.join(", ") })}
                </p>
              ) : null}
            </div>
          ) : null}

          {report && !applied ? (
            <div className="max-h-72 overflow-auto rounded border border-border">
              <table className="w-full text-left text-[11px]">
                <thead className="sticky top-0 bg-muted text-muted-foreground">
                  <tr>
                    <th className="px-2 py-1">#</th>
                    <th className="px-2 py-1">{t("assetImport.col.key")}</th>
                    <th className="px-2 py-1">{t("assetImport.col.outcome")}</th>
                    <th className="px-2 py-1">{t("assetImport.col.detail")}</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((item) => (
                    <tr key={item.row} className="border-t border-border align-top">
                      <td className="px-2 py-1 tabular-nums">{item.row}</td>
                      <td className="px-2 py-1 font-mono">{item.key || "—"}</td>
                      <td className={`px-2 py-1 ${STATUS_CLASS[item.status]}`}>
                        {t(STATUS_LABEL[item.status])}
                      </td>
                      <td className="px-2 py-1 text-muted-foreground">
                        {item.message ??
                          Object.entries(item.changes)
                            .map(([name, change]) => `${name}: ${change.old ?? "∅"} → ${change.new ?? "∅"}`)
                            .join("; ")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {report.rows.length > shown.length ? (
                <p className="px-2 py-1 text-[11px] text-muted-foreground">
                  {t("assetImport.more", { count: report.rows.length - shown.length })}
                </p>
              ) : null}
            </div>
          ) : null}
        </div>

        <DialogFooter>
          <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
            {t("assetImport.close")}
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!file || preview.isPending}
            onClick={runPreview}
          >
            {t("assetImport.preview")}
          </Button>
          <Button
            size="sm"
            disabled={!report || !importWouldChange(report) || apply.isPending || Boolean(applied)}
            onClick={runApply}
          >
            {t("assetImport.apply")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
