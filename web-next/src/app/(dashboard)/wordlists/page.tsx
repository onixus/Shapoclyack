"use client";

import { FormEvent, useRef, useState } from "react";
import { format } from "date-fns";
import { BookText, Trash2, Upload } from "lucide-react";
import { useT } from "@/lib/i18n";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import {
  useDeleteWordlist,
  useUploadWordlist,
  useWordlists,
} from "@/hooks/use-wordlists";
import { type WordlistInfo, type WordlistKind } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

export default function WordlistsPage() {
  const t = useT();
  const { canOperate } = useAuthStore();
  const { data, isLoading, error, isFetching } = useWordlists(canOperate);
  const upload = useUploadWordlist();
  const remove = useDeleteWordlist();

  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<WordlistKind>("subdomain");
  const [pendingDelete, setPendingDelete] = useState<WordlistInfo | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  if (!canOperate) {
    return (
      <div className="space-y-2 rounded-xl border border-border bg-card p-8 text-center">
        <h1 className="text-2xl font-bold tracking-tight text-foreground">{t("page.wordlists.title")}</h1>
        <p className="text-xs text-muted-foreground">
          {t("page.wordlists.denied")}
        </p>
      </div>
    );
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (!file) return;
    upload.mutate(
      { file, kind, name: name.trim() || undefined },
      {
        onSuccess: () => {
          setFile(null);
          setName("");
          if (fileInput.current) fileInput.current.value = "";
        },
      },
    );
  }

  const wordlists = data ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20 shadow-md">
            <BookText className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-foreground">{t("page.wordlists.title")}</h1>
            <p className="text-xs text-muted-foreground">
              {t("page.wordlists.subtitle")}
              {isFetching ? t("common.refreshing") : ""}
            </p>
          </div>
        </div>
      </div>

      <form
        onSubmit={onSubmit}
        className="space-y-5 rounded-xl border border-border bg-card p-6 shadow-xl backdrop-blur"
      >
        <div className="flex items-center justify-between border-b border-border pb-3">
          <h3 className="text-sm font-bold uppercase tracking-wider text-foreground">{t("ui.uploadWordlist")}</h3>
        </div>

        <div className="grid gap-5 md:grid-cols-3">
          <div className="grid gap-2">
            <Label htmlFor="wl-file" className="text-foreground font-semibold">
              {t("prose.wordlistFileOneEntryPer")}
            </Label>
            <Input
              id="wl-file"
              ref={fileInput}
              type="file"
              accept=".txt,text/plain"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="bg-muted border-border text-foreground file:mr-3 file:rounded file:border-0 file:bg-muted file:px-2 file:py-1 file:text-foreground"
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="wl-name" className="text-foreground font-semibold">
              {t("prose.nameOptionalDefaultsToFilename")}
            </Label>
            <Input
              id="wl-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="prod-subdomains"
              className="bg-muted border-border text-foreground"
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="wl-kind" className="text-foreground font-semibold">
              Kind
            </Label>
            <Select value={kind} onValueChange={(v) => setKind(v as WordlistKind)}>
              <SelectTrigger id="wl-kind" className="bg-muted border-border text-foreground">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-card border-border text-foreground">
                <SelectItem value="subdomain">subdomain (DNS brute force)</SelectItem>
                <SelectItem value="bucket">bucket (cloud storage names)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="flex items-center justify-between pt-3 border-t border-border">
          <p className="text-xs text-muted-foreground">
            Re-uploading under an existing name replaces it. Entries are lowercased, de-duplicated,
            and blank/comment lines are dropped.
          </p>
          <Button
            type="submit"
            disabled={!file || upload.isPending}
            className="gap-2 bg-sky-600 hover:bg-sky-500 text-foreground font-semibold"
          >
            <Upload className="h-3.5 w-3.5" />
            {upload.isPending ? "Uploading…" : "Upload Wordlist"}
          </Button>
        </div>
      </form>

      <div className="rounded-xl border border-border bg-card shadow-xl">
        {error ? (
          <p className="p-6 text-xs text-rose-600 dark:text-rose-400">{error.message}</p>
        ) : isLoading ? (
          <p className="p-6 text-xs text-muted-foreground">Loading wordlists…</p>
        ) : wordlists.length === 0 ? (
          <p className="p-6 text-xs text-muted-foreground">
            {t("prose.noWordlistsUploadedYetUpload")}
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="text-muted-foreground">{t("col.name")}</TableHead>
                <TableHead className="text-muted-foreground">{t("col.kind")}</TableHead>
                <TableHead className="text-muted-foreground text-right">{t("col.entries")}</TableHead>
                <TableHead className="text-muted-foreground">SHA-256</TableHead>
                <TableHead className="text-muted-foreground">{t("col.uploaded")}</TableHead>
                <TableHead className="text-muted-foreground" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {wordlists.map((wl) => (
                <TableRow key={wl.wordlist_id} className="border-border">
                  <TableCell className="font-semibold text-foreground">{wl.name}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className="border-border text-foreground">
                      {wl.kind}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right font-mono text-foreground">
                    {wl.line_count.toLocaleString()}
                  </TableCell>
                  <TableCell className="font-mono text-[11px] text-muted-foreground">
                    {wl.sha256.slice(0, 12)}…
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {wl.created_at ? format(new Date(wl.created_at), "yyyy-MM-dd HH:mm") : "—"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setPendingDelete(wl)}
                      className="text-rose-600 dark:text-rose-400 hover:bg-rose-500/10 hover:text-rose-600 dark:text-rose-300"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      <AlertDialog open={pendingDelete !== null} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <AlertDialogContent className="bg-card border-border text-foreground">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">
              Delete wordlist “{pendingDelete?.name}”?
            </AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground text-xs">
              {t("prose.scansAlreadyRunningAreUnaffected")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="border-border bg-muted text-foreground hover:bg-muted">
              {t("ui.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (pendingDelete) remove.mutate(pendingDelete.wordlist_id);
                setPendingDelete(null);
              }}
              className="bg-rose-600 text-foreground hover:bg-rose-500"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
