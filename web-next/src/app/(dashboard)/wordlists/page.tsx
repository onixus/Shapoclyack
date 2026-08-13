"use client";

import { FormEvent, useRef, useState } from "react";
import { format } from "date-fns";
import { BookText, Trash2, Upload } from "lucide-react";
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
      <div className="space-y-2 rounded-xl border border-slate-800 bg-slate-900/80 p-8 text-center">
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">Brute-force Wordlists</h1>
        <p className="text-xs text-slate-400">
          Operator or admin role privileges required to manage wordlists.
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
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-md">
            <BookText className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">Brute-force Wordlists</h1>
            <p className="text-xs text-slate-400">
              Upload dictionaries for subdomain and cloud-bucket brute force, then select one when
              launching a scan.
              {isFetching ? " · Refreshing…" : ""}
            </p>
          </div>
        </div>
      </div>

      <form
        onSubmit={onSubmit}
        className="space-y-5 rounded-xl border border-slate-800/80 bg-slate-900/80 p-6 shadow-xl backdrop-blur"
      >
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">Upload Wordlist</h3>
        </div>

        <div className="grid gap-5 md:grid-cols-3">
          <div className="grid gap-2">
            <Label htmlFor="wl-file" className="text-slate-300 font-semibold">
              Wordlist file (one entry per line)
            </Label>
            <Input
              id="wl-file"
              ref={fileInput}
              type="file"
              accept=".txt,text/plain"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="bg-slate-950 border-slate-800 text-slate-200 file:mr-3 file:rounded file:border-0 file:bg-slate-800 file:px-2 file:py-1 file:text-slate-200"
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="wl-name" className="text-slate-300 font-semibold">
              Name (optional — defaults to filename)
            </Label>
            <Input
              id="wl-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="prod-subdomains"
              className="bg-slate-950 border-slate-800 text-slate-200"
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="wl-kind" className="text-slate-300 font-semibold">
              Kind
            </Label>
            <Select value={kind} onValueChange={(v) => setKind(v as WordlistKind)}>
              <SelectTrigger id="wl-kind" className="bg-slate-950 border-slate-800 text-slate-200">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                <SelectItem value="subdomain">subdomain (DNS brute force)</SelectItem>
                <SelectItem value="bucket">bucket (cloud storage names)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="flex items-center justify-between pt-3 border-t border-slate-800">
          <p className="text-xs text-slate-400">
            Re-uploading under an existing name replaces it. Entries are lowercased, de-duplicated,
            and blank/comment lines are dropped.
          </p>
          <Button
            type="submit"
            disabled={!file || upload.isPending}
            className="gap-2 bg-sky-600 hover:bg-sky-500 text-white font-semibold"
          >
            <Upload className="h-3.5 w-3.5" />
            {upload.isPending ? "Uploading…" : "Upload Wordlist"}
          </Button>
        </div>
      </form>

      <div className="rounded-xl border border-slate-800/80 bg-slate-900/80 shadow-xl">
        {error ? (
          <p className="p-6 text-xs text-rose-400">{error.message}</p>
        ) : isLoading ? (
          <p className="p-6 text-xs text-slate-400">Loading wordlists…</p>
        ) : wordlists.length === 0 ? (
          <p className="p-6 text-xs text-slate-400">
            No wordlists uploaded yet. Upload one above to use it in a scan.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="border-slate-800 hover:bg-transparent">
                <TableHead className="text-slate-400">Name</TableHead>
                <TableHead className="text-slate-400">Kind</TableHead>
                <TableHead className="text-slate-400 text-right">Entries</TableHead>
                <TableHead className="text-slate-400">SHA-256</TableHead>
                <TableHead className="text-slate-400">Uploaded</TableHead>
                <TableHead className="text-slate-400" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {wordlists.map((wl) => (
                <TableRow key={wl.wordlist_id} className="border-slate-800">
                  <TableCell className="font-semibold text-slate-100">{wl.name}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className="border-slate-700 text-slate-300">
                      {wl.kind}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right font-mono text-slate-300">
                    {wl.line_count.toLocaleString()}
                  </TableCell>
                  <TableCell className="font-mono text-[11px] text-slate-500">
                    {wl.sha256.slice(0, 12)}…
                  </TableCell>
                  <TableCell className="text-xs text-slate-400">
                    {wl.created_at ? format(new Date(wl.created_at), "yyyy-MM-dd HH:mm") : "—"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setPendingDelete(wl)}
                      className="text-rose-400 hover:bg-rose-500/10 hover:text-rose-300"
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
        <AlertDialogContent className="bg-slate-900 border-slate-800 text-slate-100">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-slate-100">
              Delete wordlist “{pendingDelete?.name}”?
            </AlertDialogTitle>
            <AlertDialogDescription className="text-slate-400 text-xs">
              Scans already running are unaffected — they copied the list at start. New scans can no
              longer select it.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="border-slate-800 bg-slate-950 text-slate-300 hover:bg-slate-800">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (pendingDelete) remove.mutate(pendingDelete.wordlist_id);
                setPendingDelete(null);
              }}
              className="bg-rose-600 text-white hover:bg-rose-500"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
