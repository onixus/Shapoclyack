"use client";

import { useState } from "react";
import { Download, UserX } from "lucide-react";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useEraseUser, useExportUserData } from "@/hooks/use-retention";
import { useT } from "@/lib/i18n";

/**
 * Data-subject requests for console accounts (#332): export and erasure.
 *
 * Platform admin only, like the account administration it belongs with. The
 * erasure keeps the username as a pseudonym — the append-only audit trail
 * names actors by it — and removes everything that ties it to a person; the
 * confirmation asks for the username typed out, because nothing about it can
 * be undone.
 */
export function DataSubjectPanel({ currentUsername }: { currentUsername: string }) {
  const t = useT();
  const exportData = useExportUserData();
  const erase = useEraseUser();
  const [username, setUsername] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [typed, setTyped] = useState("");
  const subject = username.trim();
  const isSelf = subject !== "" && subject === currentUsername;

  return (
    <section className="space-y-3">
      <div className="space-y-1">
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          {t("retention.dsar.title")}
        </p>
        <p className="text-[11px] text-muted-foreground">{t("retention.dsar.hint")}</p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Input
          aria-label={t("retention.dsar.username")}
          placeholder={t("retention.dsar.username")}
          className="h-9 w-64"
          value={username}
          onChange={(event) => setUsername(event.target.value)}
        />
        <Button
          type="button"
          variant="outline"
          className="gap-2 border-border"
          disabled={!subject || exportData.isPending}
          onClick={() => exportData.mutate(subject)}
        >
          <Download className="h-4 w-4" />
          {t("retention.dsar.export")}
        </Button>
        <Button
          type="button"
          className="gap-2 bg-rose-600 text-foreground hover:bg-rose-500"
          disabled={!subject || isSelf || erase.isPending}
          onClick={() => {
            setTyped("");
            setConfirming(true);
          }}
        >
          <UserX className="h-4 w-4" />
          {t("retention.dsar.erase")}
        </Button>
      </div>
      {isSelf ? (
        <p className="text-[11px] text-amber-500">{t("retention.dsar.notSelf")}</p>
      ) : null}
      {erase.data && !erase.isPending ? (
        <p className="text-xs text-muted-foreground" role="status">
          {erase.data.already_erased
            ? t("retention.dsar.alreadyErased", { username: erase.data.username })
            : t("retention.dsar.erased", { username: erase.data.username })}
        </p>
      ) : null}

      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent className="border-border bg-card text-foreground">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">
              {t("retention.dsar.eraseTitle", { username: subject })}
            </AlertDialogTitle>
            <AlertDialogDescription className="text-xs text-muted-foreground">
              {t("retention.dsar.eraseHint")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Input
            aria-label={t("retention.dsar.confirmLabel", { username: subject })}
            placeholder={subject}
            value={typed}
            onChange={(event) => setTyped(event.target.value)}
          />
          <AlertDialogFooter>
            <AlertDialogCancel className="border-border bg-muted text-foreground hover:bg-muted">
              {t("ui.cancel")}
            </AlertDialogCancel>
            <Button
              type="button"
              className="bg-rose-600 text-foreground hover:bg-rose-500"
              disabled={typed.trim() !== subject || erase.isPending}
              onClick={() => {
                erase.mutate(subject);
                setConfirming(false);
              }}
            >
              {t("retention.dsar.erase")}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}
