"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useT } from "@/lib/i18n";

/**
 * The signing secret, shown once (ROADMAP Phase 10.3).
 *
 * That is the truth of the API rather than a UI choice: the value is
 * write-only from the moment it is stored, so it is rendered here, never put
 * in a toast and never written to storage — both outlive the moment the admin
 * is looking at the screen.
 */
export function WebhookSecretDialog({
  secret,
  onClose,
}: {
  secret: string | null;
  onClose: () => void;
}) {
  const t = useT();
  const [copied, setCopied] = useState(false);

  return (
    <Dialog
      open={secret !== null}
      onOpenChange={(open) => {
        if (!open) {
          setCopied(false);
          onClose();
        }
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("integrations.secret.title")}</DialogTitle>
          <DialogDescription>{t("integrations.secret.body")}</DialogDescription>
        </DialogHeader>

        <div className="space-y-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-4">
          <code className="block break-all rounded bg-background/60 p-2 font-mono text-xs text-foreground">
            {secret}
          </code>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="gap-1.5"
            onClick={() => {
              // Clipboard access can be refused (insecure origin, denied
              // permission); the secret stays selectable on screen either way.
              navigator.clipboard?.writeText(secret ?? "").then(
                () => setCopied(true),
                () => setCopied(false),
              );
            }}
          >
            {copied ? (
              <Check className="h-3.5 w-3.5 text-emerald-500" />
            ) : (
              <Copy className="h-3.5 w-3.5" />
            )}
            {copied ? t("integrations.secret.copied") : t("integrations.secret.copy")}
          </Button>
        </div>

        <DialogFooter>
          <Button
            type="button"
            onClick={() => {
              setCopied(false);
              onClose();
            }}
          >
            {t("integrations.secret.done")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
