"use client";

import { useEffect, useState } from "react";
import { useT } from "@/lib/i18n";
import type { MsgKey } from "@/lib/i18n";
import { Camera, Download } from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useRunScreenshots } from "@/hooks/use-runs";
import {
  downloadArtifact,
  fetchScreenshotBlob,
  type ScreenshotItem,
  type ScreenshotManifest,
} from "@/lib/api";

const SKIP_KEYS: Record<string, MsgKey> = {
  "screenshots.disabled": "screenshots.skip.disabled",
  "worker.unavailable": "screenshots.skip.workerUnavailable",
  "playwright.unavailable": "screenshots.skip.playwrightUnavailable",
  no_web_ports: "screenshots.skip.noWebPorts",
};

export function skipReasonKey(reason: string | null | undefined): MsgKey | null {
  if (!reason) return null;
  return SKIP_KEYS[reason] ?? null;
}

export function ScreenshotsPanel({ runId, enabled }: { runId: string; enabled: boolean }) {
  const t = useT();
  const query = useRunScreenshots(runId, enabled);
  if (!enabled) return null;

  if (query.isLoading) {
    return (
      <div className="flex items-center justify-center py-10 text-muted-foreground gap-2">
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        <span className="text-xs">{t("screenshots.loading")}</span>
      </div>
    );
  }

  if (query.error) {
    return (
      <Alert
        variant="destructive"
        className="border-danger/40 bg-danger-subtle text-danger"
      >
        <AlertDescription>
          {query.error instanceof Error ? query.error.message : t("screenshots.loadFailed")}
        </AlertDescription>
      </Alert>
    );
  }

  return <ScreenshotsGallery runId={runId} manifest={query.data ?? emptyManifest()} />;
}

function emptyManifest(): ScreenshotManifest {
  return {
    skipped_reason: null,
    captured_count: 0,
    redacted_fields: 0,
    truncated: false,
    retention_days: 0,
    items: [],
  };
}

export function ScreenshotsGallery({
  runId,
  manifest,
}: {
  runId: string;
  manifest: ScreenshotManifest;
}) {
  const t = useT();
  const skipKey = skipReasonKey(manifest.skipped_reason);
  const skip = skipKey ? t(skipKey) : manifest.skipped_reason;
  const retention =
    manifest.retention_days > 0
      ? t("screenshots.retentionDays", { days: manifest.retention_days })
      : t("screenshots.retentionOff");

  return (
    <div className="space-y-4">
      <Alert className="border-warning/30 bg-warning-subtle text-warning">
        <AlertDescription className="text-xs leading-relaxed">
          {t("screenshots.redactionWarning")} {retention}
        </AlertDescription>
      </Alert>

      {manifest.truncated ? (
        <p className="text-xs text-warning">{t("screenshots.capped")}</p>
      ) : null}

      {skip ? <p className="text-xs text-muted-foreground">{skip}</p> : null}

      {manifest.items.length === 0 && !skip ? (
        <p className="rounded-xl border border-border bg-card px-4 py-8 text-center text-xs text-muted-foreground">
          {t("screenshots.empty")}
        </p>
      ) : null}

      {manifest.items.length > 0 ? (
        <div className="grid gap-4 sm:grid-cols-2">
          {manifest.items.map((item) => (
            <ScreenshotCard key={item.file} runId={runId} item={item} />
          ))}
        </div>
      ) : null}
    </div>
  );
}

function ScreenshotCard({ runId, item }: { runId: string; item: ScreenshotItem }) {
  const t = useT();
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const title = `${item.scheme || "http"}://${item.host || "?"}${
    item.port ? `:${item.port}` : ""
  }`;

  async function handleDownload() {
    setBusy(true);
    try {
      await downloadArtifact(runId, item.file);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t("screenshots.downloadFailed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="overflow-hidden rounded-xl border border-border bg-card shadow-lg">
      <ScreenshotThumb runId={runId} item={item} onOpen={item.available ? () => setOpen(true) : undefined} />
      <div className="flex items-start justify-between gap-3 p-3">
        <div className="min-w-0 space-y-1">
          <p className="truncate font-mono text-xs font-semibold text-foreground" title={item.url || title}>
            {title}
          </p>
          <div className="flex flex-wrap items-center gap-1.5">
            {item.redacted_fields > 0 ? (
              <Badge variant="secondary" className="bg-warning-subtle text-warning border-warning/30 text-[10px]">
                {t(
                  item.redacted_fields === 1
                    ? "screenshots.badge.redactedOne"
                    : "screenshots.badge.redactedMany",
                  { count: item.redacted_fields },
                )}
              </Badge>
            ) : (
              <Badge variant="secondary" className="bg-muted text-foreground border-border text-[10px]">
                {t("screenshots.badge.noneCovered")}
              </Badge>
            )}
            {!item.available ? (
              <Badge variant="secondary" className="bg-danger-subtle text-danger border-danger/30 text-[10px]">
                {t("screenshots.badge.deleted")}
              </Badge>
            ) : null}
          </div>
        </div>
        {item.available ? (
          <Button
            variant="outline"
            size="sm"
            onClick={handleDownload}
            disabled={busy}
            className="shrink-0 border-border bg-muted text-foreground hover:bg-muted text-xs gap-1.5"
          >
            <Download className="h-3.5 w-3.5" />
            {busy ? t("screenshots.saving") : t("screenshots.save")}
          </Button>
        ) : null}
      </div>
      <ScreenshotLightbox open={open} onOpenChange={setOpen} runId={runId} item={item} title={title} />
    </div>
  );
}

function ScreenshotLightbox({
  open,
  onOpenChange,
  runId,
  item,
  title,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  runId: string;
  item: ScreenshotItem;
  title: string;
}) {
  const t = useT();
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-5xl bg-card border-border text-foreground">
        <DialogHeader>
          <DialogTitle className="pr-8 font-mono text-sm">{item.url || title}</DialogTitle>
        </DialogHeader>
        <ScreenshotThumb runId={runId} item={item} frameClassName="h-[70vh]" />
        <div className="flex justify-end">
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5"
            onClick={() => {
              void downloadArtifact(runId, item.file).catch((error: unknown) => {
                toast.error(error instanceof Error ? error.message : t("screenshots.downloadFailed"));
              });
            }}
          >
            <Download className="h-3.5 w-3.5" />
            {t("screenshots.save")}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function ScreenshotThumb({
  runId,
  item,
  onOpen,
  frameClassName = "h-40",
}: {
  runId: string;
  item: ScreenshotItem;
  onOpen?: () => void;
  frameClassName?: string;
}) {
  const t = useT();
  const [src, setSrc] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!item.available) return;
    let revoked = false;
    let objectUrl: string | null = null;
    fetchScreenshotBlob(runId, item.file)
      .then((blob) => {
        objectUrl = URL.createObjectURL(blob);
        if (revoked) {
          URL.revokeObjectURL(objectUrl);
          objectUrl = null;
          return;
        }
        setSrc(objectUrl);
      })
      .catch(() => {
        if (!revoked) setFailed(true);
      });
    return () => {
      revoked = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [runId, item.file, item.available]);

  if (!item.available || failed) {
    return (
      <div className={`flex ${frameClassName} items-center justify-center gap-2 bg-muted text-muted-foreground text-xs`}>
        <Camera className="h-4 w-4" />
        {item.available ? t("screenshots.imageUnavailable") : t("screenshots.pixelsDeleted")}
      </div>
    );
  }

  if (!src) {
    return (
      <div className={`flex ${frameClassName} items-center justify-center bg-muted text-muted-foreground text-xs`}>
        {t("screenshots.imageLoading")}
      </div>
    );
  }

  const image = (
    // The PNG is already redacted on the worker. Remaining personal data is why
    // this panel is operator-only and why retention deletes the file.
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src={src}
      alt={item.url || item.file}
      className={`${frameClassName} w-full bg-muted ${onOpen ? "object-cover object-top" : "object-contain"}`}
    />
  );
  if (!onOpen) return image;
  return (
    <button
      type="button"
      onClick={onOpen}
      className="block w-full cursor-zoom-in text-left focus:outline-none focus:ring-2 focus:ring-ring"
      aria-label={t("screenshots.open")}
    >
      {image}
    </button>
  );
}
