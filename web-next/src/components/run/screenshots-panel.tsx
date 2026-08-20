"use client";

import { useEffect, useState } from "react";
import { Camera, Download } from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useRunScreenshots } from "@/hooks/use-runs";
import {
  downloadArtifact,
  fetchScreenshotBlob,
  type ScreenshotItem,
  type ScreenshotManifest,
} from "@/lib/api";

const SKIP_COPY: Record<string, string> = {
  "screenshots.disabled": "Screenshots were off for this run. The stage is opt-in.",
  "playwright.unavailable":
    "Playwright was not installed on the scanner. No pixels were taken.",
  no_web_ports: "No already-open web ports to capture. The stage does not scan new ports.",
};

export function skipReasonCopy(reason: string | null | undefined): string | null {
  if (!reason) return null;
  return SKIP_COPY[reason] ?? reason;
}

export function ScreenshotsPanel({ runId, enabled }: { runId: string; enabled: boolean }) {
  const query = useRunScreenshots(runId, enabled);
  if (!enabled) return null;

  if (query.isLoading) {
    return (
      <div className="flex items-center justify-center py-10 text-slate-400 gap-2">
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
        <span className="text-xs">Loading screenshots…</span>
      </div>
    );
  }

  if (query.error) {
    return (
      <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
        <AlertDescription>
          {query.error instanceof Error ? query.error.message : "Failed to load screenshots"}
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
  const skip = skipReasonCopy(manifest.skipped_reason);
  const retention =
    manifest.retention_days > 0
      ? `Pixels older than ${manifest.retention_days} days are deleted. The JSON manifest stays.`
      : "Pixel retention is off; files live with the run directory.";

  return (
    <div className="space-y-4">
      <Alert className="border-amber-500/30 bg-amber-950/30 text-amber-100">
        <AlertDescription className="text-xs leading-relaxed">
          Redaction paints a black overlay on obvious form fields (password, token, SSN,
          card, OTP) before capture. A name in a heading is not redacted. These images
          can still hold personal data — that is why they are operator-only. {retention}
        </AlertDescription>
      </Alert>

      {manifest.truncated ? (
        <p className="text-xs text-amber-300">
          Capture was capped at the configured maximum. Remaining web ports were not
          visited.
        </p>
      ) : null}

      {skip ? <p className="text-xs text-slate-400">{skip}</p> : null}

      {manifest.items.length === 0 && !skip ? (
        <p className="rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-8 text-center text-xs text-slate-400">
          No screenshots were kept for this run.
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
  const [busy, setBusy] = useState(false);
  const title = `${item.scheme || "http"}://${item.host || "?"}${
    item.port ? `:${item.port}` : ""
  }`;

  async function handleDownload() {
    setBusy(true);
    try {
      await downloadArtifact(runId, item.file);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Download failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/80 shadow-lg">
      <ScreenshotThumb runId={runId} item={item} />
      <div className="flex items-start justify-between gap-3 p-3">
        <div className="min-w-0 space-y-1">
          <p className="truncate font-mono text-xs font-semibold text-slate-100" title={item.url || title}>
            {title}
          </p>
          <div className="flex flex-wrap items-center gap-1.5">
            {item.redacted_fields > 0 ? (
              <Badge variant="secondary" className="bg-amber-500/15 text-amber-200 border-amber-500/30 text-[10px]">
                {item.redacted_fields} field{item.redacted_fields === 1 ? "" : "s"} redacted
              </Badge>
            ) : (
              <Badge variant="secondary" className="bg-slate-800 text-slate-300 border-slate-700 text-[10px]">
                no form fields covered
              </Badge>
            )}
            {!item.available ? (
              <Badge variant="secondary" className="bg-rose-500/15 text-rose-200 border-rose-500/30 text-[10px]">
                deleted by retention
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
            className="shrink-0 border-slate-800 bg-slate-950 text-slate-300 hover:bg-slate-800 text-xs gap-1.5"
          >
            <Download className="h-3.5 w-3.5" />
            {busy ? "Saving…" : "Save"}
          </Button>
        ) : null}
      </div>
    </div>
  );
}

function ScreenshotThumb({ runId, item }: { runId: string; item: ScreenshotItem }) {
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
      <div className="flex h-40 items-center justify-center gap-2 bg-slate-950 text-slate-500 text-xs">
        <Camera className="h-4 w-4" />
        {item.available ? "Image unavailable" : "Pixels deleted"}
      </div>
    );
  }

  if (!src) {
    return (
      <div className="flex h-40 items-center justify-center bg-slate-950 text-slate-500 text-xs">
        Loading image…
      </div>
    );
  }

  return (
    // The PNG is already redacted on the scanner. Remaining PII is why this
    // panel is operator-only and why the reaper deletes the file.
    // eslint-disable-next-line @next/next/no-img-element
    <img src={src} alt={item.url || item.file} className="h-40 w-full object-cover object-top bg-slate-950" />
  );
}
