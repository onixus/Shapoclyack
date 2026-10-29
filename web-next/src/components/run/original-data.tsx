"use client";
import { useT } from "@/lib/i18n";
export function OriginalRunData({ data }: { data: unknown }) {
  const t = useT();
  return (
    <details className="mt-2 min-w-0 text-xs text-muted-foreground">
      <summary className="cursor-pointer">{t("scanCopy.technical")}</summary>
      <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-words font-mono">
        {typeof data === "string" ? data : JSON.stringify(data, null, 2)}
      </pre>
    </details>
  );
}
