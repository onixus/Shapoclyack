"use client";
import { useT } from "@/lib/i18n";
export function SystemTechnicalDetails({ data }: { data: unknown }) {
  const t = useT();
  return (
    <details className="mt-1 min-w-0 text-xs text-muted-foreground">
      <summary className="cursor-pointer">{t("scanCopy.technical")}</summary>
      <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words font-mono normal-case">
        {JSON.stringify(data, null, 2)}
      </pre>
    </details>
  );
}
