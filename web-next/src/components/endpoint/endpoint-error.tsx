"use client";
import { useT } from "@/lib/i18n";
import { endpointText } from "@/lib/endpoint-presentation";
import { SystemTechnicalDetails } from "@/components/system-technical-details";
export function EndpointError({ error, message }: { error: unknown; message: string }) {
  const t = useT();
  if (!error) return null;
  const original = error instanceof Error ? error.message : String(error);
  return (
    <div role="alert" className="break-words text-xs text-destructive">
      {t.locale === "ru" ? endpointText(t.locale, message) : original}
      {t.locale === "ru" && <SystemTechnicalDetails data={{ error: original }} />}
    </div>
  );
}
