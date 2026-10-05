"use client";

import { ShieldAlert } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { type AgentFleetSummary } from "@/lib/api";
import { useT } from "@/lib/i18n";

/** The fleet's client certificates that need an operator (#309): running out
 * soon or already, agents locked by a revocation, and agents refused while
 * another host holds their certificate.
 *
 * Rendered only when there is something to do: a fleet without certificates,
 * or one whose certificates are all comfortably valid, shows nothing. */
export function ClientCertExpiryAlert({ summary }: { summary?: AgentFleetSummary }) {
  const t = useT();
  const expiring = summary?.client_certs_expiring ?? 0;
  const expired = summary?.client_certs_expired ?? 0;
  const locked = summary?.client_cert_locked ?? 0;
  const conflicts = summary?.client_cert_conflicts ?? 0;
  if (expiring + expired + locked + conflicts === 0) return null;
  const counts = [
    conflicts > 0 ? t("agents.clientCerts.conflicts", { count: conflicts }) : null,
    locked > 0 ? t("agents.clientCerts.locked", { count: locked }) : null,
    expiring > 0 ? t("agents.clientCerts.expiring", { count: expiring }) : null,
    expired > 0 ? t("agents.clientCerts.expired", { count: expired }) : null,
  ].filter(Boolean);
  return (
    <Alert variant={expired + conflicts > 0 ? "destructive" : "warning"}>
      <ShieldAlert className="h-4 w-4" />
      <AlertTitle>{t("agents.clientCerts.title")}</AlertTitle>
      <AlertDescription>
        <p>{counts.join(" · ")}</p>
        <p className="text-xs opacity-80">
          {t("agents.clientCerts.hint", { mode: summary?.client_cert_mode ?? "off" })}
        </p>
      </AlertDescription>
    </Alert>
  );
}
