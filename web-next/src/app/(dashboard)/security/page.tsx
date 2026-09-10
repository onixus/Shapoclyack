"use client";

import { ShieldCheck } from "lucide-react";
import { MfaPanel } from "@/components/mfa/mfa-panel";
import { PageHeader } from "@/components/page-header";
import { useT } from "@/lib/i18n";

/**
 * The signed-in account's own security settings (#315).
 *
 * Its own route rather than a tab on `/users` because of the one session that
 * needs it most: an account this installation requires a second factor of,
 * which has not enrolled, is refused every other endpoint — including
 * `GET /api/users`, which the users page loads before it can render anything.
 * This page asks for `GET /api/auth/mfa` and nothing else, so it works from
 * exactly the state that has to reach it.
 */
export default function SecurityPage() {
  const t = useT();
  return (
    <div className="space-y-6">
      <PageHeader
        icon={ShieldCheck}
        title={t("header.security")}
        subtitle={t("mfa.description")}
        tone="emerald"
      />
      <MfaPanel />
    </div>
  );
}
