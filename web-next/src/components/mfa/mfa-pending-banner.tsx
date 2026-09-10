"use client";

import { usePathname, useRouter } from "next/navigation";
import { ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";

/** Where a confined session is allowed to go, and the only thing that clears it. */
const SETUP_PATH = "/security";

/**
 * "Set up MFA to carry on", for a session that owes the installation one (#315).
 *
 * The API answers such a session with 403 on every route but the enrolment
 * flow, so without this banner the console is a wall of failed panels and no
 * statement of why. It is deliberately not a modal: the user has to be able to
 * read the page underneath, and the one action it offers is the one route that
 * works.
 *
 * Hidden on the security page itself — standing over the form telling somebody
 * to open the form is noise.
 */
export function MfaPendingBanner() {
  const t = useT();
  const router = useRouter();
  const pathname = usePathname();
  const pending = useAuthStore((state) => state.user?.mfa_pending ?? false);

  if (!pending || pathname === SETUP_PATH) return null;

  return (
    <div
      role="alert"
      className="flex flex-wrap items-center justify-between gap-3 border-b border-amber-500/40 bg-amber-500/10 px-4 py-2 text-xs text-amber-900 dark:text-amber-200 md:px-6"
    >
      <span className="flex items-center gap-2">
        <ShieldAlert className="h-4 w-4 shrink-0" />
        <span>
          <strong className="font-semibold">{t("mfa.banner.title")}</strong> {t("mfa.banner.body")}
        </span>
      </span>
      <Button type="button" size="sm" variant="outline" onClick={() => router.push(SETUP_PATH)}>
        {t("mfa.banner.action")}
      </Button>
    </div>
  );
}
