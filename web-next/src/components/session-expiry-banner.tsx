"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getAccessToken } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";
import { minutesLeft, sessionStatus } from "@/lib/session";
import { Button } from "@/components/ui/button";

/** How often the countdown is re-read. Fifteen seconds is fine for a banner
 * that only ever says whole minutes, and it costs nothing — the token is
 * already in memory and nothing is fetched. */
const TICK_MS = 15_000;

/** "Your session ends in N minutes", five minutes ahead of the fact (#314).
 *
 * Before this, an expired token surfaced as a 401 on whatever request happened
 * next and `api.ts` redirected to the login form with no warning and no way to
 * finish what was open. There is no silent renewal yet — refresh tokens are
 * still to come (#314) — so the honest thing is to say when it will happen and
 * offer the one action that resolves it. */
export function SessionExpiryBanner() {
  const t = useT();
  const router = useRouter();
  const user = useAuthStore((state) => state.user);
  const logout = useAuthStore((state) => state.logout);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), TICK_MS);
    return () => window.clearInterval(timer);
  }, []);

  if (!user) return null;
  const status = sessionStatus(getAccessToken(), now);
  if (status.state !== "expiring") return null;

  async function signInAgain() {
    await logout();
    router.replace("/login");
  }

  return (
    <div
      role="status"
      className="flex items-center justify-between gap-3 border-b border-amber-500/40 bg-amber-500/10 px-4 py-2 text-xs text-amber-900 dark:text-amber-200 md:px-6"
    >
      <span>{t("session.expiringSoon", { minutes: minutesLeft(status.msLeft) })}</span>
      <Button type="button" size="sm" variant="outline" onClick={() => void signInAgain()}>
        {t("session.signInAgain")}
      </Button>
    </div>
  );
}
